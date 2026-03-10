package vaultpki

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	httpmuxer "github.com/traefik/traefik/v3/pkg/muxer/http"
	tcpmuxer "github.com/traefik/traefik/v3/pkg/muxer/tcp"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/traefik/v3/pkg/safe"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/types"
)

type ServerProvider struct {
	ResolverName string
	Config       *Configuration

	dynConfigs  chan dynamic.Configuration
	dynMessages chan<- dynamic.Message

	mu        sync.RWMutex
	certs     map[string]serverCert
	client    *Client
	cachePath map[string]string
}

type serverCert struct {
	issue    IssueConfig
	certPEM  string
	keyPEM   string
	notAfter time.Time
}

// Init implements provider.Provider.
func (p *ServerProvider) Init() error {
	p.dynConfigs = make(chan dynamic.Configuration)
	p.certs = make(map[string]serverCert)
	p.cachePath = make(map[string]string)
	cfg := *p.Config
	cfg.SetDefaults()
	p.Config = &cfg

	client, err := NewClient(p.Config)
	if err != nil {
		return err
	}
	p.client = client
	return nil
}

// HandleConfigUpdate implements provider.ConfigWatcher.
func (p *ServerProvider) HandleConfigUpdate(cfg dynamic.Configuration) {
	p.dynConfigs <- cfg
}

// Provide implements provider.Provider.
func (p *ServerProvider) Provide(dynMessages chan<- dynamic.Message, pool *safe.Pool) error {
	p.dynMessages = dynMessages
	logger := log.With().Str(logs.ProviderName, p.ResolverName+".vaultpki").Logger()

	pool.GoCtx(func(ctx context.Context) {
		p.watchDomains(logger.WithContext(ctx))
	})
	pool.GoCtx(func(ctx context.Context) {
		p.renewCertificates(logger.WithContext(ctx))
	})
	return nil
}

func (p *ServerProvider) watchDomains(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cfg := <-p.dynConfigs:
			requests := p.findRequests(ctx, cfg)
			updated := p.syncRequests(ctx, requests)
			if updated {
				p.sendDynamicConfig()
			}
		}
	}
}

func (p *ServerProvider) renewCertificates(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if p.renewIfNeeded(ctx) {
				p.sendDynamicConfig()
			}
		}
	}
}

type certRequest struct {
	key   string
	issue IssueConfig
}

func (p *ServerProvider) findRequests(ctx context.Context, cfg dynamic.Configuration) []certRequest {
	var requests []certRequest
	if cfg.HTTP != nil {
		for _, router := range cfg.HTTP.Routers {
			if router.TLS == nil || router.TLS.CertResolver != p.ResolverName {
				continue
			}
			reqs := p.requestsForRouterTLS(ctx, router.TLS.Domains, router.Rule, router.TLS.CertResolverOptions)
			requests = append(requests, reqs...)
		}
	}
	if cfg.TCP != nil {
		for _, router := range cfg.TCP.Routers {
			if router.TLS == nil || router.TLS.CertResolver != p.ResolverName {
				continue
			}
			reqs := p.requestsForRouterTLS(ctx, router.TLS.Domains, router.Rule, router.TLS.CertResolverOptions)
			requests = append(requests, reqs...)
		}
	}
	return requests
}

func (p *ServerProvider) requestsForRouterTLS(ctx context.Context, domains []types.Domain, rule string, options *dynamic.CertResolverOptions) []certRequest {
	var requests []certRequest
	resolvedDomains := domains
	if len(resolvedDomains) == 0 {
		parsed, err := httpmuxer.ParseDomains(rule)
		if err != nil {
			parsed, err = tcpmuxer.ParseHostSNI(rule)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("Unable to parse router domains")
				return nil
			}
		}
		parsed = sanitizeDomains(parsed)
		if len(parsed) == 0 {
			return nil
		}
		resolvedDomains = []types.Domain{{Main: parsed[0], SANs: parsed[1:]}}
	}

	for _, domain := range resolvedDomains {
		if domain.Main == "" {
			continue
		}
		issue := IssueConfig{CommonName: domain.Main, AltNames: domain.SANs}
		if options != nil && options.VaultPKI != nil {
			override := options.VaultPKI
			if override.CommonName != "" {
				issue.CommonName = override.CommonName
			}
			if len(override.AltNames) > 0 {
				issue.AltNames = override.AltNames
			}
			if len(override.URISans) > 0 {
				issue.URISans = override.URISans
			}
			if override.TTL > 0 {
				issue.TTL = override.TTL
			}
		}
		key := entryKey(p.ResolverName, issue)
		requests = append(requests, certRequest{key: key, issue: issue})
	}
	return requests
}

func (p *ServerProvider) syncRequests(ctx context.Context, requests []certRequest) bool {
	desired := map[string]certRequest{}
	for _, req := range requests {
		desired[req.key] = req
	}

	updated := false

	p.mu.Lock()
	for key := range p.certs {
		if _, ok := desired[key]; !ok {
			delete(p.certs, key)
			updated = true
		}
	}
	p.mu.Unlock()

	for _, req := range desired {
		if p.ensureCert(ctx, req) {
			updated = true
		}
	}

	return updated
}

func (p *ServerProvider) ensureCert(ctx context.Context, req certRequest) bool {
	p.mu.RLock()
	_, ok := p.certs[req.key]
	p.mu.RUnlock()
	if ok {
		return false
	}

	certPEM, keyPEM, notAfter, err := p.loadOrIssue(ctx, req.issue)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("vaultpki: failed to issue server certificate")
		return false
	}

	p.mu.Lock()
	p.certs[req.key] = serverCert{issue: req.issue, certPEM: certPEM, keyPEM: keyPEM, notAfter: notAfter}
	p.mu.Unlock()
	return true
}

func (p *ServerProvider) loadOrIssue(ctx context.Context, issue IssueConfig) (string, string, time.Time, error) {
	filePath := p.cacheFile(issue)
	if certPEM, keyPEM, notAfter, err := loadPEMFile(filePath); err == nil {
		if time.Now().Before(notAfter) {
			return certPEM, keyPEM, notAfter, nil
		}
	}
	certPEM, keyPEM, notAfter, err := p.client.Issue(ctx, issue)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if err := writePEMFile(filePath, certPEM, keyPEM); err != nil {
		return "", "", time.Time{}, err
	}
	return certPEM, keyPEM, notAfter, nil
}

func (p *ServerProvider) cacheFile(issue IssueConfig) string {
	base := p.Config.CacheFileBase(p.ResolverName, issue)
	path := p.Config.CacheDir + "/" + base
	p.mu.Lock()
	defer p.mu.Unlock()
	key := entryKey(p.ResolverName, issue)
	if existing, ok := p.cachePath[path]; ok && existing != key {
		path = strings.TrimSuffix(path, ".pem") + "-" + strings.TrimPrefix(entryKey(p.ResolverName, issue), p.ResolverName+"-") + ".pem"
	}
	p.cachePath[path] = key
	return path
}

func (p *ServerProvider) renewIfNeeded(ctx context.Context) bool {
	p.mu.RLock()
	keys := make([]string, 0, len(p.certs))
	for key := range p.certs {
		keys = append(keys, key)
	}
	p.mu.RUnlock()

	updated := false
	for _, key := range keys {
		p.mu.RLock()
		cert := p.certs[key]
		p.mu.RUnlock()

		if !p.needsRenew(cert) {
			continue
		}
		certPEM, keyPEM, notAfter, err := p.client.Issue(ctx, cert.issue)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("vaultpki: failed to renew server certificate")
			continue
		}
		if err := writePEMFile(p.cacheFile(cert.issue), certPEM, keyPEM); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("vaultpki: failed to write renewed server certificate")
			continue
		}
		p.mu.Lock()
		p.certs[key] = serverCert{issue: cert.issue, certPEM: certPEM, keyPEM: keyPEM, notAfter: notAfter}
		p.mu.Unlock()
		updated = true
	}
	return updated
}

func (p *ServerProvider) needsRenew(cert serverCert) bool {
	if p.Config.RenewBefore > 0 {
		return time.Now().After(cert.notAfter.Add(-time.Duration(p.Config.RenewBefore)))
	}
	notBefore, notAfter, err := certValidity(cert.certPEM)
	if err != nil {
		return true
	}
	lifetime := notAfter.Sub(notBefore)
	return time.Now().After(notAfter.Add(-lifetime / 3))
}

func (p *ServerProvider) sendDynamicConfig() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var certs []*traefiktls.CertAndStores
	for _, cert := range p.certs {
		certs = append(certs, &traefiktls.CertAndStores{
			Stores: []string{traefiktls.DefaultTLSStoreName},
			Certificate: traefiktls.Certificate{
				CertFile: types.FileOrContent(cert.certPEM),
				KeyFile:  types.FileOrContent(cert.keyPEM),
			},
		})
	}

	p.dynMessages <- dynamic.Message{
		ProviderName: p.ResolverName + ".vaultpki",
		Configuration: &dynamic.Configuration{
			TLS: &dynamic.TLSConfiguration{Certificates: certs},
		},
	}
}

func sanitizeDomains(domains []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, domain := range domains {
		d := strings.TrimSpace(domain)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}
