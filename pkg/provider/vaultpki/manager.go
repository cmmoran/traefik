package vaultpki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

type Manager struct {
	mu        sync.Mutex
	resolvers map[string]*Configuration
	clients   map[string]*Client
	entries   map[string]*certEntry
	files     map[string]string
}

type certEntry struct {
	key      string
	resolver string
	issue    IssueConfig
	filePath string
	client   *Client
	config   *Configuration

	cert atomic.Value // *tls.Certificate
	exp  atomic.Value // time.Time
}

func NewManager(resolvers map[string]*Configuration) *Manager {
	cfgs := map[string]*Configuration{}
	for name, cfg := range resolvers {
		if cfg == nil {
			continue
		}
		copyCfg := *cfg
		copyCfg.SetDefaults()
		cfgs[name] = &copyCfg
	}
	return &Manager{
		resolvers: cfgs,
		clients:   make(map[string]*Client),
		entries:   make(map[string]*certEntry),
		files:     make(map[string]string),
	}
}

func (m *Manager) ClientCertSource(resolver string, override *IssueConfig) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	entry, err := m.ensureEntry(resolver, override)
	if err != nil {
		return nil, err
	}
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if v := entry.cert.Load(); v != nil {
			return v.(*tls.Certificate), nil
		}
		return nil, errors.New("vaultpki client cert not ready")
	}, nil
}

func (m *Manager) ensureEntry(resolver string, override *IssueConfig) (*certEntry, error) {
	m.mu.Lock()
	cfg, ok := m.resolvers[resolver]
	if !ok || cfg == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("vaultpki resolver %q not found", resolver)
	}
	issue := mergeIssue(cfg.Issue, override)
	key := entryKey(resolver, issue)
	if entry, ok := m.entries[key]; ok {
		m.mu.Unlock()
		return entry, nil
	}

	client, err := m.clientFor(resolver, cfg)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}

	fileName := cfg.CacheFileBase(resolver, issue)
	filePath := filepath.Join(cfg.CacheDir, fileName)
	if existingKey, ok := m.files[filePath]; ok && existingKey != key {
		fileName = strings.TrimSuffix(fileName, ".pem") + "-" + strings.TrimPrefix(key, resolver+"-") + ".pem"
		filePath = filepath.Join(cfg.CacheDir, fileName)
	}
	m.files[filePath] = key

	entry := &certEntry{
		key:      key,
		resolver: resolver,
		issue:    issue,
		filePath: filePath,
		client:   client,
		config:   cfg,
	}
	m.entries[key] = entry
	m.mu.Unlock()

	if err := entry.loadOrIssue(); err != nil {
		return nil, err
	}
	go entry.renewLoop()
	return entry, nil
}

func (m *Manager) clientFor(resolver string, cfg *Configuration) (*Client, error) {
	if client, ok := m.clients[resolver]; ok {
		return client, nil
	}
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	m.clients[resolver] = client
	return client, nil
}

func mergeIssue(base *IssueConfig, override *IssueConfig) IssueConfig {
	var out IssueConfig
	if base != nil {
		out = *base
	}
	if override == nil {
		return out
	}
	if override.CommonName != "" {
		out.CommonName = override.CommonName
	}
	if len(override.AltNames) > 0 {
		out.AltNames = override.AltNames
	}
	if len(override.URISans) > 0 {
		out.URISans = override.URISans
	}
	if override.TTL > 0 {
		out.TTL = override.TTL
	}
	return out
}

func entryKey(resolver string, issue IssueConfig) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(resolver))
	_, _ = h.Write([]byte("|" + issue.CommonName))
	_, _ = h.Write([]byte("|" + strings.Join(issue.AltNames, ",")))
	_, _ = h.Write([]byte("|" + strings.Join(issue.URISans, ",")))
	_, _ = h.Write([]byte(fmt.Sprintf("|%s", issue.TTL.String())))
	return fmt.Sprintf("%s-%x", resolver, h.Sum64())
}

func (e *certEntry) loadOrIssue() error {
	if err := os.MkdirAll(filepath.Dir(e.filePath), 0o700); err != nil {
		return err
	}
	if certPEM, keyPEM, notAfter, err := loadPEMFile(e.filePath); err == nil {
		if time.Now().Before(notAfter) {
			cert, err := parseKeyPair(certPEM, keyPEM)
			if err != nil {
				return err
			}
			e.cert.Store(cert)
			e.exp.Store(notAfter)
			return nil
		}
	}
	return e.issueAndStore()
}

func (e *certEntry) issueAndStore() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	certPEM, keyPEM, notAfter, err := e.client.Issue(ctx, e.issue)
	if err != nil {
		return err
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return err
	}
	if err := writePEMFile(e.filePath, certPEM, keyPEM); err != nil {
		return err
	}
	e.cert.Store(&cert)
	e.exp.Store(notAfter)
	return nil
}

func (e *certEntry) renewLoop() {
	for {
		next, err := e.nextRenew()
		if err != nil {
			log.Error().Err(err).Msg("vaultpki: could not determine renew time")
			next = time.Now().Add(30 * time.Second)
		}
		wait := time.Until(next)
		if wait < 5*time.Second {
			wait = 5 * time.Second
		}
		time.Sleep(wait)
		if err := e.issueAndStore(); err != nil {
			log.Error().Err(err).Msg("vaultpki: failed to renew client certificate")
			time.Sleep(30 * time.Second)
		}
	}
}

func (e *certEntry) nextRenew() (time.Time, error) {
	v := e.exp.Load()
	if v == nil {
		return time.Time{}, errors.New("no certificate loaded")
	}
	notAfter := v.(time.Time)
	if e.config.RenewBefore > 0 {
		return notAfter.Add(-time.Duration(e.config.RenewBefore)), nil
	}

	cert := e.cert.Load().(*tls.Certificate)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Add(-lifetime / 3), nil
}
