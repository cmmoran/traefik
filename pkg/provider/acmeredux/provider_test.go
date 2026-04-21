package acmeredux

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/safe"
	"github.com/traefik/traefik/v3/pkg/types"
)

type testStore struct {
	getResolverStateFn        func(resolverName string, force ...bool) (*StoredData, error)
	withResolverLeaseFn       func(ctx context.Context, resolverName string, f func(context.Context, *StoredData) error) error
	upsertCertificateLockedFn func(ctx context.Context, resolverName string, cert Certificate, tlsStore string) ([]*CertAndStore, error)
	saveAccountLockedFn       func(ctx context.Context, resolverName string, account *Account) error
}

func (t *testStore) GetResolverState(resolverName string, force ...bool) (*StoredData, error) {
	if t.getResolverStateFn != nil {
		return t.getResolverStateFn(resolverName, force...)
	}
	return &StoredData{}, nil
}
func (t *testStore) SaveAccountLocked(ctx context.Context, resolverName string, account *Account) error {
	if t.saveAccountLockedFn != nil {
		return t.saveAccountLockedFn(ctx, resolverName, account)
	}
	return nil
}
func (t *testStore) UpsertCertificateLocked(ctx context.Context, resolverName string, cert Certificate, tlsStore string) ([]*CertAndStore, error) {
	if t.upsertCertificateLockedFn != nil {
		return t.upsertCertificateLockedFn(ctx, resolverName, cert, tlsStore)
	}
	return nil, nil
}
func (t *testStore) WithResolverLease(ctx context.Context, resolverName string, f func(context.Context, *StoredData) error) error {
	if t.withResolverLeaseFn != nil {
		return t.withResolverLeaseFn(ctx, resolverName, f)
	}

	state, err := t.GetResolverState(resolverName, true)
	if err != nil {
		return err
	}
	return f(ctx, state)
}
func (t *testStore) IsLocked(context.Context) (bool, error) { return false, nil }

func TestGetUncheckedCertificates(t *testing.T) {
	t.Skip("Needs TLS Manager")
	wildcardMap := make(map[string]*tls.Certificate)
	wildcardMap["*.traefik.wtf"] = &tls.Certificate{}

	wildcardSafe := &safe.Safe{}
	wildcardSafe.Set(wildcardMap)

	domainMap := make(map[string]*tls.Certificate)
	domainMap["traefik.wtf"] = &tls.Certificate{}

	domainSafe := &safe.Safe{}
	domainSafe.Set(domainMap)

	// TODO Add a test for DefaultCertificate
	testCases := []struct {
		desc             string
		dynamicCerts     *safe.Safe
		resolvingDomains map[string]struct{}
		acmeCertificates []*CertAndStore
		domains          []string
		expectedDomains  []string
	}{
		{
			desc:            "wildcard to generate",
			domains:         []string{"*.traefik.wtf"},
			expectedDomains: []string{"*.traefik.wtf"},
		},
		{
			desc:            "wildcard already exists in dynamic certificates",
			domains:         []string{"*.traefik.wtf"},
			dynamicCerts:    wildcardSafe,
			expectedDomains: nil,
		},
		{
			desc:    "wildcard already exists in ACME certificates",
			domains: []string{"*.traefik.wtf"},
			acmeCertificates: []*CertAndStore{
				{
					Certificate: Certificate{
						Domain: types.Domain{Main: "*.traefik.wtf"},
					},
				},
			},
			expectedDomains: nil,
		},
		{
			desc:            "domain CN and SANs to generate",
			domains:         []string{"traefik.wtf", "foo.traefik.wtf"},
			expectedDomains: []string{"traefik.wtf", "foo.traefik.wtf"},
		},
		{
			desc:            "domain CN already exists in dynamic certificates and SANs to generate",
			domains:         []string{"traefik.wtf", "foo.traefik.wtf"},
			dynamicCerts:    domainSafe,
			expectedDomains: []string{"foo.traefik.wtf"},
		},
		{
			desc:    "domain CN already exists in ACME certificates and SANs to generate",
			domains: []string{"traefik.wtf", "foo.traefik.wtf"},
			acmeCertificates: []*CertAndStore{
				{
					Certificate: Certificate{
						Domain: types.Domain{Main: "traefik.wtf"},
					},
				},
			},
			expectedDomains: []string{"foo.traefik.wtf"},
		},
		{
			desc:            "domain already exists in dynamic certificates",
			domains:         []string{"traefik.wtf"},
			dynamicCerts:    domainSafe,
			expectedDomains: nil,
		},
		{
			desc:    "domain already exists in ACME certificates",
			domains: []string{"traefik.wtf"},
			acmeCertificates: []*CertAndStore{
				{
					Certificate: Certificate{
						Domain: types.Domain{Main: "traefik.wtf"},
					},
				},
			},
			expectedDomains: nil,
		},
		{
			desc:            "domain matched by wildcard in dynamic certificates",
			domains:         []string{"who.traefik.wtf", "foo.traefik.wtf"},
			dynamicCerts:    wildcardSafe,
			expectedDomains: nil,
		},
		{
			desc:    "domain matched by wildcard in ACME certificates",
			domains: []string{"who.traefik.wtf", "foo.traefik.wtf"},
			acmeCertificates: []*CertAndStore{
				{
					Certificate: Certificate{
						Domain: types.Domain{Main: "*.traefik.wtf"},
					},
				},
			},
			expectedDomains: nil,
		},
		{
			desc:    "root domain with wildcard in ACME certificates",
			domains: []string{"traefik.wtf", "foo.traefik.wtf"},
			acmeCertificates: []*CertAndStore{
				{
					Certificate: Certificate{
						Domain: types.Domain{Main: "*.traefik.wtf"},
					},
				},
			},
			expectedDomains: []string{"traefik.wtf"},
		},
		{
			desc:    "all domains already managed by ACME",
			domains: []string{"traefik.wtf", "foo.traefik.wtf"},
			resolvingDomains: map[string]struct{}{
				"traefik.wtf":     {},
				"foo.traefik.wtf": {},
			},
			expectedDomains: []string{},
		},
		{
			desc:    "one domain already managed by ACME",
			domains: []string{"traefik.wtf", "foo.traefik.wtf"},
			resolvingDomains: map[string]struct{}{
				"traefik.wtf": {},
			},
			expectedDomains: []string{"foo.traefik.wtf"},
		},
		{
			desc:    "wildcard domain already managed by ACME checks the domains",
			domains: []string{"bar.traefik.wtf", "foo.traefik.wtf"},
			resolvingDomains: map[string]struct{}{
				"*.traefik.wtf": {},
			},
			expectedDomains: []string{},
		},
		{
			desc:    "wildcard domain already managed by ACME checks domains and another domain checks one other domain, one domain still unchecked",
			domains: []string{"traefik.wtf", "bar.traefik.wtf", "foo.traefik.wtf", "acme.wtf"},
			resolvingDomains: map[string]struct{}{
				"*.traefik.wtf": {},
				"traefik.wtf":   {},
			},
			expectedDomains: []string{"acme.wtf"},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			if test.resolvingDomains == nil {
				test.resolvingDomains = make(map[string]struct{})
			}

			acmeProvider := Provider{
				// certificateStore: &traefiktls.CertificateStore{
				// 	DynamicCerts: test.dynamicCerts,
				// },
				certificates:     test.acmeCertificates,
				resolvingDomains: test.resolvingDomains,
			}

			domains := acmeProvider.getUncheckedDomains(t.Context(), test.domains, "default")
			assert.Len(t, domains, len(test.expectedDomains), "Unexpected domains.")
		})
	}
}

func TestProviderUpdateCertificatesFromStorePublishes(t *testing.T) {
	configurationChan := make(chan dynamic.Message, 1)
	initial := []*CertAndStore{{
		Certificate: Certificate{
			Domain:      types.Domain{Main: "old.example.com"},
			Certificate: []byte("old-cert"),
			Key:         []byte("old-key"),
		},
		Store: "default",
	}}
	updated := []*CertAndStore{{
		Certificate: Certificate{
			Domain:      types.Domain{Main: "new.example.com"},
			Certificate: []byte("new-cert"),
			Key:         []byte("new-key"),
		},
		Store: "default",
	}}

	provider := &Provider{
		certificates:      cloneCertAndStores(initial),
		configurationChan: configurationChan,
	}

	changed := provider.updateCertificatesFromStore(updated)
	require.True(t, changed)

	select {
	case msg := <-configurationChan:
		require.Len(t, msg.Configuration.TLS.Certificates, 1)
		assert.Equal(t, types.FileOrContent([]byte("new-cert")), msg.Configuration.TLS.Certificates[0].Certificate.CertFile)
	default:
		t.Fatal("expected refreshed TLS configuration to be published")
	}

	require.Len(t, provider.certificates, 1)
	assert.Equal(t, "new.example.com", provider.certificates[0].Domain.Main)
}

func TestProviderAddCertificateForDomainLockedPublishesOnlyAfterSuccessfulSave(t *testing.T) {
	configurationChan := make(chan dynamic.Message, 1)
	initial := []*CertAndStore{{
		Certificate: Certificate{
			Domain:      types.Domain{Main: "example.com"},
			Certificate: []byte("old-cert"),
			Key:         []byte("old-key"),
		},
		Store: "default",
	}}

	saveErr := errors.New("save failed")
	provider := &Provider{
		ResolverName:      "test",
		Store:             &testStore{upsertCertificateLockedFn: func(context.Context, string, Certificate, string) ([]*CertAndStore, error) { return nil, saveErr }},
		certificates:      cloneCertAndStores(initial),
		configurationChan: configurationChan,
	}

	err := provider.addCertificateForDomainLocked(context.Background(), types.Domain{Main: "example.com"}, &certificate.Resource{
		Certificate: []byte("new-cert"),
		PrivateKey:  []byte("new-key"),
	}, "default")
	require.ErrorIs(t, err, saveErr)

	select {
	case <-configurationChan:
		t.Fatal("did not expect TLS configuration publish when certificate save fails")
	default:
	}

	require.Len(t, provider.certificates, 1)
	assert.Equal(t, []byte("old-cert"), provider.certificates[0].Certificate.Certificate)
}

func TestProviderAddCertificateForDomainLockedUsesCommittedStoreState(t *testing.T) {
	configurationChan := make(chan dynamic.Message, 1)
	initial := []*CertAndStore{{
		Certificate: Certificate{
			Domain:      types.Domain{Main: "stale.example.com"},
			Certificate: []byte("stale-cert"),
			Key:         []byte("stale-key"),
		},
		Store: "default",
	}}
	committed := []*CertAndStore{
		{
			Certificate: Certificate{
				Domain:      types.Domain{Main: "fresh.example.com"},
				Certificate: []byte("fresh-cert"),
				Key:         []byte("fresh-key"),
			},
			Store: "default",
		},
		{
			Certificate: Certificate{
				Domain:      types.Domain{Main: "example.com"},
				Certificate: []byte("new-cert"),
				Key:         []byte("new-key"),
			},
			Store: "default",
		},
	}

	provider := &Provider{
		ResolverName: "test",
		Store: &testStore{upsertCertificateLockedFn: func(_ context.Context, resolverName string, cert Certificate, tlsStore string) ([]*CertAndStore, error) {
			require.Equal(t, "test", resolverName)
			require.Equal(t, types.Domain{Main: "example.com"}, cert.Domain)
			require.Equal(t, "default", tlsStore)
			return cloneCertAndStores(committed), nil
		}},
		certificates:      cloneCertAndStores(initial),
		configurationChan: configurationChan,
	}

	err := provider.addCertificateForDomainLocked(context.Background(), types.Domain{Main: "example.com"}, &certificate.Resource{
		Certificate: []byte("new-cert"),
		PrivateKey:  []byte("new-key"),
	}, "default")
	require.NoError(t, err)

	select {
	case msg := <-configurationChan:
		require.Len(t, msg.Configuration.TLS.Certificates, 2)
		assert.Equal(t, types.FileOrContent([]byte("fresh-cert")), msg.Configuration.TLS.Certificates[0].Certificate.CertFile)
		assert.Equal(t, types.FileOrContent([]byte("new-cert")), msg.Configuration.TLS.Certificates[1].Certificate.CertFile)
	default:
		t.Fatal("expected TLS configuration publish")
	}

	require.Equal(t, committed, provider.certificates)
}

func TestProviderWithResolverLeaseUsesFreshStoreStateAndPublishes(t *testing.T) {
	stale := []*CertAndStore{{
		Certificate: Certificate{
			Domain:      types.Domain{Main: "stale.example.com"},
			Certificate: []byte("stale-cert"),
			Key:         []byte("stale-key"),
		},
		Store: "default",
	}}
	fresh := []*CertAndStore{{
		Certificate: Certificate{
			Domain:      types.Domain{Main: "fresh.example.com"},
			Certificate: []byte("fresh-cert"),
			Key:         []byte("fresh-key"),
		},
		Store: "default",
	}}
	configurationChan := make(chan dynamic.Message, 1)

	provider := &Provider{
		ResolverName: "test",
		Store: &testStore{getResolverStateFn: func(resolverName string, force ...bool) (*StoredData, error) {
			require.Equal(t, "test", resolverName)
			require.Len(t, force, 1)
			require.True(t, force[0])
			return &StoredData{Certificates: cloneCertAndStores(fresh)}, nil
		}},
		certificates:      cloneCertAndStores(stale),
		configurationChan: configurationChan,
	}

	require.NoError(t, provider.withResolverLease(context.Background(), func(context.Context, *StoredData) error { return nil }))
	require.Equal(t, fresh, provider.certificates)

	select {
	case msg := <-configurationChan:
		require.Len(t, msg.Configuration.TLS.Certificates, 1)
		assert.Equal(t, types.FileOrContent([]byte("fresh-cert")), msg.Configuration.TLS.Certificates[0].Certificate.CertFile)
	default:
		t.Fatal("expected TLS configuration publish")
	}
}

func TestProviderApplyResolverStateClearsCachedClient(t *testing.T) {
	provider := &Provider{
		account: &Account{Email: "stale@example.com"},
		client:  &lego.Client{},
	}

	changed := provider.applyResolverState(&StoredData{
		Account: &Account{Email: "fresh@example.com"},
	})

	require.False(t, changed)
	require.NotNil(t, provider.account)
	assert.Equal(t, "fresh@example.com", provider.account.Email)
	assert.Nil(t, provider.client)
}

func TestLeaseBoundRoundTripperUsesLeaseContext(t *testing.T) {
	leaseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		require.Same(t, leaseCtx, req.Context())
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})

	rt := &leaseBoundRoundTripper{leaseCtx: leaseCtx, next: transport}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestLeaseBoundRoundTripperRejectsCanceledLease(t *testing.T) {
	leaseCtx, cancel := context.WithCancel(context.Background())
	cancel()

	called := false
	rt := &leaseBoundRoundTripper{
		leaseCtx: leaseCtx,
		next: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		}),
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAcmeReduxConfigurationSetDefaultsIncludesCertificateTimeout(t *testing.T) {
	cfg := &Configuration{}
	cfg.SetDefaults()

	assert.Equal(t, 30*time.Second, time.Duration(cfg.CertificateTimeout))
}

func TestProvider_sanitizeDomains(t *testing.T) {
	testCases := []struct {
		desc            string
		domains         types.Domain
		dnsChallenge    *DNSChallenge
		expectedErr     string
		expectedDomains []string
	}{
		{
			desc:            "valid wildcard",
			domains:         types.Domain{Main: "*.traefik.wtf"},
			dnsChallenge:    &DNSChallenge{},
			expectedErr:     "",
			expectedDomains: []string{"*.traefik.wtf"},
		},
		{
			desc:            "no wildcard",
			domains:         types.Domain{Main: "traefik.wtf", SANs: []string{"foo.traefik.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			expectedErr:     "",
			expectedDomains: []string{"traefik.wtf", "foo.traefik.wtf"},
		},
		{
			desc:            "no domain",
			domains:         types.Domain{},
			dnsChallenge:    nil,
			expectedErr:     "no domain was given",
			expectedDomains: nil,
		},
		{
			desc:            "unauthorized wildcard with SAN",
			domains:         types.Domain{Main: "*.*.traefik.wtf", SANs: []string{"foo.traefik.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			expectedErr:     "unable to generate a wildcard certificate in ACME provider for domain \"*.*.traefik.wtf,foo.traefik.wtf\" : ACME does not allow '*.*' wildcard domain",
			expectedDomains: nil,
		},
		{
			desc:            "wildcard and SANs",
			domains:         types.Domain{Main: "*.traefik.wtf", SANs: []string{"traefik.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			expectedErr:     "",
			expectedDomains: []string{"*.traefik.wtf", "traefik.wtf"},
		},
		{
			desc:            "wildcard SANs",
			domains:         types.Domain{Main: "*.traefik.wtf", SANs: []string{"*.acme.wtf"}},
			dnsChallenge:    &DNSChallenge{},
			expectedErr:     "",
			expectedDomains: []string{"*.traefik.wtf", "*.acme.wtf"},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			acmeProvider := Provider{Configuration: &Configuration{DNSChallenge: test.dnsChallenge}}

			domains, err := acmeProvider.sanitizeDomains(t.Context(), test.domains)

			if len(test.expectedErr) > 0 {
				assert.EqualError(t, err, test.expectedErr, "Unexpected error.")
			} else {
				assert.Len(t, domains, len(test.expectedDomains), "Unexpected domains.")
			}
		})
	}
}

func TestDeleteUnnecessaryDomains(t *testing.T) {
	testCases := []struct {
		desc            string
		domains         []types.Domain
		expectedDomains []types.Domain
	}{
		{
			desc: "no domain to delete",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
				{
					Main: "*.foo.acme.wtf",
				},
				{
					Main: "acme02.wtf",
					SANs: []string{"traefik.acme02.wtf", "bar.foo"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
				{
					Main: "*.foo.acme.wtf",
					SANs: []string{},
				},
				{
					Main: "acme02.wtf",
					SANs: []string{"traefik.acme02.wtf", "bar.foo"},
				},
			},
		},
		{
			desc: "wildcard and root domain",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
				},
				{
					Main: "*.acme.wtf",
					SANs: []string{"acme.wtf"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{},
				},
				{
					Main: "*.acme.wtf",
					SANs: []string{},
				},
			},
		},
		{
			desc: "2 equals domains",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
			},
		},
		{
			desc: "2 domains with same values",
			domains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf"},
				},
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf", "foo.bar"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"traefik.acme.wtf"},
				},
				{
					Main: "foo.bar",
					SANs: []string{},
				},
			},
		},
		{
			desc: "domain totally checked by wildcard",
			domains: []types.Domain{
				{
					Main: "who.acme.wtf",
					SANs: []string{"traefik.acme.wtf", "bar.acme.wtf"},
				},
				{
					Main: "*.acme.wtf",
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "*.acme.wtf",
					SANs: []string{},
				},
			},
		},
		{
			desc: "duplicated wildcard",
			domains: []types.Domain{
				{
					Main: "*.acme.wtf",
					SANs: []string{"acme.wtf"},
				},
				{
					Main: "*.acme.wtf",
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "*.acme.wtf",
					SANs: []string{"acme.wtf"},
				},
			},
		},
		{
			desc: "domain partially checked by wildcard",
			domains: []types.Domain{
				{
					Main: "traefik.acme.wtf",
					SANs: []string{"acme.wtf", "foo.bar"},
				},
				{
					Main: "*.acme.wtf",
				},
				{
					Main: "who.acme.wtf",
					SANs: []string{"traefik.acme.wtf", "bar.acme.wtf"},
				},
			},
			expectedDomains: []types.Domain{
				{
					Main: "acme.wtf",
					SANs: []string{"foo.bar"},
				},
				{
					Main: "*.acme.wtf",
					SANs: []string{},
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			domains := deleteUnnecessaryDomains(t.Context(), test.domains)
			assert.Equal(t, test.expectedDomains, domains, "unexpected domain")
		})
	}
}

func TestIsAccountMatchingCaServer(t *testing.T) {
	testCases := []struct {
		desc       string
		accountURI string
		serverURI  string
		expected   bool
	}{
		{
			desc:       "acme staging with matching account",
			accountURI: "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234567",
			serverURI:  "https://acme-staging-v02.api.letsencrypt.org/acme/directory",
			expected:   true,
		},
		{
			desc:       "acme production with matching account",
			accountURI: "https://acme-v02.api.letsencrypt.org/acme/acct/1234567",
			serverURI:  "https://acme-v02.api.letsencrypt.org/acme/directory",
			expected:   true,
		},
		{
			desc:       "http only acme with matching account",
			accountURI: "http://acme.api.letsencrypt.org/acme/acct/1234567",
			serverURI:  "http://acme.api.letsencrypt.org/acme/directory",
			expected:   true,
		},
		{
			desc:       "different subdomains for account and server",
			accountURI: "https://test1.example.org/acme/acct/1234567",
			serverURI:  "https://test2.example.org/acme/directory",
			expected:   false,
		},
		{
			desc:       "different domains for account and server",
			accountURI: "https://test.example1.org/acme/acct/1234567",
			serverURI:  "https://test.example2.org/acme/directory",
			expected:   false,
		},
		{
			desc:       "different tld for account and server",
			accountURI: "https://test.example.com/acme/acct/1234567",
			serverURI:  "https://test.example.org/acme/directory",
			expected:   false,
		},
		{
			desc:       "malformed account url",
			accountURI: "//|\\/test.example.com/acme/acct/1234567",
			serverURI:  "https://test.example.com/acme/directory",
			expected:   false,
		},
		{
			desc:       "malformed server url",
			accountURI: "https://test.example.com/acme/acct/1234567",
			serverURI:  "//|\\/test.example.com/acme/directory",
			expected:   false,
		},
		{
			desc:       "malformed server and account url",
			accountURI: "//|\\/test.example.com/acme/acct/1234567",
			serverURI:  "//|\\/test.example.com/acme/directory",
			expected:   false,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			result := isAccountMatchingCaServer(t.Context(), test.accountURI, test.serverURI)

			assert.Equal(t, test.expected, result)
		})
	}
}

func TestInitAccount(t *testing.T) {
	testCases := []struct {
		desc            string
		account         *Account
		email           string
		keyType         string
		expectedAccount *Account
	}{
		{
			desc: "Existing account with all information",
			account: &Account{
				Email:   "foo@foo.net",
				KeyType: certcrypto.EC256,
			},
			expectedAccount: &Account{
				Email:   "foo@foo.net",
				KeyType: certcrypto.EC256,
			},
		},
		{
			desc:    "Account nil",
			email:   "foo@foo.net",
			keyType: "EC256",
			expectedAccount: &Account{
				Email:   "foo@foo.net",
				KeyType: certcrypto.EC256,
			},
		},
		{
			desc: "Existing account with no email",
			account: &Account{
				KeyType: certcrypto.RSA4096,
			},
			email:   "foo@foo.net",
			keyType: "EC256",
			expectedAccount: &Account{
				Email:   "foo@foo.net",
				KeyType: certcrypto.EC256,
			},
		},
		{
			desc: "Existing account with no key type",
			account: &Account{
				Email: "foo@foo.net",
			},
			email:   "bar@foo.net",
			keyType: "EC256",
			expectedAccount: &Account{
				Email:   "foo@foo.net",
				KeyType: certcrypto.EC256,
			},
		},
		{
			desc: "Existing account and provider with no key type",
			account: &Account{
				Email: "foo@foo.net",
			},
			email: "bar@foo.net",
			expectedAccount: &Account{
				Email:   "foo@foo.net",
				KeyType: certcrypto.RSA4096,
			},
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			acmeProvider := Provider{account: test.account, Configuration: &Configuration{Email: test.email, KeyType: test.keyType}}

			actualAccount, err := acmeProvider.initAccount(t.Context())
			assert.NoError(t, err, "Init account in error")
			assert.Equal(t, test.expectedAccount.Email, actualAccount.Email, "unexpected email account")
			assert.Equal(t, test.expectedAccount.KeyType, actualAccount.KeyType, "unexpected keyType account")
		})
	}
}

func Test_getCertificateRenewDurations(t *testing.T) {
	testCases := []struct {
		desc                  string
		certificatesDurations int
		expectRenewPeriod     time.Duration
		expectRenewInterval   time.Duration
	}{
		{
			desc:                  "Less than 24 Hours certificates: 20 minutes renew period, 1 minutes renew interval",
			certificatesDurations: 1,
			expectRenewPeriod:     time.Minute * 20,
			expectRenewInterval:   time.Minute,
		},
		{
			desc:                  "1 Year certificates: 4 months renew period, 1 week renew interval",
			certificatesDurations: 24 * 365,
			expectRenewPeriod:     time.Hour * 24 * 30 * 4,
			expectRenewInterval:   time.Hour * 24 * 7,
		},
		{
			desc:                  "265 Days certificates: 30 days renew period, 1 day renew interval",
			certificatesDurations: 24 * 265,
			expectRenewPeriod:     time.Hour * 24 * 30,
			expectRenewInterval:   time.Hour * 24,
		},
		{
			desc:                  "90 Days certificates: 30 days renew period, 1 day renew interval",
			certificatesDurations: 24 * 90,
			expectRenewPeriod:     time.Hour * 24 * 30,
			expectRenewInterval:   time.Hour * 24,
		},
		{
			desc:                  "30 Days certificates: 10 days renew period, 12 hour renew interval",
			certificatesDurations: 24 * 30,
			expectRenewPeriod:     time.Hour * 24 * 10,
			expectRenewInterval:   time.Hour * 12,
		},
		{
			desc:                  "7 Days certificates: 1 days renew period, 1 hour renew interval",
			certificatesDurations: 24 * 7,
			expectRenewPeriod:     time.Hour * 24,
			expectRenewInterval:   time.Hour,
		},
		{
			desc:                  "24 Hours certificates: 6 hours renew period, 10 minutes renew interval",
			certificatesDurations: 24,
			expectRenewPeriod:     time.Hour * 6,
			expectRenewInterval:   time.Minute * 10,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			renewPeriod, renewInterval := getCertificateRenewDurations(test.certificatesDurations)
			assert.Equal(t, test.expectRenewPeriod, renewPeriod)
			assert.Equal(t, test.expectRenewInterval, renewInterval)
		})
	}
}
