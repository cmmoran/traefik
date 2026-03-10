package vaultpki

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/types"
)

func TestServerProviderRequestsForRouterTLS_UsesRouterDomains(t *testing.T) {
	p := &ServerProvider{}
	ctx := context.Background()

	domains := []types.Domain{{
		Main: "example.com",
		SANs: []string{"www.example.com"},
	}}

	reqs := p.requestsForRouterTLS(ctx, domains, "", nil)

	require.Len(t, reqs, 1)
	assert.Equal(t, "example.com", reqs[0].issue.CommonName)
	assert.Equal(t, []string{"www.example.com"}, reqs[0].issue.AltNames)
	assert.Empty(t, reqs[0].issue.URISans)
}

func TestServerProviderRequestsForRouterTLS_UsesRuleDomains(t *testing.T) {
	p := &ServerProvider{}
	ctx := context.Background()

	reqs := p.requestsForRouterTLS(ctx, nil, "Host(`example.com`)", nil)

	require.Len(t, reqs, 1)
	assert.Equal(t, "example.com", reqs[0].issue.CommonName)
	assert.Empty(t, reqs[0].issue.AltNames)
}

func TestServerProviderRequestsForRouterTLS_UsesHostSNI(t *testing.T) {
	p := &ServerProvider{}
	ctx := context.Background()

	reqs := p.requestsForRouterTLS(ctx, nil, "HostSNI(`db.example.com`)", nil)

	require.Len(t, reqs, 1)
	assert.Equal(t, "db.example.com", reqs[0].issue.CommonName)
}

func TestServerProviderRequestsForRouterTLS_AppliesVaultPKIOverrides(t *testing.T) {
	p := &ServerProvider{}
	ctx := context.Background()

	domains := []types.Domain{{
		Main: "example.com",
		SANs: []string{"www.example.com"},
	}}

	options := &dynamic.CertResolverOptions{
		VaultPKI: &dynamic.VaultPKIOverrides{
			CommonName: "override.example",
			AltNames:   []string{"alt.example"},
			URISans:    []string{"spiffe://prod/stack-a/api"},
			TTL:        ptypes.Duration(2 * time.Hour),
		},
	}

	reqs := p.requestsForRouterTLS(ctx, domains, "", options)

	require.Len(t, reqs, 1)
	assert.Equal(t, "override.example", reqs[0].issue.CommonName)
	assert.Equal(t, []string{"alt.example"}, reqs[0].issue.AltNames)
	assert.Equal(t, []string{"spiffe://prod/stack-a/api"}, reqs[0].issue.URISans)
	assert.Equal(t, ptypes.Duration(2*time.Hour), reqs[0].issue.TTL)
}
