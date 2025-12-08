//go:build integration
// +build integration

package vaultpki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/require"
	ptypes "github.com/traefik/paerser/types"
)

func TestVaultPKIClientIntegration(t *testing.T) {
	cfg := integrationConfig(t)
	cacheDir := t.TempDir()
	cfg.CacheDir = cacheDir

	manager := NewManager(map[string]*Configuration{"vaultpki": cfg})
	source, err := manager.ClientCertSource("vaultpki", &IssueConfig{
		CommonName: "traefik-client",
		URISans:    []string{"spiffe://integration/client"},
		TTL:        ptypes.Duration(2 * time.Hour),
	})
	require.NoError(t, err)

	cert, err := source(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)

	leaf := parseLeaf(t, cert.Certificate[0])
	require.Equal(t, "traefik-client", leaf.Subject.CommonName)
	require.NotEmpty(t, leaf.URIs)
	require.Equal(t, "spiffe", leaf.URIs[0].Scheme)
	require.Contains(t, leaf.URIs[0].String(), "/client")

	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
}

func TestVaultPKIServerIntegration(t *testing.T) {
	cfg := integrationConfig(t)
	cacheDir := t.TempDir()
	cfg.CacheDir = cacheDir

	provider := &ServerProvider{
		ResolverName: "vaultpki",
		Config:       cfg,
	}
	require.NoError(t, provider.Init())

	certPEM, keyPEM, notAfter, err := provider.loadOrIssue(context.Background(), IssueConfig{
		CommonName: "traefik-server",
		URISans:    []string{"spiffe://integration/server"},
		TTL:        ptypes.Duration(2 * time.Hour),
	})
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)
	require.True(t, notAfter.After(time.Now()))

	leaf := parseLeafPEM(t, certPEM)
	require.Equal(t, "traefik-server", leaf.Subject.CommonName)
	require.NotEmpty(t, leaf.URIs)
	require.Equal(t, "spiffe", leaf.URIs[0].Scheme)
	require.Contains(t, leaf.URIs[0].String(), "/server")

	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
}

func integrationConfig(t *testing.T) *Configuration {
	addr := firstEnv("VAULT_ADDR", "BAO_ADDR")
	token := firstEnv("VAULT_TOKEN", "BAO_TOKEN")
	if addr == "" || token == "" {
		t.Skip("requires VAULT_ADDR/BAO_ADDR and VAULT_TOKEN/BAO_TOKEN")
	}

	pkiPath := os.Getenv("VAULT_PKI_PATH")
	if pkiPath == "" {
		pkiPath = os.Getenv("BAO_PKI_PATH")
	}
	role := os.Getenv("VAULT_PKI_ROLE")
	if role == "" {
		role = os.Getenv("BAO_PKI_ROLE")
	}

	cfg := &Configuration{
		URL: addr,
		Auth: &AuthConfig{
			Token: token,
		},
	}

	if ns := firstEnv("VAULT_NAMESPACE", "BAO_NAMESPACE"); ns != "" {
		cfg.Namespace = ns
	}

	if tlsCfg := vaultTLSFromEnv(); tlsCfg != nil {
		cfg.TLS = tlsCfg
	}

	if pkiPath == "" || role == "" {
		autoPath, autoRole, err := bootstrapTestPKI(t, addr, token, cfg.Namespace, cfg.TLS)
		if err != nil {
			t.Skipf("unable to bootstrap test PKI: %v", err)
		}
		pkiPath = autoPath
		role = autoRole
	}

	cfg.PKIPath = strings.Trim(pkiPath, "/")
	cfg.Role = role
	cfg.SetDefaults()
	return cfg
}

func vaultTLSFromEnv() *TLSConfig {
	ca := os.Getenv("VAULT_CACERT")
	cert := os.Getenv("VAULT_CLIENT_CERT")
	key := os.Getenv("VAULT_CLIENT_KEY")
	serverName := os.Getenv("VAULT_TLS_SERVER_NAME")
	skipVerify := envBool("VAULT_SKIP_VERIFY")

	if ca == "" && cert == "" && key == "" && serverName == "" && !skipVerify {
		return nil
	}

	return &TLSConfig{
		CABundle:   ca,
		Cert:       cert,
		Key:        key,
		SkipVerify: skipVerify,
		ServerName: serverName,
	}
}

func envBool(key string) bool {
	val := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return val == "1" || val == "true" || val == "yes"
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if val := os.Getenv(key); val != "" {
			return val
		}
	}
	return ""
}

func bootstrapTestPKI(t *testing.T, addr, token, namespace string, tlsCfg *TLSConfig) (string, string, error) {
	clientOpts := []vault.ClientOption{vault.WithAddress(addr)}
	if tlsCfg != nil {
		clientOpts = append(clientOpts, vault.WithTLS(vault.TLSConfiguration{
			ServerCertificate: vault.ServerCertificateEntry{
				FromFile: tlsCfg.CABundle,
			},
			ClientCertificate: vault.ClientCertificateEntry{
				FromFile: tlsCfg.Cert,
			},
			ClientCertificateKey: vault.ClientCertificateKeyEntry{
				FromFile: tlsCfg.Key,
			},
			InsecureSkipVerify: tlsCfg.SkipVerify,
			ServerName:         tlsCfg.ServerName,
		}))
	}
	client, err := vault.New(clientOpts...)
	if err != nil {
		return "", "", err
	}
	if namespace != "" {
		if err := client.SetNamespace(namespace); err != nil {
			return "", "", err
		}
	}
	if err := client.SetToken(token); err != nil {
		return "", "", err
	}

	mountPath := fmt.Sprintf("traefik-test-pki-%d", time.Now().UnixNano())
	roleName := fmt.Sprintf("traefik-test-role-%d", time.Now().UnixNano())

	if _, err := client.System.MountsEnableSecretsEngine(context.Background(), mountPath, schema.MountsEnableSecretsEngineRequest{
		Type:        "pki",
		Description: "Traefik integration test PKI",
	}); err != nil {
		return "", "", err
	}
	t.Cleanup(func() {
		_, _ = client.System.MountsDisableSecretsEngine(context.Background(), mountPath)
	})

	_, err = client.Secrets.PkiGenerateRoot(context.Background(), "internal", schema.PkiGenerateRootRequest{
		CommonName: "traefik-test-root",
		Ttl:        "24h",
	}, vault.WithMountPath(mountPath))
	if err != nil {
		return "", "", err
	}

	_, err = client.Secrets.PkiWriteRole(context.Background(), roleName, schema.PkiWriteRoleRequest{
		AllowAnyName:              true,
		AllowBareDomains:          true,
		AllowSubdomains:           true,
		AllowWildcardCertificates: true,
		AllowedDomains:            []string{"test.local"},
		AllowedUriSans:            []string{"spiffe://integration/*"},
		EnforceHostnames:          false,
		ClientFlag:                true,
		ServerFlag:                true,
		Ttl:                       "2h",
		MaxTtl:                    "4h",
	}, vault.WithMountPath(mountPath))
	if err != nil {
		return "", "", err
	}

	return mountPath, roleName, nil
}

func parseLeaf(t *testing.T, der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func parseLeafPEM(t *testing.T, certPEM string) *x509.Certificate {
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}
