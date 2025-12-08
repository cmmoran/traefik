package vaultpki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

var (
	ErrAuthRequired = errors.New("vault auth required")
)

type Client struct {
	config *Configuration
	client *http.Client

	mu    sync.Mutex
	token string
}

func NewClient(config *Configuration) (*Client, error) {
	if config == nil {
		return nil, errors.New("vaultpki config required")
	}
	if config.URL == "" {
		return nil, errors.New("vaultpki url required")
	}
	cfg := *config
	cfg.SetDefaults()
	config = &cfg

	tlsConfig := &tls.Config{}
	if config.TLS != nil {
		if config.TLS.SkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}
		if config.TLS.ServerName != "" {
			tlsConfig.ServerName = config.TLS.ServerName
		}
		if config.TLS.CABundle != "" {
			pool := x509.NewCertPool()
			pemData, err := os.ReadFile(config.TLS.CABundle)
			if err != nil {
				return nil, fmt.Errorf("read ca bundle: %w", err)
			}
			if !pool.AppendCertsFromPEM(pemData) {
				return nil, errors.New("invalid ca bundle")
			}
			tlsConfig.RootCAs = pool
		}
		if config.TLS.Cert != "" && config.TLS.Key != "" {
			cert, err := tls.LoadX509KeyPair(config.TLS.Cert, config.TLS.Key)
			if err != nil {
				return nil, fmt.Errorf("load vault client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport}

	return &Client{config: config, client: client}, nil
}

func (c *Client) Issue(ctx context.Context, req IssueConfig) (string, string, time.Time, error) {
	if c.config.Role == "" {
		return "", "", time.Time{}, errors.New("vaultpki role required")
	}
	if c.config.PKIPath == "" {
		return "", "", time.Time{}, errors.New("vaultpki pkiPath required")
	}
	if err := c.ensureToken(ctx); err != nil {
		return "", "", time.Time{}, err
	}

	endpoint := c.endpoint(path.Join("v1", c.config.PKIPath, "issue", c.config.Role))
	payload := map[string]any{}
	if req.CommonName != "" {
		payload["common_name"] = req.CommonName
	}
	if len(req.AltNames) > 0 {
		payload["alt_names"] = strings.Join(req.AltNames, ",")
	}
	if len(req.URISans) > 0 {
		payload["uri_sans"] = strings.Join(req.URISans, ",")
	}
	if req.TTL > 0 {
		payload["ttl"] = req.TTL.String()
	}

	resp, err := c.doJSON(ctx, http.MethodPost, endpoint, payload, true)
	if err == nil {
		return decodeIssue(resp)
	}

	if isAuthError(err) {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		if err := c.ensureToken(ctx); err != nil {
			return "", "", time.Time{}, err
		}
		resp, err = c.doJSON(ctx, http.MethodPost, endpoint, payload, true)
		if err != nil {
			return "", "", time.Time{}, err
		}
		return decodeIssue(resp)
	}

	return "", "", time.Time{}, err
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return nil
	}

	if c.config.Auth == nil {
		return ErrAuthRequired
	}

	if c.config.Auth.Token != "" {
		c.token = c.config.Auth.Token
		return nil
	}

	if c.config.Auth.CertAuth != nil {
		endpoint := c.endpoint(path.Join("v1", "auth", c.certAuthPath(), "login"))
		payload := map[string]string{}
		if c.config.Auth.CertAuth.Name != "" {
			payload["name"] = c.config.Auth.CertAuth.Name
		}
		resp, err := c.doJSON(ctx, http.MethodPost, endpoint, payload, false)
		if err != nil {
			return err
		}
		return c.setTokenFromResponse(resp)
	}

	if c.config.Auth.AppRole != nil {
		endpoint := c.endpoint(path.Join("v1", "auth", c.appRolePath(), "login"))
		payload := map[string]string{
			"role_id":   c.config.Auth.AppRole.RoleID,
			"secret_id": c.config.Auth.AppRole.SecretID,
		}
		resp, err := c.doJSON(ctx, http.MethodPost, endpoint, payload, false)
		if err != nil {
			// Try unwrap if secret_id is a wrapping token.
			if unwrapErr := c.tryUnwrapSecretID(ctx); unwrapErr != nil {
				return err
			}
			resp, err = c.doJSON(ctx, http.MethodPost, endpoint, payload, false)
			if err != nil {
				return err
			}
		}
		return c.setTokenFromResponse(resp)
	}

	return ErrAuthRequired
}

func (c *Client) setTokenFromResponse(resp *http.Response) error {
	defer resp.Body.Close()
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Auth.ClientToken == "" {
		return errors.New("vault auth returned empty token")
	}
	c.token = out.Auth.ClientToken
	return nil
}

func (c *Client) tryUnwrapSecretID(ctx context.Context) error {
	if c.config.Auth == nil || c.config.Auth.AppRole == nil {
		return ErrAuthRequired
	}
	if c.config.Auth.AppRole.SecretID == "" {
		return ErrAuthRequired
	}
	endpoint := c.endpoint(path.Join("v1", "sys", "wrapping", "unwrap"))

	resp, err := c.doJSONWithToken(ctx, http.MethodPost, endpoint, map[string]any{}, c.config.Auth.AppRole.SecretID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	val, ok := out.Data["secret_id"].(string)
	if !ok || val == "" {
		return errors.New("vault unwrap did not return secret_id")
	}
	c.config.Auth.AppRole.SecretID = val
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, body any, requireAuth bool) (*http.Response, error) {
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()

	return c.doJSONWithToken(ctx, method, endpoint, body, token, requireAuth)
}

func (c *Client) doJSONWithToken(ctx context.Context, method, endpoint string, body any, token string, requireAuth ...bool) (*http.Response, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewBuffer(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.config.Namespace)
	}
	if len(requireAuth) == 0 || requireAuth[0] {
		if token == "" {
			return nil, ErrAuthRequired
		}
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("vault http %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

func (c *Client) endpoint(p string) string {
	base := strings.TrimRight(c.config.URL, "/")
	p = strings.TrimLeft(p, "/")
	u, _ := url.Parse(base + "/" + p)
	return u.String()
}

func (c *Client) appRolePath() string {
	if c.config.Auth != nil && c.config.Auth.AppRole != nil && c.config.Auth.AppRole.EnginePath != "" {
		return strings.Trim(c.config.Auth.AppRole.EnginePath, "/")
	}
	return "approle"
}

func (c *Client) certAuthPath() string {
	if c.config.Auth != nil && c.config.Auth.CertAuth != nil && c.config.Auth.CertAuth.EnginePath != "" {
		return strings.Trim(c.config.Auth.CertAuth.EnginePath, "/")
	}
	return "cert"
}

func isAuthError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "http 401") || strings.Contains(s, "http 403") || strings.Contains(s, "permission denied")
}

func decodeIssue(resp *http.Response) (string, string, time.Time, error) {
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Certificate string   `json:"certificate"`
			PrivateKey  string   `json:"private_key"`
			CAChain     []string `json:"ca_chain"`
			IssuingCA   string   `json:"issuing_ca"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", time.Time{}, err
	}
	if out.Data.Certificate == "" || out.Data.PrivateKey == "" {
		return "", "", time.Time{}, errors.New("vault issue response missing certificate/private_key")
	}
	notAfter, err := parseNotAfter(out.Data.Certificate)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return out.Data.Certificate, out.Data.PrivateKey, notAfter, nil
}

func parseNotAfter(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, errors.New("invalid cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
