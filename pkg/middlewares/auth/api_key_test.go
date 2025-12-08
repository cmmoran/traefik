package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"golang.org/x/crypto/bcrypt"
)

func TestAPIKeyHeaderScheme(t *testing.T) {
	t.Parallel()

	secret := hashSecret(t, "mykey")
	config := dynamic.APIKey{
		KeySource: &dynamic.APIKeySource{
			Header:           "Authorization",
			HeaderAuthScheme: "Bearer",
		},
		SecretNonBase64Encoded: true,
		SecretValues:           []string{secret},
	}

	handler, err := NewAPIKey(context.Background(), http.HandlerFunc(okHandler), config, "apikey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer mykey")
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestAPIKeyHeaderSchemeMismatch(t *testing.T) {
	t.Parallel()

	secret := hashSecret(t, "mykey")
	config := dynamic.APIKey{
		KeySource: &dynamic.APIKeySource{
			Header:           "Authorization",
			HeaderAuthScheme: "Bearer",
		},
		SecretNonBase64Encoded: true,
		SecretValues:           []string{secret},
	}

	handler, err := NewAPIKey(context.Background(), http.HandlerFunc(okHandler), config, "apikey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Basic mykey")
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}
}

func TestAPIKeyBase64Header(t *testing.T) {
	t.Parallel()

	secret := hashSecret(t, "mykey")
	config := dynamic.APIKey{
		KeySource: &dynamic.APIKeySource{
			Header: "X-API-Key",
		},
		SecretNonBase64Encoded: false,
		SecretValues:           []string{secret},
	}

	handler, err := NewAPIKey(context.Background(), http.HandlerFunc(okHandler), config, "apikey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-API-Key", base64.StdEncoding.EncodeToString([]byte("mykey")))
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestAPIKeyQuery(t *testing.T) {
	t.Parallel()

	secret := hashSecret(t, "mykey")
	config := dynamic.APIKey{
		KeySource: &dynamic.APIKeySource{
			Query: "api_key",
		},
		SecretNonBase64Encoded: true,
		SecretValues:           []string{secret},
	}

	handler, err := NewAPIKey(context.Background(), http.HandlerFunc(okHandler), config, "apikey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/?api_key=mykey", nil)
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestAPIKeyCookie(t *testing.T) {
	t.Parallel()

	secret := hashSecret(t, "mykey")
	config := dynamic.APIKey{
		KeySource: &dynamic.APIKeySource{
			Cookie: "api_key",
		},
		SecretNonBase64Encoded: true,
		SecretValues:           []string{secret},
	}

	handler, err := NewAPIKey(context.Background(), http.HandlerFunc(okHandler), config, "apikey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "api_key", Value: "mykey"})
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestAPIKeyInvalidConfig(t *testing.T) {
	t.Parallel()

	config := dynamic.APIKey{
		KeySource:              &dynamic.APIKeySource{},
		SecretNonBase64Encoded: true,
		SecretValues:           []string{"unused"},
	}

	_, err := NewAPIKey(context.Background(), http.HandlerFunc(okHandler), config, "apikey")
	if err == nil {
		t.Fatal("expected error for empty keySource")
	}
}

func hashSecret(t *testing.T, raw string) string {
	t.Helper()

	secret, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("failed to hash secret: %v", err)
	}
	return string(secret)
}

func okHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
}
