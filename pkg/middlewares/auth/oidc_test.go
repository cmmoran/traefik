package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

func TestOIDCLoginFlow(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var nonce string

	jwksJSON := buildJWKS(t, &privateKey.PublicKey)
	baseURL := ""
	issuerServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(rw, map[string]any{
				"issuer":                 baseURL,
				"authorization_endpoint": baseURL + "/auth",
				"token_endpoint":         baseURL + "/token",
				"jwks_uri":               baseURL + "/keys",
			})
		case "/keys":
			rw.WriteHeader(http.StatusOK)
			rw.Write(jwksJSON)
		case "/token":
			require.NoError(t, req.ParseForm())
			token := buildIDToken(t, baseURL, "client", nonce, privateKey)
			accessToken := buildAccessToken(t, baseURL, privateKey)
			writeJSON(rw, map[string]any{
				"access_token":  accessToken,
				"id_token":      token,
				"refresh_token": "refresh",
				"expires_in":    3600,
				"token_type":    "Bearer",
			})
		default:
			rw.WriteHeader(http.StatusOK)
		}
	}))
	baseURL = issuerServer.URL
	defer issuerServer.Close()

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := NewOIDC(context.Background(), nextHandler, dynamic.OIDC{
		Issuer:       issuerServer.URL,
		RedirectURL:  "/callback",
		ClientID:     "client",
		ClientSecret: "secret",
	}, "oidc")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	require.NotEmpty(t, location)

	authURL, err := url.Parse(location)
	require.NoError(t, err)
	nonce = authURL.Query().Get("nonce")
	state := authURL.Query().Get("state")
	require.NotEmpty(t, state)
	require.NotEmpty(t, nonce)

	stateCookie := extractCookie(rr, "oidc-state")
	require.NotNil(t, stateCookie)

	callbackReq := httptest.NewRequest(http.MethodGet, "http://example.com/callback?code=abc&state="+state, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	handler.ServeHTTP(callbackRR, callbackReq)
	require.Equal(t, http.StatusFound, callbackRR.Code)

	sessionCookie := extractCookie(callbackRR, "oidc-session")
	require.NotNil(t, sessionCookie)

	authReq := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	authReq.AddCookie(sessionCookie)
	authRR := httptest.NewRecorder()
	handler.ServeHTTP(authRR, authReq)
	require.Equal(t, http.StatusOK, authRR.Code)
}

func TestOIDCClientSecretFile(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "oidc-secret")
	require.NoError(t, err)
	_, err = tmp.WriteString("supersecret\n")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	value, err := resolveOIDCClientSecret(tmp.Name())
	require.NoError(t, err)
	require.Equal(t, "supersecret", value)
}

func buildJWKS(t *testing.T, publicKey *rsa.PublicKey) []byte {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigEndian(publicKey.E))
	jwk := map[string]any{
		"kty": "RSA",
		"kid": "test-key",
		"alg": "RS256",
		"use": "sig",
		"n":   n,
		"e":   e,
	}
	data, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	require.NoError(t, err)
	return data
}

func buildIDToken(t *testing.T, issuer, clientID, nonce string, key *rsa.PrivateKey) string {
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   "user",
		"aud":   clientID,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func buildAccessToken(t *testing.T, issuer string, key *rsa.PrivateKey) string {
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "user",
		"aud": "api",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func writeJSON(rw http.ResponseWriter, payload any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(payload)
}

func extractCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, header := range rr.Header().Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(header)
		if err != nil {
			continue
		}
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func bigEndian(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var buf []byte
	for value > 0 {
		buf = append([]byte{byte(value & 0xff)}, buf...)
		value >>= 8
	}
	return buf
}
