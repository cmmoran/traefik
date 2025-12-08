package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"

	goauth "github.com/abbot/go-http-auth"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"github.com/traefik/traefik/v3/pkg/middlewares/observability"
)

const (
	typeNameAPIKey = "APIKey"
)

type apiKey struct {
	next                   http.Handler
	name                   string
	keySource              dynamic.APIKeySource
	secretNonBase64Encoded bool
	secretValues           []string
}

// NewAPIKey creates an API key authentication middleware.
func NewAPIKey(ctx context.Context, next http.Handler, config dynamic.APIKey, name string) (http.Handler, error) {
	middlewares.GetLogger(ctx, name, typeNameAPIKey).Debug().Msg("Creating middleware")

	if config.KeySource == nil {
		return nil, errors.New("apiKey.keySource must be set")
	}

	sourceCount := 0
	if config.KeySource.Header != "" {
		sourceCount++
	}
	if config.KeySource.Query != "" {
		sourceCount++
	}
	if config.KeySource.Cookie != "" {
		sourceCount++
	}
	if sourceCount == 0 {
		return nil, errors.New("apiKey.keySource must define header, query, or cookie")
	}
	if sourceCount > 1 {
		return nil, errors.New("apiKey.keySource must define only one of header, query, or cookie")
	}

	if len(config.SecretValues) == 0 {
		return nil, errors.New("apiKey.secretValues must be set")
	}

	secretValues, err := resolveSecretValues(config.SecretValues)
	if err != nil {
		return nil, err
	}
	if len(secretValues) == 0 {
		return nil, errors.New("apiKey.secretValues must resolve to at least one value")
	}

	return &apiKey{
		next:                   next,
		name:                   name,
		keySource:              *config.KeySource,
		secretNonBase64Encoded: config.SecretNonBase64Encoded,
		secretValues:           secretValues,
	}, nil
}

func (a *apiKey) GetTracingInformation() (string, string) {
	return a.name, typeNameAPIKey
}

func (a *apiKey) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), a.name, typeNameAPIKey)

	key, ok := a.lookupKey(req)
	if !ok {
		logger.Debug().Msg("API key missing")
		observability.SetStatusErrorf(req.Context(), "API key missing")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	if !a.secretNonBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			logger.Debug().Err(err).Msg("API key base64 decode failed")
			observability.SetStatusErrorf(req.Context(), "API key base64 decode failed")
			http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		key = string(decoded)
	}

	if !a.isAuthorized(key) {
		logger.Debug().Msg("API key authentication failed")
		observability.SetStatusErrorf(req.Context(), "API key authentication failed")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	logger.Debug().Msg("API key authentication succeeded")
	a.next.ServeHTTP(rw, req)
}

func (a *apiKey) lookupKey(req *http.Request) (string, bool) {
	if a.keySource.Header != "" {
		value := req.Header.Get(a.keySource.Header)
		if value == "" {
			return "", false
		}
		if a.keySource.HeaderAuthScheme != "" && strings.EqualFold(a.keySource.Header, authorizationHeader) {
			return parseAuthScheme(value, a.keySource.HeaderAuthScheme)
		}
		return value, true
	}

	if a.keySource.Query != "" {
		value := req.URL.Query().Get(a.keySource.Query)
		if value == "" {
			return "", false
		}
		return value, true
	}

	if a.keySource.Cookie != "" {
		cookie, err := req.Cookie(a.keySource.Cookie)
		if err != nil {
			return "", false
		}
		if cookie.Value == "" {
			return "", false
		}
		return cookie.Value, true
	}

	return "", false
}

func (a *apiKey) isAuthorized(key string) bool {
	for _, secret := range a.secretValues {
		if goauth.CheckSecret(key, secret) {
			return true
		}
	}
	return false
}

func parseAuthScheme(value, scheme string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) < 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], scheme) {
		return "", false
	}
	return parts[1], true
}

func resolveSecretValues(values []string) ([]string, error) {
	resolved := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "file://") {
			path := strings.TrimPrefix(value, "file://")
			if path == "" {
				return nil, errors.New("apiKey.secretValues file:// path is empty")
			}
			fileValues, err := readSecretFile(path)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, fileValues...)
			continue
		}

		if looksLikeHash(value) {
			resolved = append(resolved, value)
			continue
		}

		fileValues, ok, err := tryReadSecretFile(value)
		if err != nil {
			return nil, err
		}
		if ok {
			resolved = append(resolved, fileValues...)
			continue
		}

		resolved = append(resolved, value)
	}
	return resolved, nil
}

func tryReadSecretFile(path string) ([]string, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	values, err := readSecretFile(path)
	if err != nil {
		return nil, false, err
	}
	return values, true, nil
}

func readSecretFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		values = append(values, trimmed)
	}
	return values, nil
}

func looksLikeHash(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(value, "$2") ||
		strings.HasPrefix(value, "$apr1$") ||
		strings.HasPrefix(value, "$1$") ||
		strings.HasPrefix(lower, "{sha}") ||
		strings.HasPrefix(lower, "{ssha}") ||
		strings.HasPrefix(lower, "{md5}") ||
		strings.HasPrefix(lower, "{smd5}")
}
