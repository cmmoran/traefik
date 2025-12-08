package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
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

	return &apiKey{
		next:                   next,
		name:                   name,
		keySource:              *config.KeySource,
		secretNonBase64Encoded: config.SecretNonBase64Encoded,
		secretValues:           config.SecretValues,
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
