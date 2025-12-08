package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"github.com/traefik/traefik/v3/pkg/middlewares/accesslog"
	"github.com/traefik/traefik/v3/pkg/middlewares/observability"
	"github.com/traefik/traefik/v3/pkg/types"
	"golang.org/x/oauth2"
)

const (
	typeNameOIDC = "OIDC"

	defaultSessionExpirySeconds = 86400
	defaultStateMaxAgeSeconds   = 600
	defaultClientTimeoutSeconds = 5
	defaultClientMaxRetries     = 3
	defaultCSRFHeaderName       = "TraefikHub-Csrf-Token"
	csrfCookieName              = "traefikee-csrf-token"
)

type oidcAuth struct {
	next http.Handler
	name string

	issuer         string
	clientID       string
	clientSecret   string
	redirectURL    string
	loginURL       string
	logoutURL      string
	postLoginURL   string
	postLogoutURL  string
	backchannelURL string

	disableLogin bool
	pkce         bool

	claimsEvaluator  claimsExpression
	needsAccessToken bool
	usernameClaim    string
	forwardHeaders   map[string]string
	authParams       map[string]string

	oauthConfig         oauth2.Config
	tokenVerifier       *oidc.IDTokenVerifier
	accessTokenVerifier *oidc.IDTokenVerifier

	httpClient   *http.Client
	stateCodec   *cookieCodec
	sessionCodec *cookieCodec

	stateCookie   cookieConfig
	sessionCookie cookieConfig
	csrfConfig    *csrfConfig

	refreshEnabled  bool
	slidingSessions bool
	sessionExpiry   time.Duration
}

type cookieCodec struct {
	aead cipher.AEAD
}

type oidcSession struct {
	IDToken        string    `json:"idToken"`
	AccessToken    string    `json:"accessToken"`
	RefreshToken   string    `json:"refreshToken,omitempty"`
	TokenExpiresAt time.Time `json:"tokenExpiresAt"`
	SessionExpires time.Time `json:"sessionExpires"`
	CSRFToken      string    `json:"csrfToken,omitempty"`
}

type oidcState struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier,omitempty"`
	ReturnURL    string `json:"returnUrl,omitempty"`
	RedirectURL  string `json:"redirectUrl,omitempty"`
}

type cookieConfig struct {
	name     string
	path     string
	domain   string
	maxAge   int
	sameSite http.SameSite
	httpOnly bool
	secure   bool
}

type csrfConfig struct {
	secure     bool
	headerName string
}

type oidcMetadata struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

// NewOIDC creates an OpenID Connect authentication middleware.
func NewOIDC(ctx context.Context, next http.Handler, config dynamic.OIDC, name string) (http.Handler, error) {
	middlewares.GetLogger(ctx, name, typeNameOIDC).Debug().Msg("Creating middleware")

	if config.Issuer == "" {
		return nil, errors.New("oidc.issuer must be set")
	}
	if config.RedirectURL == "" {
		return nil, errors.New("oidc.redirectUrl must be set")
	}
	if config.ClientID == "" {
		return nil, errors.New("oidc.clientID must be set")
	}
	if config.ClientSecret == "" {
		return nil, errors.New("oidc.clientSecret must be set")
	}

	clientSecret, err := resolveOIDCClientSecret(config.ClientSecret)
	if err != nil {
		return nil, err
	}

	stateCookie, err := buildStateCookie(name, config.StateCookie)
	if err != nil {
		return nil, err
	}
	sessionCookie, err := buildSessionCookie(name, config.Session)
	if err != nil {
		return nil, err
	}

	sessionExpiry := time.Duration(sessionCookie.maxAge) * time.Second
	if sessionExpiry <= 0 {
		return nil, errors.New("oidc.session.expiry must be greater than zero")
	}

	clientConfig := config.ClientConfig
	clientTimeout := defaultClientTimeoutSeconds
	clientMaxRetries := defaultClientMaxRetries
	var clientTLS *types.ClientTLS
	if clientConfig != nil {
		if clientConfig.TimeoutSeconds > 0 {
			clientTimeout = clientConfig.TimeoutSeconds
		}
		if clientConfig.MaxRetries >= 0 {
			clientMaxRetries = clientConfig.MaxRetries
		}
		clientTLS = clientConfig.TLS
	}

	httpClient, err := buildOIDCHTTPClient(ctx, clientTimeout, clientMaxRetries, clientTLS)
	if err != nil {
		return nil, err
	}

	metadata, err := discoverOIDC(ctx, config.Issuer, config.DiscoveryParams, httpClient)
	if err != nil {
		return nil, err
	}
	if metadata.Issuer != "" && metadata.Issuer != config.Issuer {
		return nil, fmt.Errorf("oidc issuer mismatch: expected %s, got %s", config.Issuer, metadata.Issuer)
	}

	oidcCtx := oidc.ClientContext(ctx, httpClient)
	keySet := oidc.NewRemoteKeySet(oidcCtx, metadata.JWKSURL)
	verifier := oidc.NewVerifier(config.Issuer, keySet, &oidc.Config{
		ClientID: config.ClientID,
	})
	accessVerifier := oidc.NewVerifier(config.Issuer, keySet, &oidc.Config{
		SkipClientIDCheck: true,
	})

	scopes := ensureOpenIDScope(config.Scopes)
	oauthConfig := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  metadata.AuthURL,
			TokenURL: metadata.TokenURL,
		},
		Scopes: scopes,
	}

	claimsEvaluator, err := parseClaimsExpression(config.Claims)
	if err != nil {
		return nil, fmt.Errorf("invalid oidc claims expression: %w", err)
	}

	localCookieCodec, err := newCookieCodec(clientSecret, config.Issuer, name)
	if err != nil {
		return nil, err
	}

	csrfCfg := buildCSRFCfg(config.CSRF)

	if config.Session != nil && config.Session.Store != nil && config.Session.Store.Redis != nil {
		middlewares.GetLogger(ctx, name, typeNameOIDC).Warn().Msg("OIDC Redis session store is not supported yet; falling back to cookie-based sessions")
	}
	if config.BackchannelLogoutURL != "" {
		middlewares.GetLogger(ctx, name, typeNameOIDC).Warn().Msg("OIDC backchannel logout is not fully supported; requests are acknowledged without invalidating sessions")
	}

	refreshEnabled := true
	slidingSessions := true
	if config.Session != nil {
		if config.Session.Refresh != nil {
			refreshEnabled = *config.Session.Refresh
		}
		if config.Session.Sliding != nil {
			slidingSessions = *config.Session.Sliding
		}
	}

	return &oidcAuth{
		next:                next,
		name:                name,
		issuer:              config.Issuer,
		clientID:            config.ClientID,
		clientSecret:        clientSecret,
		redirectURL:         config.RedirectURL,
		loginURL:            config.LoginURL,
		logoutURL:           config.LogoutURL,
		postLoginURL:        config.PostLoginRedirectURL,
		postLogoutURL:       config.PostLogoutRedirectURL,
		backchannelURL:      config.BackchannelLogoutURL,
		disableLogin:        config.DisableLogin,
		pkce:                config.PKCE,
		claimsEvaluator:     claimsEvaluator,
		needsAccessToken:    claimsEvaluator != nil && claimsEvaluator.NeedsAccessToken(),
		usernameClaim:       config.UsernameClaim,
		forwardHeaders:      config.ForwardHeaders,
		authParams:          config.AuthParams,
		oauthConfig:         oauthConfig,
		tokenVerifier:       verifier,
		accessTokenVerifier: accessVerifier,
		httpClient:          httpClient,
		stateCodec:          localCookieCodec,
		sessionCodec:        localCookieCodec,
		stateCookie:         stateCookie,
		sessionCookie:       sessionCookie,
		csrfConfig:          csrfCfg,
		refreshEnabled:      refreshEnabled,
		slidingSessions:     slidingSessions,
		sessionExpiry:       sessionExpiry,
	}, nil
}

func (o *oidcAuth) GetTracingInformation() (string, string) {
	return o.name, typeNameOIDC
}

func (o *oidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), o.name, typeNameOIDC)

	if o.logoutURL != "" && matchConfiguredURL(req, o.logoutURL) {
		o.handleLogout(rw, req, logger)
		return
	}

	if o.backchannelURL != "" && matchConfiguredURL(req, o.backchannelURL) {
		logger.Debug().Msg("Backchannel logout received")
		rw.WriteHeader(http.StatusOK)
		return
	}

	if matchConfiguredURL(req, o.redirectURL) {
		o.handleCallback(rw, req, logger)
		return
	}

	session, claims, ok, handled := o.validateSession(rw, req, logger)
	if handled {
		return
	}
	if ok {
		o.applyClaims(req, claims)
		o.touchSession(rw, session)
		o.next.ServeHTTP(rw, req)
		return
	}

	if o.disableLogin {
		observability.SetStatusErrorf(req.Context(), "OIDC authorization required")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	if o.loginURL != "" && !matchConfiguredURL(req, o.loginURL) {
		observability.SetStatusErrorf(req.Context(), "OIDC authorization required")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	o.startLogin(rw, req, logger)
}

func (o *oidcAuth) validateSession(rw http.ResponseWriter, req *http.Request, logger *zerolog.Logger) (*oidcSession, tokenClaims, bool, bool) {
	session, ok := o.readSession(req)
	if !ok {
		return nil, tokenClaims{}, false, false
	}
	if time.Now().After(session.SessionExpires) {
		o.clearSession(rw)
		return nil, tokenClaims{}, false, false
	}

	if o.csrfConfig != nil && !isSafeMethod(req.Method) {
		if !o.validateCSRF(req, session) {
			logger.Debug().Msg("CSRF validation failed")
			observability.SetStatusErrorf(req.Context(), "CSRF validation failed")
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return nil, tokenClaims{}, false, true
		}
	}

	claims, refreshed, ok := o.verifyTokens(req.Context(), session, logger)
	if !ok {
		o.clearSession(rw)
		return nil, tokenClaims{}, false, false
	}
	if refreshed {
		o.storeSession(rw, session)
	}

	if o.claimsEvaluator != nil && !o.claimsEvaluator.Eval(claims) {
		logger.Debug().Msg("OIDC claims validation failed")
		observability.SetStatusErrorf(req.Context(), "OIDC claims validation failed")
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil, tokenClaims{}, false, true
	}

	return session, claims, true, false
}

func (o *oidcAuth) handleCallback(rw http.ResponseWriter, req *http.Request, logger *zerolog.Logger) {
	stateParam := req.URL.Query().Get("state")
	code := req.URL.Query().Get("code")
	if stateParam == "" || code == "" {
		observability.SetStatusErrorf(req.Context(), "OIDC callback missing state or code")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	state, ok := o.readState(req)
	if !ok {
		observability.SetStatusErrorf(req.Context(), "OIDC state validation failed")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if state.State != stateParam {
		observability.SetStatusErrorf(req.Context(), "OIDC state validation failed")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	redirectURL := o.resolveRedirectURL(req)
	exchangeOpts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("redirect_uri", redirectURL)}
	if o.pkce && state.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("code_verifier", state.CodeVerifier))
	}

	ctx := oidc.ClientContext(req.Context(), o.httpClient)
	token, err := o.oauthConfig.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		logger.Debug().Err(err).Msg("OIDC code exchange failed")
		observability.SetStatusErrorf(req.Context(), "OIDC code exchange failed")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		logger.Debug().Msg("OIDC missing id_token")
		observability.SetStatusErrorf(req.Context(), "OIDC missing id_token")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	idToken, err := o.tokenVerifier.Verify(ctx, idTokenRaw)
	if err != nil {
		logger.Debug().Err(err).Msg("OIDC id_token verification failed")
		observability.SetStatusErrorf(req.Context(), "OIDC id_token verification failed")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if state.Nonce != "" && idToken.Nonce != state.Nonce {
		logger.Debug().Msg("OIDC nonce mismatch")
		observability.SetStatusErrorf(req.Context(), "OIDC nonce mismatch")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	session := &oidcSession{
		IDToken:        idTokenRaw,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		TokenExpiresAt: token.Expiry,
		SessionExpires: time.Now().Add(o.sessionExpiry),
	}
	if o.csrfConfig != nil {
		session.CSRFToken = randomString(32)
	}

	o.storeSession(rw, session)
	o.clearState(rw)

	redirectTarget := state.ReturnURL
	if o.postLoginURL != "" {
		redirectTarget = o.postLoginURL
	}
	if redirectTarget == "" || redirectTarget == o.loginURL {
		redirectTarget = "/"
	}
	http.Redirect(rw, req, redirectTarget, http.StatusFound)
}

func (o *oidcAuth) handleLogout(rw http.ResponseWriter, req *http.Request, logger *zerolog.Logger) {
	o.clearSession(rw)
	o.clearState(rw)
	logger.Debug().Msg("OIDC session cleared")

	target := o.postLogoutURL
	if target == "" {
		rw.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(rw, req, target, http.StatusFound)
}

func (o *oidcAuth) startLogin(rw http.ResponseWriter, req *http.Request, logger *zerolog.Logger) {
	state := randomString(24)
	nonce := randomString(24)

	statePayload := oidcState{
		State:     state,
		Nonce:     nonce,
		ReturnURL: req.URL.RequestURI(),
	}

	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("redirect_uri", o.resolveRedirectURL(req)),
	}

	if o.pkce {
		statePayload.CodeVerifier = randomString(64)
		codeChallenge := codeChallengeS256(statePayload.CodeVerifier)
		authOpts = append(authOpts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	for key, value := range o.authParams {
		if key == "prompt" && value == "" {
			continue
		}
		authOpts = append(authOpts, oauth2.SetAuthURLParam(key, value))
	}

	if err := o.storeState(rw, statePayload); err != nil {
		observability.SetStatusErrorf(req.Context(), "OIDC state cookie creation failed")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	authURL := o.oauthConfig.AuthCodeURL(state, authOpts...)
	logger.Debug().Msg("Redirecting to OIDC provider")
	http.Redirect(rw, req, authURL, http.StatusFound)
}

func (o *oidcAuth) verifyTokens(ctx context.Context, session *oidcSession, logger *zerolog.Logger) (tokenClaims, bool, bool) {
	ctx = oidc.ClientContext(ctx, o.httpClient)

	refreshed := false
	if !session.TokenExpiresAt.IsZero() && time.Now().After(session.TokenExpiresAt) {
		if !o.refreshEnabled || session.RefreshToken == "" {
			return tokenClaims{}, false, false
		}
		if err := o.refreshToken(ctx, session); err != nil {
			logger.Debug().Err(err).Msg("OIDC refresh failed")
			return tokenClaims{}, false, false
		}
		refreshed = true
	}

	idToken, err := o.tokenVerifier.Verify(ctx, session.IDToken)
	if err != nil {
		logger.Debug().Err(err).Msg("OIDC id_token verification failed")
		return tokenClaims{}, false, false
	}

	var idClaims map[string]any
	if err := idToken.Claims(&idClaims); err != nil {
		logger.Debug().Err(err).Msg("OIDC id_token claims extraction failed")
		return tokenClaims{}, false, false
	}

	claims := tokenClaims{idToken: idClaims}

	if o.needsAccessToken || o.usernameClaim != "" || len(o.forwardHeaders) > 0 {
		if session.AccessToken != "" && looksLikeJWT(session.AccessToken) {
			accessToken, err := o.accessTokenVerifier.Verify(ctx, session.AccessToken)
			if err == nil {
				var accessClaims map[string]any
				if err := accessToken.Claims(&accessClaims); err == nil {
					claims.accessToken = accessClaims
				}
			}
		}
	}

	return claims, refreshed, true
}

func (o *oidcAuth) refreshToken(ctx context.Context, session *oidcSession) error {
	token := &oauth2.Token{
		RefreshToken: session.RefreshToken,
		Expiry:       session.TokenExpiresAt,
	}
	source := o.oauthConfig.TokenSource(ctx, token)
	newToken, err := source.Token()
	if err != nil {
		return err
	}
	if newToken.AccessToken != "" {
		session.AccessToken = newToken.AccessToken
	}
	if newToken.RefreshToken != "" {
		session.RefreshToken = newToken.RefreshToken
	}
	session.TokenExpiresAt = newToken.Expiry

	if idTokenRaw, ok := newToken.Extra("id_token").(string); ok && idTokenRaw != "" {
		session.IDToken = idTokenRaw
	}
	return nil
}

func (o *oidcAuth) applyClaims(req *http.Request, claims tokenClaims) {
	if o.usernameClaim != "" {
		if value, ok := lookupClaimValue(claims, o.usernameClaim); ok {
			logData := accesslog.GetLogData(req)
			if logData != nil {
				logData.Core[accesslog.ClientUsername] = value
			}
		}
	}

	if len(o.forwardHeaders) == 0 {
		return
	}

	for header, claimKey := range o.forwardHeaders {
		if value, ok := lookupClaimValue(claims, claimKey); ok {
			req.Header.Set(header, value)
			continue
		}
		req.Header.Set(header, "")
	}
}

func (o *oidcAuth) touchSession(rw http.ResponseWriter, session *oidcSession) {
	if !o.slidingSessions {
		return
	}
	session.SessionExpires = time.Now().Add(o.sessionExpiry)
	o.storeSession(rw, session)
}

func (o *oidcAuth) validateCSRF(req *http.Request, session *oidcSession) bool {
	if session.CSRFToken == "" {
		return false
	}
	cookie, err := req.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	headerValue := req.Header.Get(o.csrfConfig.headerName)
	return headerValue != "" && headerValue == cookie.Value && headerValue == session.CSRFToken
}

func (o *oidcAuth) readSession(req *http.Request) (*oidcSession, bool) {
	cookie, err := req.Cookie(o.sessionCookie.name)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	data, err := o.sessionCodec.Decode(cookie.Value)
	if err != nil {
		return nil, false
	}
	var session oidcSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, false
	}
	return &session, true
}

func (o *oidcAuth) storeSession(rw http.ResponseWriter, session *oidcSession) {
	data, err := json.Marshal(session)
	if err != nil {
		return
	}
	encoded, err := o.sessionCodec.Encode(data)
	if err != nil {
		return
	}

	cookie := buildHTTPCookie(o.sessionCookie, encoded, session.SessionExpires)
	http.SetCookie(rw, cookie)

	if o.csrfConfig != nil {
		csrfCookie := buildHTTPCookie(cookieConfig{
			name:     csrfCookieName,
			path:     o.sessionCookie.path,
			domain:   o.sessionCookie.domain,
			maxAge:   o.sessionCookie.maxAge,
			sameSite: o.sessionCookie.sameSite,
			httpOnly: false,
			secure:   o.csrfConfig.secure,
		}, session.CSRFToken, session.SessionExpires)
		http.SetCookie(rw, csrfCookie)
	}
}

func (o *oidcAuth) clearSession(rw http.ResponseWriter) {
	http.SetCookie(rw, deleteCookie(o.sessionCookie))
	if o.csrfConfig != nil {
		http.SetCookie(rw, deleteCookie(cookieConfig{name: csrfCookieName, path: o.sessionCookie.path, domain: o.sessionCookie.domain}))
	}
}

func (o *oidcAuth) readState(req *http.Request) (*oidcState, bool) {
	cookie, err := req.Cookie(o.stateCookie.name)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	data, err := o.stateCodec.Decode(cookie.Value)
	if err != nil {
		return nil, false
	}
	var state oidcState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false
	}
	return &state, true
}

func (o *oidcAuth) storeState(rw http.ResponseWriter, state oidcState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	encoded, err := o.stateCodec.Encode(data)
	if err != nil {
		return err
	}
	cookie := buildHTTPCookie(o.stateCookie, encoded, time.Now().Add(time.Duration(o.stateCookie.maxAge)*time.Second))
	http.SetCookie(rw, cookie)
	return nil
}

func (o *oidcAuth) clearState(rw http.ResponseWriter) {
	http.SetCookie(rw, deleteCookie(o.stateCookie))
}

func (o *oidcAuth) resolveRedirectURL(req *http.Request) string {
	return resolveURL(req, o.redirectURL)
}

func buildStateCookie(name string, cfg *dynamic.OIDCStateCookie) (cookieConfig, error) {
	baseName := sanitizeCookieName(name)
	if baseName == "" {
		baseName = "oidc"
	}
	state := cookieConfig{
		name:     baseName + "-state",
		path:     "/",
		maxAge:   defaultStateMaxAgeSeconds,
		sameSite: http.SameSiteLaxMode,
		httpOnly: true,
	}
	if cfg == nil {
		return state, nil
	}
	if cfg.Name != "" {
		state.name = cfg.Name
	}
	if cfg.Path != "" {
		state.path = cfg.Path
	}
	if cfg.Domain != "" {
		state.domain = cfg.Domain
	}
	if cfg.MaxAge != 0 {
		state.maxAge = cfg.MaxAge
	}
	if cfg.SameSite != "" {
		parsed, err := parseSameSite(cfg.SameSite)
		if err != nil {
			return state, err
		}
		state.sameSite = parsed
	}
	if cfg.HTTPOnly != nil {
		state.httpOnly = *cfg.HTTPOnly
	}
	if cfg.Secure {
		state.secure = true
	}
	return state, nil
}

func buildSessionCookie(name string, cfg *dynamic.OIDCSession) (cookieConfig, error) {
	baseName := sanitizeCookieName(name)
	if baseName == "" {
		baseName = "oidc"
	}
	session := cookieConfig{
		name:     baseName + "-session",
		path:     "/",
		maxAge:   defaultSessionExpirySeconds,
		sameSite: http.SameSiteLaxMode,
		httpOnly: true,
	}
	if cfg == nil {
		return session, nil
	}
	if cfg.Name != "" {
		session.name = cfg.Name
	}
	if cfg.Path != "" {
		session.path = cfg.Path
	}
	if cfg.Domain != "" {
		session.domain = cfg.Domain
	}
	if cfg.Expiry != 0 {
		session.maxAge = cfg.Expiry
	}
	if cfg.SameSite != "" {
		parsed, err := parseSameSite(cfg.SameSite)
		if err != nil {
			return session, err
		}
		session.sameSite = parsed
	}
	if cfg.HTTPOnly != nil {
		session.httpOnly = *cfg.HTTPOnly
	}
	if cfg.Secure {
		session.secure = true
	}
	return session, nil
}

func buildCSRFCfg(cfg *dynamic.OIDCCSRF) *csrfConfig {
	if cfg == nil {
		return nil
	}
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = defaultCSRFHeaderName
	}
	return &csrfConfig{
		secure:     cfg.Secure,
		headerName: headerName,
	}
}

func buildHTTPCookie(cfg cookieConfig, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     cfg.name,
		Value:    value,
		Path:     cfg.path,
		Domain:   cfg.domain,
		MaxAge:   cfg.maxAge,
		Expires:  expires,
		Secure:   cfg.secure,
		HttpOnly: cfg.httpOnly,
		SameSite: cfg.sameSite,
	}
}

func deleteCookie(cfg cookieConfig) *http.Cookie {
	return &http.Cookie{
		Name:     cfg.name,
		Path:     cfg.path,
		Domain:   cfg.domain,
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: cfg.httpOnly,
		SameSite: cfg.sameSite,
		Secure:   cfg.secure,
	}
}

func parseSameSite(value string) (http.SameSite, error) {
	switch strings.ToLower(value) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("invalid sameSite %q", value)
	}
}

func newCookieCodec(secret, issuer, name string) (*cookieCodec, error) {
	key := sha256.Sum256([]byte(secret + ":" + issuer + ":" + name))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &cookieCodec{aead: gcm}, nil
}

func (c *cookieCodec) Encode(data []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	encrypted := c.aead.Seal(nonce, nonce, data, nil)
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func (c *cookieCodec) Decode(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(raw) < c.aead.NonceSize() {
		return nil, errors.New("invalid cookie payload")
	}
	nonce := raw[:c.aead.NonceSize()]
	ciphertext := raw[c.aead.NonceSize():]
	return c.aead.Open(nil, nonce, ciphertext, nil)
}

func randomString(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	data := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return ""
	}
	for i, b := range data {
		data[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(data)
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ensureOpenIDScope(scopes []string) []string {
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return append(scopes, "openid")
	}
	return scopes
}

func discoverOIDC(ctx context.Context, issuer string, params map[string]string, client *http.Client) (*oidcMetadata, error) {
	issuer = strings.TrimRight(issuer, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"
	urlParsed, err := url.Parse(discoveryURL)
	if err != nil {
		return nil, err
	}
	if len(params) > 0 {
		query := urlParsed.Query()
		for key, value := range params {
			query.Set(key, value)
		}
		urlParsed.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlParsed.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discovery returned %s", resp.Status)
	}

	var metadata oidcMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}
	if metadata.AuthURL == "" || metadata.TokenURL == "" || metadata.JWKSURL == "" {
		return nil, errors.New("oidc discovery missing endpoints")
	}
	return &metadata, nil
}

func buildOIDCHTTPClient(ctx context.Context, timeoutSeconds int, maxRetries int, tlsConfig *types.ClientTLS) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		tlsConf, err := tlsConfig.CreateTLSConfig(ctx)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConf
	}

	var rt http.RoundTripper = transport
	if maxRetries > 0 {
		rt = &retryRoundTripper{base: transport, maxRetries: maxRetries}
	}

	return &http.Client{
		Transport: rt,
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
	}, nil
}

type retryRoundTripper struct {
	base       http.RoundTripper
	maxRetries int
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		resp, err := r.base.RoundTrip(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("status %s", resp.Status)
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func matchConfiguredURL(req *http.Request, cfg string) bool {
	if cfg == "" {
		return false
	}
	reqPath := requestPath(req)
	if strings.HasPrefix(cfg, "http://") || strings.HasPrefix(cfg, "https://") {
		parsed, err := url.Parse(cfg)
		if err != nil {
			return false
		}
		return strings.EqualFold(parsed.Host, requestHost(req)) && reqPath == parsed.Path
	}
	if strings.HasPrefix(cfg, "/") {
		return reqPath == cfg
	}
	host, pathSuffix, ok := strings.Cut(cfg, "/")
	if !ok {
		host = cfg
		pathSuffix = ""
	}
	if pathSuffix == "" {
		return strings.EqualFold(host, requestHost(req))
	}
	return strings.EqualFold(host, requestHost(req)) && reqPath == "/"+pathSuffix
}

func resolveURL(req *http.Request, cfg string) string {
	if cfg == "" {
		return ""
	}
	if strings.HasPrefix(cfg, "http://") || strings.HasPrefix(cfg, "https://") {
		return cfg
	}
	scheme := requestScheme(req)
	if strings.HasPrefix(cfg, "/") {
		return fmt.Sprintf("%s://%s%s", scheme, requestHost(req), cfg)
	}
	return fmt.Sprintf("%s://%s", scheme, cfg)
}

func requestScheme(req *http.Request) string {
	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
		if parts := strings.Split(proto, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if req.TLS != nil {
		return "https"
	}
	if req.URL.Scheme != "" {
		return req.URL.Scheme
	}
	return "http"
}

func requestHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		if parts := strings.Split(host, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return req.Host
}

func requestPath(req *http.Request) string {
	path := req.URL.Path
	if path == "" && req.RequestURI != "" {
		path = req.RequestURI
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	return path
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func looksLikeJWT(value string) bool {
	return strings.Count(value, ".") == 2
}

func lookupClaimValue(claims tokenClaims, key string) (string, bool) {
	tokenKind, claimKey := splitTokenKey(key)
	var source map[string]any
	switch tokenKind {
	case "access_token":
		source = claims.accessToken
	default:
		source = claims.idToken
	}
	value, ok := lookupClaim(source, claimKey)
	if !ok {
		return "", false
	}
	return fmt.Sprint(value), true
}

func sanitizeCookieName(name string) string {
	if name == "" {
		return ""
	}
	base := strings.SplitN(name, "@", 2)[0]
	var builder strings.Builder
	for _, ch := range base {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			builder.WriteRune(ch)
			continue
		}
		builder.WriteByte('-')
	}
	return strings.Trim(builder.String(), "-")
}

func resolveOIDCClientSecret(secret string) (string, error) {
	if strings.HasPrefix(secret, "file://") {
		path := strings.TrimPrefix(secret, "file://")
		if path == "" {
			return "", errors.New("oidc.clientSecret file:// path is empty")
		}
		values, err := readSecretFile(path)
		if err != nil {
			return "", err
		}
		return firstSecretValue(values)
	}

	values, ok, err := tryReadSecretFile(secret)
	if err != nil {
		return "", err
	}
	if ok {
		return firstSecretValue(values)
	}

	return secret, nil
}

func firstSecretValue(values []string) (string, error) {
	if len(values) == 0 {
		return "", errors.New("oidc.clientSecret file is empty")
	}
	if len(values) > 1 {
		return "", errors.New("oidc.clientSecret file must contain a single value")
	}
	return values[0], nil
}
