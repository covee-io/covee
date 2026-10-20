package management

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const oidcFlowDuration = 10 * time.Minute
const oidcSessionDuration = time.Hour

type oidcFlow struct {
	binding, nonce, verifier string
	// origin is the console origin the sign-in started at; the provider
	// returns there, and only there is the flow completed.
	origin  string
	expires time.Time
}

type oidcAuthenticator struct {
	client   *http.Client
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	mu       sync.Mutex
	flows    map[string]oidcFlow
}

func newOIDC(c Config, client *http.Client) (*oidcAuthenticator, error) {
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		transport.ResponseHeaderTimeout = 10 * time.Second
		transport.MaxResponseHeaderBytes = 64 << 10
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	base := oidc.ClientContext(context.Background(), client)
	ctx, cancel := context.WithTimeout(base, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, c.OIDCIssuer)
	if err != nil {
		client.CloseIdleConnections()
		return nil, errors.New("OIDC discovery failed; verify the issuer, TLS trust and provider availability")
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	endpoint := provider.Endpoint()
	if err := provider.Claims(&metadata); err != nil || !validHTTPSURL(metadata.JWKSURL) || !validHTTPSURL(endpoint.AuthURL) || !validHTTPSURL(endpoint.TokenURL) {
		client.CloseIdleConnections()
		return nil, errors.New("OIDC discovery requires valid HTTPS authorization, token and JWKS endpoints")
	}
	// Microsoft supports client_secret_post. Avoid probe/retry exchanges of a
	// single-use authorization code and never put the secret in a URL.
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &oidcAuthenticator{
		client:   client,
		oauth:    oauth2.Config{ClientID: c.OIDCClientID, ClientSecret: c.OIDCClientSecret, RedirectURL: c.PublicURL + "/auth/oidc/callback", Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}},
		verifier: provider.VerifierContext(base, &oidc.Config{ClientID: c.OIDCClientID, SupportedSigningAlgs: []string{oidc.RS256}}),
		flows:    make(map[string]oidcFlow),
	}, nil
}

func (s *Server) oidcHostAllowed(r *http.Request) bool {
	// Use the configured origins, never Forwarded/X-Forwarded-* headers.
	_, ok := s.hostOrigin(r)
	return ok
}

// oauthFor returns the OAuth configuration whose redirect returns to origin.
func (a *oidcAuthenticator) oauthFor(origin string) *oauth2.Config {
	c := a.oauth
	c.RedirectURL = origin + "/auth/oidc/callback"
	return &c
}

func (s *Server) oidcFlowCookie(w http.ResponseWriter, value string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "__Host-covee_oidc", Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: maxAge})
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		fail(w, 404, "not_found", "OIDC login is disabled")
		return
	}
	origin, ok := s.hostOrigin(r)
	if !ok || !s.sameOrigin(r) {
		fail(w, 403, "origin_rejected", "Request origin is not allowed")
		return
	}
	if !s.allowLogin(r) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "rate_limited", "Too many login attempts; try again in one minute")
		return
	}
	now := time.Now()
	flow := oidcFlow{binding: randomToken(), nonce: randomToken(), verifier: oauth2.GenerateVerifier(), origin: origin, expires: now.Add(oidcFlowDuration)}
	state := randomToken()
	s.oidc.mu.Lock()
	for key, pending := range s.oidc.flows {
		if !now.Before(pending.expires) {
			delete(s.oidc.flows, key)
		}
	}
	if len(s.oidc.flows) >= 1024 {
		s.oidc.mu.Unlock()
		fail(w, 503, "login_capacity", "Login capacity reached; try again later")
		return
	}
	s.oidc.flows[state] = flow
	s.oidc.mu.Unlock()
	s.oidcFlowCookie(w, flow.binding, flow.expires, int(oidcFlowDuration.Seconds()))
	// Return the navigation URL to same-origin JavaScript. A form redirect to a
	// third-party identity provider can be blocked by our form-action 'self' CSP.
	respond(w, 200, map[string]string{"authorizationUrl": s.oidc.oauthFor(origin).AuthCodeURL(state, oidc.Nonce(flow.nonce), oauth2.S256ChallengeOption(flow.verifier), oauth2.SetAuthURLParam("response_mode", "query"))})
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		fail(w, 404, "not_found", "OIDC login is disabled")
		return
	}
	failed := func() {
		fail(w, 400, "oidc_login_failed", "Sign-in could not be completed. Return to the console and try again.")
	}
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "OIDC callback requires GET")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !s.oidcHostAllowed(r) || len(q["state"]) != 1 || len(q["code"]) != 1 || q.Get("error") != "" || len(q.Get("code")) == 0 || len(q.Get("code")) > 8192 {
		failed()
		return
	}
	cookie, err := r.Cookie("__Host-covee_oidc")
	if err != nil {
		failed()
		return
	}
	now := time.Now()
	state := q.Get("state")
	s.oidc.mu.Lock()
	flow, ok := s.oidc.flows[state]
	if ok && !now.Before(flow.expires) {
		delete(s.oidc.flows, state)
		ok = false
	}
	if callbackOrigin, hostOK := s.hostOrigin(r); ok && hostOK && callbackOrigin == flow.origin && sameSecret(cookie.Value, flow.binding) {
		delete(s.oidc.flows, state) // Single use, including failed code/token exchange.
	} else {
		ok = false
	}
	s.oidc.mu.Unlock()
	if !ok {
		failed()
		return
	}
	s.oidcFlowCookie(w, "", time.Unix(1, 0), -1)
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), s.oidc.client), 10*time.Second)
	defer cancel()
	token, err := s.oidc.oauthFor(flow.origin).Exchange(ctx, q.Get("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil {
		failed()
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 64<<10 {
		failed()
		return
	}
	id, err := s.oidc.verifier.Verify(ctx, raw)
	if err != nil || id.Subject == "" || len(id.Subject) > 512 || !sameSecret(id.Nonce, flow.nonce) || id.IssuedAt.IsZero() || id.IssuedAt.After(now.Add(time.Minute)) {
		failed()
		return
	}
	var claims struct {
		Roles           []string `json:"roles"`
		Name            string   `json:"name"`
		AuthorizedParty string   `json:"azp"`
		NotBefore       int64    `json:"nbf"`
	}
	if err := id.Claims(&claims); err != nil || claims.NotBefore > now.Unix() || (claims.AuthorizedParty != "" && claims.AuthorizedParty != s.config.OIDCClientID) || (len(id.Audience) > 1 && claims.AuthorizedParty != s.config.OIDCClientID) {
		failed()
		return
	}
	role := ""
	for _, value := range claims.Roles {
		if value == roleAdmin {
			role = roleAdmin
			break
		}
		if value == roleReader {
			role = roleReader
		}
	}
	if role == "" {
		fail(w, 403, "role_required", "Your account needs the Covee.Admin or Covee.Reader app role")
		return
	}
	name := claims.Name
	if !validText(name, 0, 200) {
		name = ""
	}
	expires := minTime(time.Now().Add(oidcSessionDuration), id.Expiry)
	if !expires.After(time.Now()) {
		failed()
		return
	}
	actor := Actor{Type: "oidc", Issuer: id.Issuer, Subject: id.Subject, Name: name, Role: role}
	if _, ok := s.issueSession(w, r, actor, expires); !ok {
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
