package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/oauth2"
)

const flowCookie = "__Host-covee_identity"
const lifetime = 5 * time.Minute

type upstream struct {
	config   ProviderConfig
	issuer   string
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	appleKey *ecdsa.PrivateKey
}
type downstream struct {
	config ClientConfig
	secret string
}
type authorization struct{ client, redirect, challenge, nonce, state, kind string }
type flow struct {
	authorization
	binding, provider, nonce, verifier string
	expires                            time.Time
	// login is the pending passkey challenge of a local sign-in.
	login *webauthn.SessionData
}
type identityClaims struct {
	Subject         string   `json:"sub"`
	Username        string   `json:"preferred_username"`
	Name            string   `json:"name"`
	Roles           []string `json:"roles,omitempty"`
	Groups          []string `json:"groups,omitempty"`
	UpstreamIssuer  string   `json:"upstream_issuer"`
	UpstreamSubject string   `json:"upstream_sub"`
}
type code struct {
	authorization
	claims  identityClaims
	expires time.Time
}
type access struct {
	claims  identityClaims
	expires time.Time
}

type Server struct {
	config       Config
	client       *http.Client
	providers    map[string]*upstream
	clients      map[string]downstream
	grants       map[string]Grant
	key          *rsa.PrivateKey
	kid          string
	mu           sync.Mutex
	flows        map[string]flow
	codes        map[string]code
	access       map[string]access
	startTokens  float64
	startUpdated time.Time
	// local is set when operator-invited Covee accounts are enabled.
	local *localProvider
}

func New(ctx context.Context, c Config) (*Server, error) {
	// Trusted callers may provide a verified test/private-root client through
	// oidc.ClientContext. Production main passes context.Background and uses
	// the hardened, proxy-free transport below.
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	return newWithClient(ctx, c, client)
}
func newWithClient(ctx context.Context, c Config, client *http.Client) (*Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	key, err := readSigningKey(c.SigningKeyFile)
	if err != nil {
		return nil, errors.New("identity signing key could not be loaded")
	}
	if _, err := privateFile(c.TLSKeyFile, 32<<10); err != nil {
		return nil, errors.New("identity TLS key must be private")
	}
	if _, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
		return nil, errors.New("identity TLS certificate/key could not be loaded")
	}
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		transport.ResponseHeaderTimeout = 10 * time.Second
		transport.MaxResponseHeaderBytes = 64 << 10
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	// go-oidc reads discovery/JWKS responses in full. Bound the decompressed
	// response stream as well as socket time/header limits.
	boundedClient := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	boundedClient.Transport = boundedTransport{transport}
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if boundedClient.Timeout <= 0 || boundedClient.Timeout > 10*time.Second {
		boundedClient.Timeout = 10 * time.Second
	}
	client = &boundedClient
	s := &Server{config: c, client: client, key: key, kid: keyID(key), providers: map[string]*upstream{}, clients: map[string]downstream{}, grants: map[string]Grant{}, flows: map[string]flow{}, codes: map[string]code{}, access: map[string]access{}, startTokens: 32, startUpdated: time.Now()}
	for _, cc := range c.Clients {
		secret, err := readSecret(cc.SecretFile, 32)
		if err != nil {
			return nil, errors.New("identity downstream client secret could not be loaded")
		}
		s.clients[cc.ID] = downstream{cc, secret}
	}
	for _, g := range c.Grants {
		s.grants[g.Provider+"\x00"+g.Subject] = g
	}
	base := oidc.ClientContext(ctx, client)
	for _, p := range c.Providers {
		if p.ID == "local" {
			// Local accounts have no upstream issuer to discover.
			if s.local, err = newLocal(c.Issuer, p); err != nil {
				return nil, err
			}
			continue
		}
		issuer := p.Issuer
		if p.ID == "google" {
			issuer = GoogleIssuer
		}
		if p.ID == "apple" {
			issuer = AppleIssuer
		}
		discovery, cancel := context.WithTimeout(base, 10*time.Second)
		provider, err := oidc.NewProvider(discovery, issuer)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("identity %s provider discovery failed", p.ID)
		}
		var metadata struct {
			JWKS string `json:"jwks_uri"`
		}
		endpoint := provider.Endpoint()
		if provider.Claims(&metadata) != nil {
			return nil, errors.New("identity provider discovery metadata invalid")
		}
		for _, raw := range []string{metadata.JWKS, endpoint.AuthURL, endpoint.TokenURL} {
			if _, err := httpsURL(raw); err != nil {
				return nil, errors.New("identity provider endpoints must be HTTPS")
			}
		}
		if p.ID == "google" && (endpoint.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" || endpoint.TokenURL != "https://oauth2.googleapis.com/token" || metadata.JWKS != "https://www.googleapis.com/oauth2/v3/certs") {
			return nil, errors.New("Google discovery endpoints do not match its supported endpoints")
		}
		if p.ID == "apple" && (endpoint.AuthURL != AppleIssuer+"/auth/authorize" || endpoint.TokenURL != AppleIssuer+"/auth/token" || metadata.JWKS != AppleIssuer+"/auth/keys") {
			return nil, errors.New("Apple discovery endpoints do not match its supported endpoints")
		}
		endpoint.AuthStyle = oauth2.AuthStyleInParams
		u := &upstream{config: p, issuer: issuer, oauth: oauth2.Config{ClientID: p.ClientID, RedirectURL: c.Issuer + "/callback/" + p.ID, Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile}}, verifier: provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: p.ClientID, SupportedSigningAlgs: []string{oidc.RS256}})}
		if p.ID == "apple" {
			u.appleKey, err = readAppleKey(p.PrivateKeyFile)
			u.oauth.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeEmail}
		} else {
			u.oauth.ClientSecret, err = readSecret(p.ClientSecretFile, 1)
		}
		if err != nil {
			return nil, fmt.Errorf("identity %s provider secret could not be loaded", p.ID)
		}
		s.providers[p.ID] = u
	}
	return s, nil
}

type boundedTransport struct{ http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(r)
	if err == nil {
		response.Body = http.MaxBytesReader(nil, response.Body, 1<<20)
	}
	return response, err
}
func (t boundedTransport) CloseIdleConnections() {
	if closer, ok := t.RoundTripper.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }
func (s *Server) Close()                { s.client.CloseIdleConnections() }
func (s *Server) ListenAndServe() error {
	server := &http.Server{Addr: s.config.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
}
func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("cryptographic randomness unavailable")
	}
	return base64URL(b)
}
func same(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func (s *Server) origin() string {
	u, _ := url.Parse(s.config.Issuer)
	return u.Scheme + "://" + u.Host
}
func (s *Server) clean(now time.Time) {
	for k, v := range s.flows {
		if !now.Before(v.expires) {
			delete(s.flows, k)
		}
	}
	for k, v := range s.codes {
		if !now.Before(v.expires) {
			delete(s.codes, k)
		}
	}
	for k, v := range s.access {
		if !now.Before(v.expires) {
			delete(s.access, k)
		}
	}
}
func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func deny(w http.ResponseWriter, status int, code string) {
	if b, ok := w.(browserWriter); ok {
		renderError(b, status, code)
		return
	}
	reply(w, status, map[string]string{"error": code})
}

// host is the network's public hostname, shown at the foot of every page.
func (s *Server) host() string {
	u, _ := url.Parse(s.config.Issuer)
	return u.Host
}
func (s *Server) cookie(w http.ResponseWriter, value string, expires time.Time, sameSite http.SameSite, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: sameSite, MaxAge: maxAge, Expires: expires})
}
func single(v url.Values, key string) string {
	if len(v[key]) != 1 {
		return ""
	}
	return v[key][0]
}
func singletonValues(v url.Values) bool {
	for _, values := range v {
		if len(values) != 1 {
			return false
		}
	}
	return true
}
func parseForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.URL.RawQuery != "" {
		return nil, errors.New("query forbidden")
	}
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/x-www-form-urlencoded" {
		return nil, errors.New("form required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(string(b))
	if err != nil || !singletonValues(values) {
		return nil, errors.New("invalid or duplicate form parameters")
	}
	return values, nil
}
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Not no-referrer: browsers then send "Origin: null" when the chooser form posts to
	// /identity/select, and that request must carry this origin. same-origin still keeps
	// URLs away from the providers.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	u, _ := url.Parse(s.config.Issuer)
	if !strings.EqualFold(r.Host, u.Host) || r.URL.RawPath != "" || len(r.URL.RawQuery) > 16<<10 || r.TLS == nil {
		deny(w, 400, "invalid_request")
		return
	}
	w = asBrowser(w, r, u.Host)
	path := r.URL.Path
	switch {
	case path == "/identity/.well-known/openid-configuration" && r.Method == "GET":
		s.discovery(w)
	case path == "/identity/jwks" && r.Method == "GET":
		reply(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"}}})
	case path == "/identity/providers" && r.Method == "GET":
		var providers []map[string]string
		for _, id := range s.providerOrder() {
			providers = append(providers, map[string]string{"id": id, "name": providerName(id)})
		}
		reply(w, 200, providers)
	case path == "/identity/healthz" && r.Method == "GET":
		reply(w, 200, map[string]string{"status": "ok"})
	case path == "/identity/authorize" && r.Method == "GET":
		s.authorize(w, r)
	case path == "/identity/select" && r.Method == "POST":
		s.selectProvider(w, r)
	case strings.HasPrefix(path, "/identity/callback/"):
		s.callback(w, r, strings.TrimPrefix(path, "/identity/callback/"))
	case path == "/identity/token" && r.Method == "POST":
		s.token(w, r)
	case path == "/identity/userinfo" && (r.Method == "GET" || r.Method == "POST"):
		s.userinfo(w, r)
	case strings.HasPrefix(path, "/identity/local/") && s.local != nil:
		s.serveLocal(w, r, path)
	default:
		deny(w, 404, "not_found")
	}
}
func providerName(id string) string {
	switch id {
	case "entra":
		return "Microsoft"
	case "google":
		return "Google"
	case "apple":
		return "Apple"
	case "local":
		return "a Covee account"
	}
	return ""
}

// providerOrder lists the enabled providers in display order.
func (s *Server) providerOrder() []string {
	var ids []string
	for _, id := range []string{"entra", "google", "apple"} {
		if _, ok := s.providers[id]; ok {
			ids = append(ids, id)
		}
	}
	if s.local != nil {
		ids = append(ids, "local")
	}
	return ids
}
func (s *Server) discovery(w http.ResponseWriter) {
	base := s.config.Issuer
	reply(w, 200, map[string]any{"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "userinfo_endpoint": base + "/userinfo", "jwks_uri": base + "/jwks", "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"}, "grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid", "profile", "email"}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !singletonValues(q) {
		deny(w, 400, "invalid_request")
		return
	}
	client, ok := s.clients[single(q, "client_id")]
	challenge := single(q, "code_challenge")
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if !ok || single(q, "response_type") != "code" || !client.config.allowsRedirect(single(q, "redirect_uri")) || single(q, "code_challenge_method") != "S256" || err != nil || len(decoded) != 32 || base64URL(decoded) != challenge || !textOK(single(q, "nonce"), 16, 256) || !textOK(single(q, "state"), 16, 512) || (q.Get("response_mode") != "" && single(q, "response_mode") != "query") {
		deny(w, 400, "invalid_request")
		return
	}
	scopes := strings.Fields(single(q, "scope"))
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
		} else if scope != "profile" && scope != "email" {
			deny(w, 400, "invalid_scope")
			return
		}
	}
	if !hasOpenID {
		deny(w, 400, "invalid_scope")
		return
	}
	now := time.Now()
	state := random()
	pending := flow{authorization: authorization{client: client.config.ID, redirect: single(q, "redirect_uri"), challenge: challenge, nonce: single(q, "nonce"), state: single(q, "state"), kind: client.config.Kind}, binding: random(), expires: now.Add(10 * time.Minute)}
	s.mu.Lock()
	s.clean(now)
	// This is a global bucket. The private broker sees the ingress peer and
	// deliberately does not trust Forwarded headers. At most 632 starts fit
	// into the ten-minute flow lifetime, below the 1024-flow storage ceiling.
	s.startTokens = min(32, s.startTokens+now.Sub(s.startUpdated).Seconds())
	s.startUpdated = now
	if s.startTokens < 1 {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		deny(w, 429, "rate_limited")
		return
	}
	s.startTokens--
	if len(s.flows) >= 1024 {
		s.mu.Unlock()
		deny(w, 503, "temporarily_unavailable")
		return
	}
	s.flows[state] = pending
	s.mu.Unlock()
	s.cookie(w, pending.binding, pending.expires, http.SameSiteLaxMode, 600)
	data := pageData{Title: "Sign in", Host: s.host(), Console: client.config.Kind == "console", State: state}
	for _, id := range s.providerOrder() {
		data.Providers = append(data.Providers, providerChoice{ID: id, Name: providerName(id), Icon: providerIcons[id]})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	chooser.Execute(w, data)
}
func (s *Server) selectProvider(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.origin() {
		deny(w, 403, "origin_rejected")
		return
	}
	form, err := parseForm(w, r)
	if err != nil {
		deny(w, 400, "invalid_request")
		return
	}
	id, state := single(form, "provider"), single(form, "state")
	u, ok := s.providers[id]
	if !ok && (id != "local" || s.local == nil) {
		deny(w, 400, "invalid_request")
		return
	}
	cookie, err := r.Cookie(flowCookie)
	if err != nil {
		deny(w, 400, "invalid_request")
		return
	}
	s.mu.Lock()
	pending, ok := s.flows[state]
	if !ok || !time.Now().Before(pending.expires) || pending.provider != "" || !same(cookie.Value, pending.binding) {
		s.mu.Unlock()
		deny(w, 400, "invalid_request")
		return
	}
	delete(s.flows, state)
	pending.provider = id
	pending.nonce = random()
	pending.verifier = oauth2.GenerateVerifier()
	state = random()
	s.flows[state] = pending
	s.mu.Unlock()
	if id == "local" {
		// Covee accounts sign in on the broker's own page, not upstream.
		s.renderLocalSignIn(w, 200, state, "")
		return
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(pending.nonce)}
	if id == "apple" {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
		s.cookie(w, pending.binding, pending.expires, http.SameSiteNoneMode, int(time.Until(pending.expires).Seconds()))
	} else {
		opts = append(opts, oauth2.S256ChallengeOption(pending.verifier), oauth2.SetAuthURLParam("response_mode", "query"))
	}
	// A top-level GET navigation is required for provider redirects under CSP.
	authorizationURL := u.oauth.AuthCodeURL(state, opts...)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	// Meta refresh performs navigation without scripts or a cross-origin form.
	redirectPage.Execute(w, pageData{Title: "Continue signing in", Host: s.host(), Provider: providerName(id), Target: authorizationURL})
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request, id string) {
	u, ok := s.providers[id]
	if !ok {
		deny(w, 404, "not_found")
		return
	}
	var form url.Values
	var err error
	if id == "apple" {
		if r.Method != "POST" || r.Header.Get("Origin") != AppleIssuer {
			deny(w, 400, "invalid_request")
			return
		}
		form, err = parseForm(w, r)
	} else {
		if r.Method != "GET" || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.origin()) {
			deny(w, 400, "invalid_request")
			return
		}
		form, err = url.ParseQuery(r.URL.RawQuery)
		if err == nil && !singletonValues(form) {
			err = errors.New("duplicate callback parameters")
		}
	}
	if err != nil || !textOK(single(form, "state"), 1, 256) || !textOK(single(form, "code"), 1, 8192) || form.Get("error") != "" {
		deny(w, 400, "authentication_failed")
		return
	}
	cookie, err := r.Cookie(flowCookie)
	if err != nil {
		deny(w, 400, "authentication_failed")
		return
	}
	s.mu.Lock()
	pending, ok := s.flows[single(form, "state")]
	if !ok || !time.Now().Before(pending.expires) || pending.provider != id || !same(cookie.Value, pending.binding) {
		s.mu.Unlock()
		deny(w, 400, "authentication_failed")
		return
	}
	delete(s.flows, single(form, "state"))
	s.mu.Unlock()
	s.cookie(w, "", time.Unix(1, 0), http.SameSiteNoneMode, -1)
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), s.client), 10*time.Second)
	defer cancel()
	oauth := u.oauth
	var opts []oauth2.AuthCodeOption
	if id == "apple" {
		secret, err := appleSecret(u, time.Now())
		if err != nil {
			deny(w, 400, "authentication_failed")
			return
		}
		oauth.ClientSecret = secret
	} else {
		opts = append(opts, oauth2.VerifierOption(pending.verifier))
	}
	token, err := oauth.Exchange(ctx, single(form, "code"), opts...)
	if err != nil {
		deny(w, 400, "authentication_failed")
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 64<<10 {
		deny(w, 400, "authentication_failed")
		return
	}
	verified, err := u.verifier.Verify(ctx, raw)
	now := time.Now()
	if err != nil || !textOK(verified.Subject, 1, 512) || !same(verified.Nonce, pending.nonce) || verified.IssuedAt.IsZero() || verified.IssuedAt.After(now.Add(time.Minute)) {
		deny(w, 400, "authentication_failed")
		return
	}
	var claims struct {
		Roles      []string                   `json:"roles"`
		Groups     []string                   `json:"groups"`
		AZP        string                     `json:"azp"`
		NBF        int64                      `json:"nbf"`
		HasGroups  json.RawMessage            `json:"hasgroups"`
		ClaimNames map[string]json.RawMessage `json:"_claim_names"`
	}
	if verified.Claims(&claims) != nil || claims.NBF > now.Unix() || (claims.AZP != "" && claims.AZP != u.config.ClientID) || (len(verified.Audience) > 1 && claims.AZP != u.config.ClientID) {
		deny(w, 400, "authentication_failed")
		return
	}
	role, enroll := "", false
	if id == "entra" {
		for _, r := range claims.Roles {
			if r == RoleAdmin {
				role = RoleAdmin
				break
			}
			if r == RoleReader {
				role = RoleReader
			}
		}
		for _, allowed := range u.config.AllowedGroupIDs {
			for _, group := range claims.Groups {
				if strings.EqualFold(group, allowed) {
					enroll = true
				}
			}
		}
		if len(claims.HasGroups) > 0 || len(claims.ClaimNames["groups"]) > 0 {
			enroll = false
		}
	} else if grant, ok := s.grants[id+"\x00"+verified.Subject]; ok {
		role, enroll = grant.Role, grant.Enroll
	}
	// Google permits both its legacy bare issuer and HTTPS issuer in signed
	// tokens. Use the configured, verified provider issuer as the namespace so
	// a subject remains stable across those equivalent forms.
	target, err := s.issue(pending, u.issuer, verified.Subject, role, enroll)
	s.finishHTML(w, r, target, err, providerName(id), verified.Subject)
}

func appleSecret(u *upstream, now time.Time) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: u.appleKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", u.config.KeyID))
	if err != nil {
		return "", err
	}
	claims := map[string]any{"iss": u.config.TeamID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "aud": AppleIssuer, "sub": u.config.ClientID}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(raw)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	form, err := parseForm(w, r)
	if err != nil {
		deny(w, 400, "invalid_request")
		return
	}
	id, secret := single(form, "client_id"), single(form, "client_secret")
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		if form.Has("client_id") || form.Has("client_secret") {
			deny(w, 400, "invalid_request")
			return
		}
		var err error
		id, err = url.QueryUnescape(basicID)
		if err != nil {
			deny(w, 401, "invalid_client")
			return
		}
		secret, err = url.QueryUnescape(basicSecret)
		if err != nil {
			deny(w, 401, "invalid_client")
			return
		}
	}
	client, ok := s.clients[id]
	if !ok || !same(secret, client.secret) {
		deny(w, 401, "invalid_client")
		return
	}
	if single(form, "grant_type") != "authorization_code" {
		deny(w, 400, "unsupported_grant_type")
		return
	}
	value := single(form, "code")
	s.mu.Lock()
	entry, ok := s.codes[value]
	if ok && entry.client == id {
		delete(s.codes, value)
	} else {
		ok = false
	}
	s.mu.Unlock()
	verifier := single(form, "code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if !ok || !time.Now().Before(entry.expires) || single(form, "redirect_uri") != entry.redirect || !validVerifier(verifier) || !same(base64URL(sum[:]), entry.challenge) {
		deny(w, 400, "invalid_grant")
		return
	}
	now := time.Now()
	expires := now.Add(lifetime)
	claims := map[string]any{"iss": s.config.Issuer, "aud": id, "sub": entry.claims.Subject, "iat": now.Unix(), "exp": expires.Unix(), "nonce": entry.nonce, "preferred_username": entry.claims.Username, "name": entry.claims.Name, "upstream_issuer": entry.claims.UpstreamIssuer, "upstream_sub": entry.claims.UpstreamSubject}
	if len(entry.claims.Roles) > 0 {
		claims["roles"] = entry.claims.Roles
	}
	if len(entry.claims.Groups) > 0 {
		claims["groups"] = entry.claims.Groups
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.kid))
	if err != nil {
		deny(w, 500, "server_error")
		return
	}
	raw, _ := json.Marshal(claims)
	signed, err := signer.Sign(raw)
	if err != nil {
		deny(w, 500, "server_error")
		return
	}
	idToken, err := signed.CompactSerialize()
	if err != nil {
		deny(w, 500, "server_error")
		return
	}
	accessToken := random()
	s.mu.Lock()
	s.clean(now)
	if len(s.access) >= 2048 {
		s.mu.Unlock()
		deny(w, 503, "temporarily_unavailable")
		return
	}
	s.access[accessToken] = access{claims: entry.claims, expires: expires}
	s.mu.Unlock()
	reply(w, 200, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": int(lifetime.Seconds()), "id_token": idToken, "scope": "openid profile"})
}
func validVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || len(header) > 256 || r.URL.RawQuery != "" {
		deny(w, 401, "invalid_token")
		return
	}
	s.mu.Lock()
	entry, ok := s.access[strings.TrimPrefix(header, "Bearer ")]
	if ok && !time.Now().Before(entry.expires) {
		delete(s.access, strings.TrimPrefix(header, "Bearer "))
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		deny(w, 401, "invalid_token")
		return
	}
	reply(w, 200, entry.claims)
}
