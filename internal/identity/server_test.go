package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

type fixture struct {
	t                *testing.T
	server           *Server
	broker, upstream *httptest.Server
	key              *rsa.PrivateKey
	apple            *ecdsa.PrivateKey
	mu               sync.Mutex
	tokens           map[string]string
	exchanges        []url.Values
	client           *http.Client
}

func writePrivate(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, tokens: map[string]string{}}
	var err error
	f.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.apple, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(f.upstreamHTTP))
	t.Cleanup(f.upstream.Close)
	var handler http.Handler
	f.broker = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler == nil {
			http.Error(w, "not ready", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(f.broker.Close)
	dir := t.TempDir()
	secret := writePrivate(t, dir, "secret", []byte(strings.Repeat("x", 48)))
	key := writePrivate(t, dir, "key", pkcs8(t, f.key))
	apple := writePrivate(t, dir, "apple", pkcs8(t, f.apple))
	cert := writePrivate(t, dir, "tls-cert", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.broker.TLS.Certificates[0].Certificate[0]}))
	tlsKey := writePrivate(t, dir, "tls-key", pkcs8(t, f.broker.TLS.Certificates[0].PrivateKey))
	c := Config{Issuer: f.broker.URL + "/identity", Listen: ":8446", TLSCertFile: cert, TLSKeyFile: tlsKey, SigningKeyFile: key, Clients: []ClientConfig{{ID: "console", SecretFile: secret, RedirectURI: "https://console.example.test/auth/oidc/callback", Kind: "console"}, {ID: "enrollment", SecretFile: secret, RedirectURI: "https://control.example.test/oidc/callback", Kind: "enrollment"}}, Providers: []ProviderConfig{{ID: "google", Kind: "google", ClientID: "google-client", ClientSecretFile: secret}, {ID: "apple", Kind: "apple", ClientID: "example.apple.service", TeamID: "TEAM123456", KeyID: "KEY1234567", PrivateKeyFile: apple}, {ID: "entra", Kind: "entra", Issuer: "https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.0", ClientID: "entra-client", ClientSecretFile: secret, AllowedGroupIDs: []string{"11234567-89ab-cdef-0123-456789abcdef"}}}, Grants: []Grant{{Provider: "google", Subject: "social-person", Role: RoleReader, Enroll: true}, {Provider: "apple", Subject: "apple-person", Role: RoleAdmin, Enroll: true}}}
	transport := f.upstream.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	target, _ := url.Parse(f.upstream.URL)
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = target.Hostname()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	upstreamClient := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f.server, err = New(oidc.ClientContext(context.Background(), upstreamClient), c)
	if err != nil {
		t.Fatal(err)
	}
	handler = f.server.Handler()
	t.Cleanup(f.server.Close)
	f.client = f.broker.Client()
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return f
}
func (f *fixture) upstreamHTTP(w http.ResponseWriter, r *http.Request) {
	issuer, id, auth, token, jwks := "", "", "", "", ""
	switch r.Host {
	case "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com":
		issuer, id, auth, token, jwks = GoogleIssuer, "google-client", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://www.googleapis.com/oauth2/v3/certs"
	case "appleid.apple.com":
		issuer, id, auth, token, jwks = AppleIssuer, "example.apple.service", AppleIssuer+"/auth/authorize", AppleIssuer+"/auth/token", AppleIssuer+"/auth/keys"
	case "login.microsoftonline.com":
		issuer = "https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.0"
		id = "entra-client"
		auth = issuer + "/authorize"
		token = issuer + "/token"
		jwks = issuer + "/keys"
	}
	_ = id
	if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
		reply(w, 200, map[string]any{"issuer": issuer, "authorization_endpoint": auth, "token_endpoint": token, "jwks_uri": jwks, "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}})
		return
	}
	if r.URL.Path == "/oauth2/v3/certs" || strings.HasSuffix(r.URL.Path, "/keys") {
		reply(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "upstream", Algorithm: "RS256", Use: "sig"}}})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/token") {
		r.ParseForm()
		f.mu.Lock()
		f.exchanges = append(f.exchanges, r.Form)
		raw, ok := f.tokens[r.Form.Get("code")]
		delete(f.tokens, r.Form.Get("code"))
		f.mu.Unlock()
		if !ok {
			deny(w, 400, "invalid_grant")
			return
		}
		reply(w, 200, map[string]any{"access_token": "upstream-access", "token_type": "Bearer", "expires_in": 300, "id_token": raw})
		return
	}
	http.NotFound(w, r)
}
func (f *fixture) request(method, path string, form url.Values, cookie *http.Cookie, origin string) *http.Response {
	f.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequest(method, f.broker.URL+path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	response, err := f.client.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	return response
}
func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type browserFlow struct {
	state, nonce, verifier string
	cookie                 *http.Cookie
	auth                   *url.URL
}

func (f *fixture) start(client, provider string) browserFlow {
	f.t.Helper()
	verifier := oauth2.GenerateVerifier()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {f.server.clients[client].config.RedirectURI}, "response_type": {"code"}, "scope": {"openid profile email"}, "nonce": {strings.Repeat("downstream-nonce", 2)}, "state": {strings.Repeat("downstream-state", 2)}, "code_challenge": {base64URL(sum[:])}, "code_challenge_method": {"S256"}}
	r := f.request("GET", "/identity/authorize?"+q.Encode(), nil, nil, "")
	body := readBody(f.t, r)
	if r.StatusCode != 200 {
		f.t.Fatalf("authorize %d: %s", r.StatusCode, body)
	}
	state := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(body)
	if len(state) != 2 {
		f.t.Fatalf("no flow state %s", body)
	}
	cookie := r.Cookies()[0]
	r = f.request("POST", "/identity/select", url.Values{"state": {state[1]}, "provider": {provider}}, cookie, f.broker.URL)
	body = readBody(f.t, r)
	if r.StatusCode != 200 {
		f.t.Fatalf("select %d %s", r.StatusCode, body)
	}
	for _, c := range r.Cookies() {
		if c.Name == flowCookie {
			cookie = c
		}
	}
	matches := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(body)
	if len(matches) != 2 {
		f.t.Fatalf("no auth link %s", body)
	}
	auth, err := url.Parse(html.UnescapeString(matches[1]))
	if err != nil {
		f.t.Fatal(err)
	}
	return browserFlow{state: auth.Query().Get("state"), nonce: auth.Query().Get("nonce"), verifier: verifier, cookie: cookie, auth: auth}
}
func (f *fixture) sign(provider, subject, nonce string, extra map[string]any) string {
	u := f.server.providers[provider]
	now := time.Now()
	claims := map[string]any{"iss": u.issuer, "sub": subject, "aud": u.config.ClientID, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": nonce}
	for k, v := range extra {
		claims[k] = v
	}
	b, _ := json.Marshal(claims)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "upstream"))
	if err != nil {
		f.t.Fatal(err)
	}
	signed, err := signer.Sign(b)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}
func (f *fixture) callback(flow browserFlow, provider, subject string, extra map[string]any) *http.Response {
	code := random()
	f.mu.Lock()
	f.tokens[code] = f.sign(provider, subject, flow.nonce, extra)
	f.mu.Unlock()
	form := url.Values{"state": {flow.state}, "code": {code}}
	if provider == "apple" {
		return f.request("POST", "/identity/callback/"+provider, form, flow.cookie, AppleIssuer)
	}
	return f.request("GET", "/identity/callback/"+provider+"?"+form.Encode(), nil, flow.cookie, "")
}
func (f *fixture) exchange(client, value, verifier string) *http.Response {
	return f.request("POST", "/identity/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "client_secret": {f.server.clients[client].secret}, "redirect_uri": {f.server.clients[client].config.RedirectURI}, "code": {value}, "code_verifier": {verifier}}, nil, "")
}
func issuedCode(t *testing.T, r *http.Response) string {
	t.Helper()
	body := readBody(t, r)
	if r.StatusCode != 303 {
		t.Fatalf("callback %d: %s", r.StatusCode, body)
	}
	u, err := url.Parse(r.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code")
}

func TestRealSignedProvidersAndDownstreamJWT(t *testing.T) {
	for _, provider := range []string{"google", "apple", "entra"} {
		t.Run(provider, func(t *testing.T) {
			f := newFixture(t)
			subject := "social-person"
			extra := map[string]any{"roles": []string{RoleAdmin}, "email": "Pat@Example.com", "email_verified": true, "name": "Pat Example"}
			email, name := "pat@example.com", "Pat Example"
			if provider == "apple" {
				// Apple sends no name in its token, and older tokens send the flag as a string.
				subject = "apple-person"
				extra = map[string]any{"roles": []string{RoleAdmin}, "email": "x1@privaterelay.appleid.com", "email_verified": "true"}
				email, name = "x1@privaterelay.appleid.com", "x1@privaterelay.appleid.com"
			}
			if provider == "entra" {
				// Entra's profile scope carries the sign-in name, not an email claim.
				subject = "entra-person"
				extra = map[string]any{"roles": []string{RoleAdmin}, "groups": []string{"11234567-89ab-cdef-0123-456789abcdef"}, "preferred_username": "Pat@Contoso.com", "name": "Pat Example"}
				email = "pat@contoso.com"
			}
			for _, client := range []string{"console", "enrollment"} {
				flow := f.start(client, provider)
				if provider == "apple" {
					if flow.auth.Query().Get("code_challenge") != "" || flow.auth.Query().Get("response_mode") != "form_post" || flow.cookie.SameSite != http.SameSiteNoneMode {
						t.Fatal("Apple flow properties")
					}
				} else if flow.auth.Query().Get("code_challenge_method") != "S256" {
					t.Fatal("missing upstream PKCE")
				}
				value := issuedCode(t, f.callback(flow, provider, subject, extra))
				r := f.exchange(client, value, flow.verifier)
				body := readBody(t, r)
				if r.StatusCode != 200 {
					t.Fatalf("exchange %d %s", r.StatusCode, body)
				}
				var result struct {
					ID     string `json:"id_token"`
					Access string `json:"access_token"`
				}
				if err := json.Unmarshal([]byte(body), &result); err != nil {
					t.Fatal(err)
				}
				ctx := oidc.ClientContext(context.Background(), f.client)
				discovery, err := oidc.NewProvider(ctx, f.server.config.Issuer)
				if err != nil {
					t.Fatal(err)
				}
				id, err := discovery.VerifierContext(ctx, &oidc.Config{ClientID: client, SupportedSigningAlgs: []string{"RS256"}}).Verify(ctx, result.ID)
				if err != nil {
					t.Fatal(err)
				}
				if id.Nonce != strings.Repeat("downstream-nonce", 2) || len(id.Subject) != 64 {
					t.Fatal("invalid broker identity")
				}
				var claims identityClaims
				if id.Claims(&claims) != nil {
					t.Fatal("invalid claims")
				}
				if claims.UpstreamIssuer != f.server.providers[provider].issuer || claims.UpstreamSubject != subject || claims.Username != "u"+id.Subject {
					t.Fatal("lost upstream binding")
				}
				if claims.Email != email || !claims.EmailVerified || claims.Name != name {
					t.Fatalf("profile = %q %v %q", claims.Email, claims.EmailVerified, claims.Name)
				}
				if client == "console" {
					if len(claims.Groups) != 0 || len(claims.Roles) != 1 {
						t.Fatal("console claims crossed audience")
					}
					if provider == "google" && claims.Roles[0] != RoleReader {
						t.Fatal("social provider role escalation")
					}
				} else if len(claims.Roles) != 0 || len(claims.Groups) != 1 || claims.Groups[0] != "covee.enroll" {
					t.Fatal("enrollment claims crossed audience")
				}
				req, _ := http.NewRequest("GET", f.broker.URL+"/identity/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+result.Access)
				response, err := f.client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				userinfo := readBody(t, response)
				if response.StatusCode != 200 || !strings.Contains(userinfo, id.Subject) || !strings.Contains(userinfo, `"email":"`+email+`","email_verified":true`) {
					t.Fatalf("userinfo %d %s", response.StatusCode, userinfo)
				}
				response = f.exchange(client, value, flow.verifier)
				if response.StatusCode != 400 {
					t.Fatal("replayed downstream code")
				}
				response.Body.Close()
			}
			if provider == "apple" {
				f.mu.Lock()
				exchanges := append([]url.Values{}, f.exchanges...)
				f.mu.Unlock()
				for _, e := range exchanges {
					if e.Get("code_verifier") != "" {
						t.Fatal("Apple erroneously sent PKCE")
					}
					jws, err := jose.ParseSigned(e.Get("client_secret"), []jose.SignatureAlgorithm{jose.ES256})
					if err != nil {
						t.Fatal(err)
					}
					payload, err := jws.Verify(&f.apple.PublicKey)
					if err != nil {
						t.Fatal(err)
					}
					var claims map[string]any
					json.Unmarshal(payload, &claims)
					if claims["iss"] != "TEAM123456" || claims["sub"] != "example.apple.service" || claims["aud"] != AppleIssuer || claims["exp"].(float64)-claims["iat"].(float64) != 300 {
						t.Fatal("invalid Apple client secret")
					}
				}
			}
		})
	}
}

func TestTheProfileOnlyLabelsThePerson(t *testing.T) {
	f := newFixture(t)
	group := []string{"11234567-89ab-cdef-0123-456789abcdef"}
	signIn := func(provider, subject string, extra map[string]any) (string, identityClaims) {
		t.Helper()
		flow := f.start("enrollment", provider)
		r := f.exchange("enrollment", issuedCode(t, f.callback(flow, provider, subject, extra)), flow.verifier)
		body := readBody(t, r)
		var result struct {
			ID string `json:"id_token"`
		}
		if r.StatusCode != 200 || json.Unmarshal([]byte(body), &result) != nil {
			t.Fatalf("exchange %d %s", r.StatusCode, body)
		}
		ctx := oidc.ClientContext(context.Background(), f.client)
		discovery, err := oidc.NewProvider(ctx, f.server.config.Issuer)
		if err != nil {
			t.Fatal(err)
		}
		id, err := discovery.VerifierContext(ctx, &oidc.Config{ClientID: "enrollment", SupportedSigningAlgs: []string{"RS256"}}).Verify(ctx, result.ID)
		if err != nil {
			t.Fatal(err)
		}
		var claims identityClaims
		var raw map[string]any
		if id.Claims(&claims) != nil || id.Claims(&raw) != nil {
			t.Fatal("invalid claims")
		}
		if _, ok := raw["email_verified"]; ok != (claims.Email != "") {
			t.Fatalf("email_verified must come with an address and only then: %v", raw)
		}
		return id.Subject, claims
	}
	for _, c := range []struct {
		name, provider, subject string
		extra                   map[string]any
		email, display          string
	}{
		{"an unverified Google address is left out", "google", "social-person", map[string]any{"email": "pat@example.com", "email_verified": false, "name": "Pat Example"}, "", "Pat Example"},
		{"a Google address without the flag is left out", "google", "social-person", map[string]any{"email": "pat@example.com"}, "", "Covee user"},
		{"Apple's flag must say true", "apple", "apple-person", map[string]any{"email": "x1@privaterelay.appleid.com", "email_verified": "false"}, "", "Covee user"},
		{"an Entra guest's email comes before its sign-in name", "entra", "guest", map[string]any{"groups": group, "email": "Guest@Fabrikam.com", "preferred_username": "guest_fabrikam.com#EXT#@contoso.onmicrosoft.com"}, "guest@fabrikam.com", "guest@fabrikam.com"},
		{"a display-form address is not an address", "entra", "member", map[string]any{"groups": group, "email": "Pat <pat@contoso.com>", "preferred_username": "pat@contoso.com"}, "pat@contoso.com", "pat@contoso.com"},
		{"a phone sign-in name is not an address", "entra", "phone", map[string]any{"groups": group, "preferred_username": "+15551234567"}, "", "Covee user"},
		{"a name with control characters is left out", "entra", "member", map[string]any{"groups": group, "preferred_username": "pat@contoso.com", "name": "Pat\u0007Example"}, "pat@contoso.com", "pat@contoso.com"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, claims := signIn(c.provider, c.subject, c.extra)
			if claims.Email != c.email || claims.EmailVerified != (c.email != "") || claims.Name != c.display {
				t.Fatalf("profile = %q %v %q", claims.Email, claims.EmailVerified, claims.Name)
			}
		})
	}
	// One address on two accounts stays two people: the address never links them.
	first, a := signIn("entra", "one", map[string]any{"groups": group, "preferred_username": "pat@contoso.com"})
	second, b := signIn("entra", "two", map[string]any{"groups": group, "preferred_username": "pat@contoso.com"})
	if first == second || a.Username == b.Username || a.Email != b.Email {
		t.Fatalf("an address linked two accounts: %s %s", first, second)
	}
}

func TestAuthenticationAndAuthorizationFailClosed(t *testing.T) {
	cases := []struct {
		name, provider, client, subject string
		extra                           map[string]any
		status                          int
	}{
		{"unknown social subject", "google", "console", "unapproved", map[string]any{"roles": []string{RoleAdmin}}, 403},
		{"unknown enrollment", "google", "enrollment", "unapproved", nil, 403},
		{"Apple social role ignored", "apple", "console", "unapproved", map[string]any{"roles": []string{RoleAdmin}}, 403},
		{"Entra group no role", "entra", "console", "entra-person", map[string]any{"groups": []string{"11234567-89ab-cdef-0123-456789abcdef"}}, 403},
		{"Entra role no group", "entra", "enrollment", "entra-person", map[string]any{"roles": []string{RoleAdmin}}, 403},
		{"Entra overage", "entra", "enrollment", "entra-person", map[string]any{"hasgroups": true}, 403},
		{"Entra ambiguous overage", "entra", "enrollment", "entra-person", map[string]any{"hasgroups": true, "groups": []string{"11234567-89ab-cdef-0123-456789abcdef"}}, 403},
		{"Entra malformed distributedclaims", "entra", "enrollment", "entra-person", map[string]any{"_claim_names": map[string]string{"groups": "src1"}}, 400},
		{"wrong nonce", "google", "console", "social-person", map[string]any{"nonce": "wrong"}, 400},
		{"wrong audience", "google", "console", "social-person", map[string]any{"aud": "other"}, 400},
		{"wrong issuer", "google", "console", "social-person", map[string]any{"iss": AppleIssuer}, 400},
		{"future issued", "google", "console", "social-person", map[string]any{"iat": time.Now().Add(time.Hour).Unix()}, 400},
		{"future notbefore", "google", "console", "social-person", map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}, 400},
		{"expired token", "google", "console", "social-person", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}, 400},
		{"wrong azp", "google", "console", "social-person", map[string]any{"azp": "other"}, 400},
		{"multi aud no azp", "google", "console", "social-person", map[string]any{"aud": []string{"google-client", "other"}}, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			flow := f.start(tc.client, tc.provider)
			r := f.callback(flow, tc.provider, tc.subject, tc.extra)
			body := readBody(t, r)
			if r.StatusCode != tc.status {
				t.Fatalf("got %d want %d: %s", r.StatusCode, tc.status, body)
			}
			r = f.callback(flow, tc.provider, tc.subject, tc.extra)
			if r.StatusCode != 400 {
				t.Fatal("upstream flow replay")
			}
			r.Body.Close()
		})
	}
}

func TestPKCEClientAndRedirectBinding(t *testing.T) {
	for _, kind := range []string{"pkce", "client", "redirect", "secret", "duplicate", "basic"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			flow := f.start("console", "google")
			value := issuedCode(t, f.callback(flow, "google", "social-person", nil))
			form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"console"}, "client_secret": {f.server.clients["console"].secret}, "redirect_uri": {f.server.clients["console"].config.RedirectURI}, "code": {value}, "code_verifier": {flow.verifier}}
			switch kind {
			case "pkce":
				form.Set("code_verifier", strings.Repeat("a", 43))
			case "client":
				form.Set("client_id", "enrollment")
			case "redirect":
				form.Set("redirect_uri", "https://attacker.example/callback")
			case "secret":
				form.Set("client_secret", "bad")
			case "duplicate":
				form.Add("code", value)
			case "basic":
				delete(form, "client_id")
				delete(form, "client_secret")
			}
			if kind == "basic" {
				request, _ := http.NewRequest("POST", f.broker.URL+"/identity/token", strings.NewReader(form.Encode()))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.SetBasicAuth("console", f.server.clients["console"].secret)
				response, err := f.client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body := readBody(t, response)
				if response.StatusCode != 200 {
					t.Fatalf("basic failed %d %s", response.StatusCode, body)
				}
				return
			}
			r := f.request("POST", "/identity/token", form, nil, "")
			body := readBody(t, r)
			if r.StatusCode == 200 {
				t.Fatalf("accepted %s %s", kind, body)
			}
		})
	}
}

func TestChooserLetsBrowsersSendTheirOwnOrigin(t *testing.T) {
	f := newFixture(t)
	sum := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
	q := url.Values{"client_id": {"console"}, "redirect_uri": {f.server.clients["console"].config.RedirectURI}, "response_type": {"code"}, "scope": {"openid profile email"}, "nonce": {strings.Repeat("downstream-nonce", 2)}, "state": {strings.Repeat("downstream-state", 2)}, "code_challenge": {base64URL(sum[:])}, "code_challenge_method": {"S256"}}
	r := f.request("GET", "/identity/authorize?"+q.Encode(), nil, nil, "")
	body := readBody(t, r)
	// A form posted from a no-referrer page reaches us as "Origin: null" (Fetch standard),
	// which selectProvider rightly refuses. Chrome did exactly that in the first live sign-in.
	if got := r.Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("chooser Referrer-Policy %q", got)
	}
	state := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(body)
	if len(state) != 2 {
		t.Fatalf("no flow state %s", body)
	}
	cookie := r.Cookies()[0]
	form := url.Values{"state": {state[1]}, "provider": {"google"}}
	r = f.request("POST", "/identity/select", form, cookie, "null")
	if body := readBody(t, r); r.StatusCode != 403 || !strings.Contains(body, "origin_rejected") {
		t.Fatalf("null origin %d %s", r.StatusCode, body)
	}
	r = f.request("POST", "/identity/select", form, cookie, f.broker.URL)
	if body := readBody(t, r); r.StatusCode != 200 {
		t.Fatalf("own origin %d %s", r.StatusCode, body)
	}
}

func TestFlowBrowserProviderAndOriginBinding(t *testing.T) {
	f := newFixture(t)
	flow := f.start("console", "google")
	for _, attempt := range []struct {
		name, path string
		cookie     *http.Cookie
		origin     string
		method     string
	}{{"provider", "/identity/callback/entra", flow.cookie, "", "GET"}, {"cookie", "/identity/callback/google", &http.Cookie{Name: flowCookie, Value: "wrong"}, "", "GET"}, {"origin", "/identity/callback/google", flow.cookie, "https://attacker.example", "GET"}, {"post", "/identity/callback/google", flow.cookie, "", "POST"}} {
		t.Run(attempt.name, func(t *testing.T) {
			params := url.Values{"state": {flow.state}, "code": {"bad"}}
			path := attempt.path
			var form url.Values
			if attempt.method == "GET" {
				path += "?" + params.Encode()
			} else {
				form = params
			}
			r := f.request(attempt.method, path, form, attempt.cookie, attempt.origin)
			if r.StatusCode != 400 {
				t.Fatal(r.StatusCode)
			}
			r.Body.Close()
		})
	}
	issuedCode(t, f.callback(flow, "google", "social-person", nil))
	flow = f.start("console", "apple")
	r := f.request("POST", "/identity/callback/apple", url.Values{"state": {flow.state}, "code": {"bad"}}, flow.cookie, "https://attacker.example")
	if r.StatusCode != 400 {
		t.Fatal("Apple origin accepted")
	}
	r.Body.Close()
	issuedCode(t, f.callback(flow, "apple", "apple-person", nil))
}

func TestExpiredFlowCodeAccessAndCapacity(t *testing.T) {
	f := newFixture(t)
	flow := f.start("console", "google")
	f.server.mu.Lock()
	pending := f.server.flows[flow.state]
	pending.expires = time.Now().Add(-time.Second)
	f.server.flows[flow.state] = pending
	f.server.mu.Unlock()
	r := f.callback(flow, "google", "social-person", nil)
	if r.StatusCode != 400 {
		t.Fatal("expired flow")
	}
	r.Body.Close()
	flow = f.start("console", "google")
	value := issuedCode(t, f.callback(flow, "google", "social-person", nil))
	f.server.mu.Lock()
	entry := f.server.codes[value]
	entry.expires = time.Now().Add(-time.Second)
	f.server.codes[value] = entry
	f.server.mu.Unlock()
	r = f.exchange("console", value, flow.verifier)
	if r.StatusCode != 400 {
		t.Fatal("expired code")
	}
	r.Body.Close()
	f.server.mu.Lock()
	f.server.access["expired"] = access{expires: time.Now().Add(-time.Second)}
	for i := 0; i < 1024; i++ {
		f.server.flows[fmt.Sprint(i)] = flowWithExpiry(time.Now().Add(time.Minute))
	}
	f.server.mu.Unlock()
	q := url.Values{"client_id": {"console"}, "redirect_uri": {f.server.clients["console"].config.RedirectURI}, "response_type": {"code"}, "scope": {"openid"}, "nonce": {strings.Repeat("n", 20)}, "state": {strings.Repeat("s", 20)}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}}
	sum := sha256.Sum256([]byte("v"))
	q.Set("code_challenge", base64URL(sum[:]))
	r = f.request("GET", "/identity/authorize?"+q.Encode(), nil, nil, "")
	if r.StatusCode != 503 {
		t.Fatal("flow capacity", r.StatusCode)
	}
	r.Body.Close()
	req, _ := http.NewRequest("GET", f.broker.URL+"/identity/userinfo", nil)
	req.Header.Set("Authorization", "Bearer expired")
	r, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 401 {
		t.Fatal("expired access")
	}
	r.Body.Close()
}
func flowWithExpiry(expires time.Time) flow { return flow{expires: expires} }

func TestAuthorizationInputRejection(t *testing.T) {
	f := newFixture(t)
	sum := sha256.Sum256([]byte("v"))
	base := url.Values{"client_id": {"console"}, "redirect_uri": {f.server.clients["console"].config.RedirectURI}, "response_type": {"code"}, "scope": {"openid"}, "nonce": {strings.Repeat("n", 20)}, "state": {strings.Repeat("s", 20)}, "code_challenge": {base64URL(sum[:])}, "code_challenge_method": {"S256"}}
	for _, tc := range []struct{ key, value string }{{"client_id", "other"}, {"redirect_uri", "https://attacker.example"}, {"response_type", "token"}, {"scope", "profile"}, {"scope", "openid admin"}, {"nonce", ""}, {"state", ""}, {"code_challenge_method", "plain"}, {"code_challenge", "bad"}, {"response_mode", "fragment"}} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			q := url.Values{}
			for k, v := range base {
				q[k] = append([]string{}, v...)
			}
			q.Set(tc.key, tc.value)
			r := f.request("GET", "/identity/authorize?"+q.Encode(), nil, nil, "")
			body := readBody(t, r)
			if r.StatusCode != 400 || r.Header.Get("Location") != "" {
				t.Fatalf("accepted input %d %s", r.StatusCode, body)
			}
		})
	}
	request, _ := http.NewRequest("GET", f.broker.URL+"/identity/healthz", nil)
	request.Host = "attacker.example"
	r, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 400 {
		t.Fatal("host confusion")
	}
	r.Body.Close()
	r = f.request("POST", "/identity/select", url.Values{"state": {"bad"}, "provider": {"google"}}, nil, "https://attacker.example")
	if r.StatusCode != 403 {
		t.Fatal("select origin")
	}
	r.Body.Close()
	r = f.request("GET", "/identity/userinfo?access_token=secret", nil, nil, "")
	if r.StatusCode != 401 {
		t.Fatal("query bearer accepted")
	}
	r.Body.Close()
}

func TestDeniedSubjectEscapedAndNoAutoLink(t *testing.T) {
	f := newFixture(t)
	flow := f.start("console", "google")
	r := f.callback(flow, "google", "<script>alert(1)</script>", map[string]any{"email": "admin@example.com", "email_verified": true, "roles": []string{RoleAdmin}})
	body := readBody(t, r)
	if r.StatusCode != 403 || strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") || strings.Contains(body, "admin@example.com") {
		t.Fatalf("unsafe denied identity %d %s", r.StatusCode, body)
	}
}

// All test outbound provider traffic is TLS, certificate verified, and local.
// The dial remapping above is trusted test injection; no real provider is used.
var _ = tls.VersionTLS12

func TestBrowsersGetAPageAndProgramsGetJSONWhenSignInStops(t *testing.T) {
	f := newFixture(t)
	get := func(path, accept string) (*http.Response, string) {
		r, _ := http.NewRequest("GET", f.broker.URL+path, nil)
		r.Host = strings.TrimPrefix(f.server.config.Issuer[:strings.Index(f.server.config.Issuer, "/identity")], "https://")
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp, readBody(t, resp)
	}
	resp, body := get("/identity/authorize?client_id=nobody", "text/html,application/xhtml+xml,*/*;q=0.8")
	if resp.StatusCode != 400 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || !strings.Contains(body, "This sign-in has expired") || strings.Contains(body, "invalid_request") {
		t.Fatalf("browser error page %d %q %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("the error page lost the strict content policy")
	}
	resp, body = get("/identity/authorize?client_id=nobody", "")
	if resp.StatusCode != 400 || !strings.Contains(body, `"error":"invalid_request"`) {
		t.Fatalf("program error %d %s", resp.StatusCode, body)
	}
	// Token and other API endpoints stay JSON even for browsers.
	resp, body = get("/identity/userinfo", "text/html")
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("API answered with a page: %s", body)
	}
}

func TestConsoleClientMayReturnToItsOtherOriginsOnly(t *testing.T) {
	f := newFixture(t)
	console := f.server.clients["console"]
	console.config.ExtraRedirectURIs = []string{"https://console.mesh.example.test/auth/oidc/callback"}
	f.server.clients["console"] = console
	sum := sha256.Sum256([]byte("v"))
	ask := func(client, redirect string) *http.Response {
		q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}, "nonce": {strings.Repeat("n", 20)}, "state": {strings.Repeat("s", 20)}, "code_challenge": {base64URL(sum[:])}, "code_challenge_method": {"S256"}}
		return f.request("GET", "/identity/authorize?"+q.Encode(), nil, nil, "")
	}
	if r := ask("console", "https://console.mesh.example.test/auth/oidc/callback"); r.StatusCode != 200 {
		t.Fatalf("extra console redirect refused: %d", r.StatusCode)
	}
	f.server.mu.Lock()
	var stored []string
	for _, pending := range f.server.flows {
		stored = append(stored, pending.authorization.redirect)
	}
	f.server.mu.Unlock()
	if len(stored) != 1 || stored[0] != "https://console.mesh.example.test/auth/oidc/callback" {
		t.Fatalf("the flow does not remember the chosen redirect: %v", stored)
	}
	for _, tc := range []struct{ client, redirect string }{
		{"console", "https://console.mesh.example.test/auth/oidc/callback/"},
		{"console", "https://evil.example/auth/oidc/callback"},
		{"enrollment", "https://console.mesh.example.test/auth/oidc/callback"},
	} {
		if r := ask(tc.client, tc.redirect); r.StatusCode != 400 {
			t.Fatalf("%s accepted %s", tc.client, tc.redirect)
		}
	}
	base := ClientConfig{ID: "c", SecretFile: "/s", RedirectURI: "https://a.example/cb", Kind: "enrollment", ExtraRedirectURIs: []string{"https://b.example/cb"}}
	c := Config{Issuer: "https://a.example/identity", Listen: ":1", TLSCertFile: "/c", TLSKeyFile: "/k", SigningKeyFile: "/s", Clients: []ClientConfig{base}, Providers: []ProviderConfig{{ID: "google", Kind: "google", ClientID: "x", ClientSecretFile: "/x"}}}
	valid := c
	valid.Clients = []ClientConfig{{ID: "c", SecretFile: "/s", RedirectURI: "https://a.example/cb", Kind: "console", ExtraRedirectURIs: []string{"https://b.example/cb"}}}
	if err := valid.validate(); err != nil {
		t.Fatalf("a console client with one extra redirect was refused: %v", err)
	}
	if err := c.validate(); err == nil {
		t.Fatal("an enrollment client was allowed extra redirects")
	}
	for _, extras := range [][]string{{"https://a.example/cb"}, {"http://b.example/cb"}, {"https://b.example/cb", "https://b.example/cb"}, {"https://b/1", "https://b/2", "https://b/3"}} {
		base.Kind, base.ExtraRedirectURIs = "console", extras
		c.Clients = []ClientConfig{base}
		if err := c.validate(); err == nil {
			t.Fatalf("extra redirects %v accepted", extras)
		}
	}
}
