package management

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const oidcTestClientID = "console-client"
const oidcTestSecret = "oidc-secret-must-never-be-logged"

type testAuthorization struct{ nonce, challenge, redirect string }

// This provider uses real HTTPS discovery/JWKS/token endpoints and RSA-signed
// JWTs. The client must exchange a one-use code with the matching PKCE verifier.
type testOIDCProvider struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	mu             sync.Mutex
	codes          map[string]testAuthorization
	claims         func(map[string]any)
	signingKey     *rsa.PrivateKey
	endpointScheme string
	exchanges      atomic.Int32
	// extraRedirects are accepted besides the console's public callback.
	extraRedirects []string
}

func (p *testOIDCProvider) allowsRedirect(uri string) bool {
	if uri == "https://console.example.test/auth/oidc/callback" {
		return true
	}
	for _, extra := range p.extraRedirects {
		if uri == extra {
			return true
		}
	}
	return false
}

func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testOIDCProvider{key: key, codes: map[string]testAuthorization{}, endpointScheme: "https"}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.server.Close)
	return p
}

func (p *testOIDCProvider) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		base := p.server.URL
		if p.endpointScheme == "http" {
			base = strings.Replace(base, "https://", "http://", 1)
		}
		respond(w, 200, map[string]any{"issuer": p.server.URL, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "jwks_uri": base + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != oidcTestClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || !p.allowsRedirect(q.Get("redirect_uri")) || q.Get("response_mode") != "query" {
			http.Error(w, "bad authorization request", 400)
			return
		}
		code := randomToken()
		p.mu.Lock()
		p.codes[code] = testAuthorization{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")}
		p.mu.Unlock()
		u, _ := url.Parse(q.Get("redirect_uri"))
		query := url.Values{"code": {code}, "state": {q.Get("state")}}
		u.RawQuery = query.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	case "/token":
		p.exchanges.Add(1)
		if r.Method != "POST" || r.ParseForm() != nil {
			http.Error(w, "bad token request", 400)
			return
		}
		p.mu.Lock()
		auth, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		p.mu.Unlock()
		challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != oidcTestClientID || r.Form.Get("client_secret") != oidcTestSecret || r.Form.Get("redirect_uri") != auth.redirect || base64.RawURLEncoding.EncodeToString(challenge[:]) != auth.challenge {
			http.Error(w, "bad token request", 400)
			return
		}
		now := time.Now()
		claims := map[string]any{"iss": p.server.URL, "aud": oidcTestClientID, "sub": "user-subject-123", "iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(30 * time.Minute).Unix(), "nonce": auth.nonce, "name": "Alice Example", "roles": []string{roleAdmin}}
		if p.claims != nil {
			p.claims(claims)
		}
		key := p.key
		if p.signingKey != nil {
			key = p.signingKey
		}
		jwt, err := signTestJWT(key, claims)
		if err != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		respond(w, 200, map[string]any{"access_token": "unused-access-token", "token_type": "Bearer", "expires_in": 1800, "id_token": jwt})
	case "/jwks":
		respond(w, 200, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture-key", "n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())}}})
	default:
		http.NotFound(w, r)
	}
}

func signTestJWT(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture-key","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	data := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(data))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return data + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func newOIDCTestServer(t *testing.T, p *testOIDCProvider, handler http.HandlerFunc) *Server {
	t.Helper()
	up := httptest.NewServer(handler)
	t.Cleanup(up.Close)
	client := p.server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s, err := newServer(Config{Listen: "127.0.0.1:8088", PublicURL: "https://console.example.test", AuthMode: "oidc", OIDCIssuer: p.server.URL, OIDCClientID: oidcTestClientID, OIDCClientSecret: oidcTestSecret, HeadscaleURL: up.URL, HeadscaleAPIKey: testAPIKey, DataDir: t.TempDir()}, client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func oidcRequest(s *Server, method, path string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, s.config.PublicURL+path, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func beginOIDC(t *testing.T, s *Server, p *testOIDCProvider) (string, *http.Cookie) {
	t.Helper()
	w := oidcRequest(s, "POST", "/auth/oidc/login", nil, map[string]string{"Origin": s.config.PublicURL})
	assertStatus(t, w, 200)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatal("unsafe OIDC browser binding cookie")
	}
	var start struct {
		AuthorizationURL string `json:"authorizationUrl"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &start); err != nil {
		t.Fatal(err)
	}
	response, err := s.oidc.client.Get(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatal("provider rejected authorization request")
	}
	u, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.RequestURI(), cookies[0]
}

func finishOIDC(t *testing.T, s *Server, p *testOIDCProvider) (*http.Cookie, map[string]any) {
	t.Helper()
	callback, binding := beginOIDC(t, s, p)
	w := oidcRequest(s, "GET", callback, binding, nil)
	assertStatus(t, w, 303)
	if w.Header().Get("Location") != "/" {
		t.Fatal("OIDC redirected outside fixed console root")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cookieName() {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("missing secure session cookie")
	}
	w = request(s, "GET", "/api/session", "", nil, cookie)
	assertStatus(t, w, 200)
	var info map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	return cookie, info
}

func TestOIDCAdminFlowAuthorizationAndDurableActorAudit(t *testing.T) {
	p := newTestOIDCProvider(t)
	var calls atomic.Int32
	s := newOIDCTestServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testAPIKey {
			t.Error("Headscale credential missing")
		}
		io.WriteString(w, `{"user":{"id":"1","name":"alice"}}`)
	})
	assertStatus(t, request(s, "POST", "/api/login", `{"token":"`+testToken+`"}`, map[string]string{"Origin": s.config.PublicURL}, nil), 404)
	assertStatus(t, request(s, "GET", "/api/session", "", bearer(), nil), 401)
	cookie, info := finishOIDC(t, s, p)
	if info["permissions"].(map[string]any)["canWrite"] != true {
		t.Fatal("admin role not granted")
	}
	csrf := info["csrfToken"].(string)
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"alice"}`, map[string]string{"X-CSRF-Token": csrf}, cookie), 403)
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"alice"}`, map[string]string{"Origin": "https://evil.example", "X-CSRF-Token": csrf}, cookie), 403)
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"alice"}`, map[string]string{"Origin": s.config.PublicURL, "X-CSRF-Token": csrf}, cookie), 201)
	if calls.Load() != 1 {
		t.Fatal("blocked request reached Headscale")
	}
	data, err := os.ReadFile(filepath.Join(s.config.DataDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), oidcTestSecret) || strings.Contains(string(data), "unused-access-token") || strings.Contains(string(data), testAPIKey) {
		t.Fatal("audit contains a credential")
	}
	replay, err := openAudit(s.config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.close()
	if events := replay.latest(); len(events) != 2 || events[0].Actor != (Actor{Type: "oidc", Issuer: p.server.URL, Subject: "user-subject-123", Name: "Alice Example", Role: roleAdmin}) || events[0].Actor != events[1].Actor || events[0].Outcome != "success" || events[1].Outcome != "intent" {
		t.Fatal("durable audit did not attribute intent/result to the signed identity")
	}
	assertStatus(t, request(s, "GET", "/api/session", "", bearer(), cookie), 401)
	assertStatus(t, request(s, "POST", "/api/logout", `{}`, map[string]string{"Origin": s.config.PublicURL, "X-CSRF-Token": csrf}, cookie), 200)
	assertStatus(t, request(s, "GET", "/api/session", "", nil, cookie), 401)
}

func TestOIDCReaderCannotMutateAnyResource(t *testing.T) {
	p := newTestOIDCProvider(t)
	p.claims = func(c map[string]any) { c["roles"] = []string{roleReader}; c["sub"] = "reader-subject" }
	var calls atomic.Int32
	s := newOIDCTestServer(t, p, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, `{"users":[]}`) })
	cookie, info := finishOIDC(t, s, p)
	if info["permissions"].(map[string]any)["canWrite"] != false {
		t.Fatal("reader granted write permission")
	}
	assertStatus(t, request(s, "GET", "/api/users", "", nil, cookie), 200)
	assertStatus(t, request(s, "GET", "/api/audit", "", nil, cookie), 200)
	headers := map[string]string{"Origin": s.config.PublicURL, "X-CSRF-Token": info["csrfToken"].(string)}
	for _, op := range []struct{ method, path string }{{"POST", "/api/users"}, {"DELETE", "/api/users/1"}, {"PATCH", "/api/devices/1"}, {"DELETE", "/api/devices/1"}, {"POST", "/api/devices/1/expire"}, {"POST", "/api/keys"}, {"POST", "/api/keys/1/expire"}, {"PUT", "/api/policy"}, {"POST", "/api/devices/1/routes"}, {"PUT", "/api/gateway"}} {
		assertStatus(t, request(s, op.method, op.path, `{}`, headers, cookie), 403)
	}
	if calls.Load() != 1 || len(s.audit.latest()) != 0 {
		t.Fatal("reader mutation reached Headscale or was journaled as an operation")
	}
	assertStatus(t, request(s, "POST", "/api/logout", `{}`, headers, cookie), 200)
}

func TestOIDCRejectsInvalidSignedClaimsAndSignature(t *testing.T) {
	for _, kind := range []string{"nonce", "issuer", "audience", "signature", "expired", "future-nbf", "future-iat", "missing-iat", "missing-subject", "missing-role", "groups-only", "wrong-role", "malformed-roles", "wrong-azp", "multiple-aud-no-azp"} {
		t.Run(kind, func(t *testing.T) {
			p := newTestOIDCProvider(t)
			p.claims = func(c map[string]any) {
				switch kind {
				case "nonce":
					c["nonce"] = "wrong-nonce"
				case "issuer":
					c["iss"] = "https://attacker.example"
				case "audience":
					c["aud"] = "different-client"
				case "expired":
					c["exp"] = time.Now().Add(-time.Minute).Unix()
				case "future-nbf":
					c["nbf"] = time.Now().Add(time.Hour).Unix()
				case "future-iat":
					c["iat"] = time.Now().Add(time.Hour).Unix()
				case "missing-iat":
					delete(c, "iat")
				case "missing-subject":
					delete(c, "sub")
				case "missing-role":
					delete(c, "roles")
				case "groups-only":
					delete(c, "roles")
					c["groups"] = []string{roleAdmin}
				case "wrong-role":
					c["roles"] = []string{"covee.admin", "Admin"}
				case "malformed-roles":
					c["roles"] = roleAdmin
				case "wrong-azp":
					c["azp"] = "different-client"
				case "multiple-aud-no-azp":
					c["aud"] = []string{oidcTestClientID, "another-client"}
				}
			}
			if kind == "signature" {
				var err error
				p.signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
			}
			s := newOIDCTestServer(t, p, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected Headscale request") })
			callback, binding := beginOIDC(t, s, p)
			w := oidcRequest(s, "GET", callback, binding, nil)
			want := 400
			if kind == "missing-role" || kind == "groups-only" || kind == "wrong-role" {
				want = 403
			}
			assertStatus(t, w, want)
			if len(s.sessions) != 0 || strings.Contains(w.Body.String(), oidcTestSecret) || strings.Contains(w.Body.String(), "wrong-nonce") {
				t.Fatal("failed login created a session or exposed token detail")
			}
			assertStatus(t, oidcRequest(s, "GET", callback, binding, nil), 400)
			if p.exchanges.Load() != 1 {
				t.Fatal("failed login replay exchanged a code again")
			}
		})
	}
}

func TestOIDCStateBrowserBindingExpiryReplayAndHost(t *testing.T) {
	for _, kind := range []string{"missing-cookie", "wrong-cookie", "wrong-state", "expired", "replay", "wrong-host", "duplicate-state", "duplicate-code", "provider-error", "code-exchange-error"} {
		t.Run(kind, func(t *testing.T) {
			p := newTestOIDCProvider(t)
			s := newOIDCTestServer(t, p, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected Headscale request") })
			callback, binding := beginOIDC(t, s, p)
			u, _ := url.Parse(callback)
			q := u.Query()
			switch kind {
			case "missing-cookie":
				binding = nil
			case "wrong-cookie":
				binding = &http.Cookie{Name: binding.Name, Value: "wrong-browser"}
			case "wrong-state":
				q.Set("state", "wrong-state")
			case "expired":
				s.oidc.mu.Lock()
				f := s.oidc.flows[q.Get("state")]
				f.expires = time.Now().Add(-time.Second)
				s.oidc.flows[q.Get("state")] = f
				s.oidc.mu.Unlock()
			case "replay":
				assertStatus(t, oidcRequest(s, "GET", callback, binding, nil), 303)
			case "duplicate-state":
				q.Add("state", q.Get("state"))
			case "duplicate-code":
				q.Add("code", q.Get("code"))
			case "provider-error":
				q.Set("error", "access_denied_sensitive_detail")
			case "code-exchange-error":
				q.Set("code", "sensitive-bad-code")
			}
			u.RawQuery = q.Encode()
			var w *httptest.ResponseRecorder
			if kind == "wrong-host" {
				r := httptest.NewRequest("GET", "https://evil.example"+u.RequestURI(), nil)
				r.AddCookie(binding)
				r.Header.Set("X-Forwarded-Host", "console.example.test")
				w = httptest.NewRecorder()
				s.ServeHTTP(w, r)
			} else {
				w = oidcRequest(s, "GET", u.RequestURI(), binding, nil)
			}
			assertStatus(t, w, 400)
			if strings.Contains(w.Body.String(), "sensitive") {
				t.Fatal("login failure disclosed provider/query details")
			}
			want := int32(0)
			if kind == "replay" || kind == "code-exchange-error" {
				want = 1
			}
			if p.exchanges.Load() != want {
				t.Fatal("invalid callback exchanged a code")
			}
		})
	}
}

func TestOIDCSessionSeparationLifetimeAndLoginOrigin(t *testing.T) {
	p := newTestOIDCProvider(t)
	p.claims = func(c map[string]any) {
		c["exp"] = time.Now().Add(2 * time.Hour).Unix()
		c["roles"] = []string{roleReader, roleAdmin}
	}
	s := newOIDCTestServer(t, p, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected Headscale request") })
	assertStatus(t, oidcRequest(s, "POST", "/auth/oidc/login", nil, nil), 403)
	assertStatus(t, oidcRequest(s, "POST", "/auth/oidc/login", nil, map[string]string{"Origin": "https://evil.example"}), 403)
	first, a := finishOIDC(t, s, p)
	second, b := finishOIDC(t, s, p)
	if first.Value == second.Value || a["csrfToken"] == b["csrfToken"] || first.MaxAge > int(oidcSessionDuration.Seconds()) {
		t.Fatal("OIDC sessions were shared or exceeded maximum lifetime")
	}
	assertStatus(t, request(s, "POST", "/api/logout", `{}`, map[string]string{"Origin": s.config.PublicURL, "X-CSRF-Token": a["csrfToken"].(string)}, second), 403)
	assertStatus(t, request(s, "POST", "/api/logout", `{}`, map[string]string{"Origin": s.config.PublicURL, "X-CSRF-Token": a["csrfToken"].(string)}, first), 200)
	assertStatus(t, request(s, "GET", "/api/session", "", nil, second), 200)
	s.sessionMu.Lock()
	sess := s.sessions[second.Value]
	sess.expires = time.Now().Add(-time.Second)
	s.sessions[second.Value] = sess
	s.sessionMu.Unlock()
	assertStatus(t, request(s, "GET", "/api/session", "", nil, second), 401)
}

func TestOIDCDiscoveryRejectsInsecureMetadataAndUntrustedTLS(t *testing.T) {
	p := newTestOIDCProvider(t)
	c := Config{AuthMode: "oidc", OIDCIssuer: p.server.URL, OIDCClientID: oidcTestClientID, OIDCClientSecret: oidcTestSecret, PublicURL: "https://console.example.test"}
	if _, err := newOIDC(c, nil); err == nil || strings.Contains(err.Error(), oidcTestSecret) {
		t.Fatal("discovery accepted untrusted provider TLS")
	}
	p.endpointScheme = "http"
	if _, err := newOIDC(c, p.server.Client()); err == nil {
		t.Fatal("discovery accepted HTTP endpoints")
	}
}

func TestOIDCAdditionalOriginSignsInOnlyAtItsOwnAddress(t *testing.T) {
	p := newTestOIDCProvider(t)
	p.claims = func(c map[string]any) { c["roles"] = []string{roleAdmin} }
	mesh := "https://console.mesh.example.test"
	p.extraRedirects = []string{mesh + "/auth/oidc/callback"}
	s := newOIDCTestServer(t, p, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected Headscale request") })
	s.config.AdditionalOrigins = []string{mesh}
	at := func(origin, method, target string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin+target, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	// Neither origin accepts the other's requests.
	assertStatus(t, at(mesh, "POST", "/auth/oidc/login", nil, map[string]string{"Origin": s.config.PublicURL}), 403)
	assertStatus(t, at(s.config.PublicURL, "POST", "/auth/oidc/login", nil, map[string]string{"Origin": mesh}), 403)

	w := at(mesh, "POST", "/auth/oidc/login", nil, map[string]string{"Origin": mesh})
	assertStatus(t, w, 200)
	binding := w.Result().Cookies()[0]
	var start struct {
		AuthorizationURL string `json:"authorizationUrl"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &start); err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(start.AuthorizationURL); u.Query().Get("redirect_uri") != mesh+"/auth/oidc/callback" {
		t.Fatalf("sign-in at the second origin returns elsewhere: %s", start.AuthorizationURL)
	}
	response, err := s.oidc.client.Get(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	callback, _ := url.Parse(response.Header.Get("Location"))
	// The flow cannot be completed at the other origin, and stays usable at its own.
	assertStatus(t, at(s.config.PublicURL, "GET", callback.RequestURI(), binding, nil), 400)
	w = at(mesh, "GET", callback.RequestURI(), binding, nil)
	assertStatus(t, w, 303)
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cookieName() {
			session = c
		}
	}
	if session == nil || !session.Secure || session.SameSite != http.SameSiteStrictMode {
		t.Fatal("no secure session at the second origin")
	}
	if p.exchanges.Load() != 1 {
		t.Fatalf("code exchanges: %d", p.exchanges.Load())
	}
}
