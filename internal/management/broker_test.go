package management

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"covee.io/internal/identity"
)

// This transport substitutes only the signed HTTPS Google fixture. Browser,
// broker and console still use their real discovery, JWKS and token handlers.
type brokerFixtureTransport struct {
	base    http.RoundTripper
	fixture *url.URL
}

func (t brokerFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "accounts.google.com" || r.URL.Host == "oauth2.googleapis.com" || r.URL.Host == "www.googleapis.com" {
		copy := r.Clone(r.Context())
		address := *r.URL
		address.Scheme, address.Host = t.fixture.Scheme, t.fixture.Host
		copy.URL = &address
		return t.base.RoundTrip(copy)
	}
	return t.base.RoundTrip(r)
}

func brokerPrivateFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func challengeForTest(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestBrokerGoogleLoginEstablishesOnlyGrantedConsoleRole(t *testing.T) {
	for _, role := range []string{roleAdmin, roleReader, ""} {
		t.Run("grant="+role, func(t *testing.T) {
			p := newTestOIDCProvider(t)
			front := httptest.NewUnstartedServer(nil)
			t.Cleanup(front.Close)
			issuer := "https://" + front.Listener.Addr().String() + "/identity"
			p.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					respond(w, 200, map[string]any{"issuer": identity.GoogleIssuer, "authorization_endpoint": identity.GoogleIssuer + "/o/oauth2/v2/auth", "token_endpoint": "https://oauth2.googleapis.com/token", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
				case "/o/oauth2/v2/auth":
					q := r.URL.Query()
					if q.Get("redirect_uri") != issuer+"/callback/google" || q.Get("client_id") != "google-broker-client" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
						t.Error("broker sent invalid upstream authorization request")
						http.Error(w, "invalid_request", 400)
						return
					}
					p.mu.Lock()
					p.codes["google-single-use-code"] = testAuthorization{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")}
					p.mu.Unlock()
					http.Redirect(w, r, issuer+"/callback/google?"+url.Values{"code": {"google-single-use-code"}, "state": {q.Get("state")}}.Encode(), 303)
				case "/token":
					if r.ParseForm() != nil {
						t.Error("invalid token form")
						return
					}
					p.mu.Lock()
					auth, ok := p.codes[r.Form.Get("code")]
					delete(p.codes, r.Form.Get("code"))
					p.mu.Unlock()
					if !ok || r.Form.Get("client_id") != "google-broker-client" || r.Form.Get("client_secret") != "google-private-secret" || r.Form.Get("redirect_uri") != auth.redirect || challengeForTest(r.Form.Get("code_verifier")) != auth.challenge {
						http.Error(w, "invalid_grant", 400)
						return
					}
					now := time.Now()
					// Upstream role/email injection must never grant a social user access.
					claims := map[string]any{"iss": identity.GoogleIssuer, "aud": "google-broker-client", "sub": "google-stable-subject", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": auth.nonce, "roles": []string{roleAdmin}, "email": "admin@example.test", "email_verified": true}
					raw, err := signTestJWT(p.key, claims)
					if err != nil {
						t.Error(err)
						return
					}
					respond(w, 200, map[string]any{"access_token": "google-unused-access", "token_type": "Bearer", "id_token": raw, "expires_in": 3600})
				case "/oauth2/v3/certs":
					r.URL.Path = "/jwks"
					p.handle(w, r)
				default:
					http.NotFound(w, r)
				}
			})
			client := p.server.Client()
			fixtureURL, _ := url.Parse(p.server.URL)
			client.Transport = brokerFixtureTransport{client.Transport, fixtureURL}
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			client.Timeout = 10 * time.Second
			keyDER, err := x509.MarshalPKCS8PrivateKey(p.key)
			if err != nil {
				t.Fatal(err)
			}
			tlsKeyDER, err := x509.MarshalPKCS8PrivateKey(p.server.TLS.Certificates[0].PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			c := identity.Config{Issuer: issuer, Listen: "127.0.0.1:8446", TLSCertFile: brokerPrivateFile(t, "tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.server.Certificate().Raw})), TLSKeyFile: brokerPrivateFile(t, "tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsKeyDER})), SigningKeyFile: brokerPrivateFile(t, "signing.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
				Clients:   []identity.ClientConfig{{ID: oidcTestClientID, SecretFile: brokerPrivateFile(t, "console.secret", []byte(oidcTestSecret)), RedirectURI: "https://console.example.test/auth/oidc/callback", Kind: "console"}},
				Providers: []identity.ProviderConfig{{ID: "google", Kind: "google", ClientID: "google-broker-client", ClientSecretFile: brokerPrivateFile(t, "google.secret", []byte("google-private-secret"))}}}
			if role != "" {
				c.Grants = []identity.Grant{{Provider: "google", Subject: "google-stable-subject", Role: role}}
			}
			broker, err := identity.New(oidc.ClientContext(context.Background(), client), c)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(broker.Close)
			front.Config.Handler = broker.Handler()
			front.StartTLS()
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"users":[]}`) }))
			t.Cleanup(up.Close)
			s, err := newServer(Config{Listen: "127.0.0.1:8088", PublicURL: "https://console.example.test", AuthMode: "oidc", OIDCIssuer: issuer, OIDCClientID: oidcTestClientID, OIDCClientSecret: oidcTestSecret, OIDCLabel: "Continue to sign in", HeadscaleURL: up.URL, HeadscaleAPIKey: testAPIKey, DataDir: t.TempDir()}, client)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			settings := oidcRequest(s, "GET", "/auth/config", nil, nil)
			if !strings.Contains(settings.Body.String(), `"signinLabel":"Continue to sign in"`) {
				t.Fatal("console did not advertise provider-neutral sign-in")
			}
			login := oidcRequest(s, "POST", "/auth/oidc/login", nil, map[string]string{"Origin": s.config.PublicURL})
			assertStatus(t, login, 200)
			var start map[string]string
			if err := json.Unmarshal(login.Body.Bytes(), &start); err != nil {
				t.Fatal(err)
			}
			consoleBinding := login.Result().Cookies()[0]
			chooser, err := client.Get(start["authorizationUrl"])
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(chooser.Body)
			chooser.Body.Close()
			if chooser.StatusCode != 200 {
				t.Fatalf("broker chooser rejected console authorization: %d", chooser.StatusCode)
			}
			states := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(string(body))
			if len(states) != 2 {
				t.Fatal("broker chooser missing browser-bound state")
			}
			binding := chooser.Cookies()[0]
			form := url.Values{"provider": {"google"}, "state": {html.UnescapeString(states[1])}}
			r, _ := http.NewRequest("POST", issuer+"/select", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", strings.TrimSuffix(issuer, "/identity"))
			r.AddCookie(binding)
			selected, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(selected.Body)
			selected.Body.Close()
			links := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(string(body))
			if selected.StatusCode != 200 || len(links) != 2 {
				t.Fatal("broker selection did not return provider navigation")
			}
			google, err := client.Get(html.UnescapeString(links[1]))
			if err != nil {
				t.Fatal(err)
			}
			google.Body.Close()
			if google.StatusCode != 303 {
				t.Fatal("signed Google fixture rejected broker")
			}
			r, _ = http.NewRequest("GET", google.Header.Get("Location"), nil)
			r.AddCookie(binding)
			callback, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(callback.Body)
			callback.Body.Close()
			if role == "" {
				if callback.StatusCode != 403 || !strings.Contains(string(body), "google-stable-subject") {
					t.Fatal("ungranted identity gained access or could not request its own grant")
				}
				assertStatus(t, oidcRequest(s, "GET", "/api/session", nil, nil), 401)
				return
			}
			if callback.StatusCode != 303 {
				t.Fatalf("granted identity rejected: %d", callback.StatusCode)
			}
			consoleCallback, _ := url.Parse(callback.Header.Get("Location"))
			finish := oidcRequest(s, "GET", consoleCallback.RequestURI(), consoleBinding, nil)
			assertStatus(t, finish, 303)
			var sessionCookie *http.Cookie
			for _, cookie := range finish.Result().Cookies() {
				if cookie.Name == s.cookieName() {
					sessionCookie = cookie
				}
			}
			if sessionCookie == nil || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.MaxAge > 300 {
				t.Fatal("broker session did not retain strict cookie and bounded token lifetime")
			}
			sessionResponse := oidcRequest(s, "GET", "/api/session", sessionCookie, nil)
			assertStatus(t, sessionResponse, 200)
			var info struct {
				User        Actor
				Permissions struct {
					CanWrite bool `json:"canWrite"`
				}
			}
			if json.Unmarshal(sessionResponse.Body.Bytes(), &info) != nil || info.User.Issuer != issuer || info.User.Role != role || info.Permissions.CanWrite != (role == roleAdmin) {
				t.Fatal("broker role was not enforced by the real console")
			}
			assertStatus(t, oidcRequest(s, "GET", consoleCallback.RequestURI(), consoleBinding, nil), 400)
		})
	}
}
