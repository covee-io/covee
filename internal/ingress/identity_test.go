package ingress

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIdentityRoutesUseOnlyDedicatedVerifiedBackend(t *testing.T) {
	var coordinatorCalls, managementCalls, identityCalls atomic.Int32
	coordinator := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		coordinatorCalls.Add(1)
		w.WriteHeader(204)
	}))
	defer coordinator.Close()
	management := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		managementCalls.Add(1)
		w.WriteHeader(204)
	}))
	defer management.Close()
	identity := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityCalls.Add(1)
		if r.Host != "control.example.test" {
			t.Error("identity proxy changed browser-visible host")
		}
		if r.Header.Get("X-Forwarded-Host") != "control.example.test" || r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Error("identity proxy trusted injected forwarded headers")
		}
		w.WriteHeader(202)
	}))
	defer identity.Close()
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{ControlHost: "control.example.test", ControlPort: "443", AdminHost: "admin.example.test", AdminPort: "8444", HeadscaleURL: coordinator.URL, ManagementURL: management.URL, IdentityURL: identity.URL, CAFile: ca}
	for _, only := range []bool{false, true} {
		c.IdentityOnly = only
		g, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		front := httptest.NewTLSServer(g.ControlHandler())
		admin := httptest.NewTLSServer(g.AdminHandler())
		allowed := []struct{ method, path string }{
			{"GET", "/identity/.well-known/openid-configuration"}, {"GET", "/identity/jwks"},
			{"GET", "/identity/authorize?client_id=coordinator"}, {"POST", "/identity/select"},
			{"GET", "/identity/callback/entra?code=example&state=example"}, {"GET", "/identity/callback/google"},
			{"POST", "/identity/callback/apple"}, {"POST", "/identity/token"}, {"GET", "/identity/userinfo"},
			{"GET", "/identity/local/app.js"}, {"GET", "/identity/local/invite"}, {"POST", "/identity/local/passkey/options"},
			{"POST", "/identity/local/passkey/finish"}, {"POST", "/identity/local/password"}, {"POST", "/identity/local/invite/info"},
			{"POST", "/identity/local/invite/passkey/options"}, {"POST", "/identity/local/invite/passkey/finish"},
			{"POST", "/identity/local/invite/totp"}, {"POST", "/identity/local/invite/password"},
		}
		for _, tc := range allowed {
			r := gatewayRequest(t, front, tc.method, tc.path, c.ControlHost, http.Header{"X-Forwarded-Host": {"attacker.invalid"}, "Forwarded": {"host=attacker.invalid"}}, strings.NewReader("state=example"))
			if r.StatusCode != 202 {
				t.Fatalf("identity-only=%t: %s %s status=%d", only, tc.method, tc.path, r.StatusCode)
			}
			r.Body.Close()
		}
		before := identityCalls.Load()
		for _, tc := range []struct{ method, path string }{
			{"GET", "/identity"}, {"GET", "/identity/healthz"}, {"GET", "/identity/providers"},
			{"GET", "/identity/api/users"}, {"GET", "/identity/callback/apple"}, {"POST", "/identity/callback/google"},
			{"POST", "/identity/local/app.js"}, {"GET", "/identity/local/password"}, {"GET", "/identity/local/accounts"},
			{"POST", "/identity/local/invite"}, {"GET", "/identity/local/invite/info"}, {"GET", "/identity/local/"},
			{"GET", "/identity/token"}, {"POST", "/identity/jwks"}, {"GET", "/identity/callback/other"},
			{"GET", "/identity/%2e%2e/api/users"}, {"GET", "/identity//jwks"},
		} {
			r := gatewayRequest(t, front, tc.method, tc.path, c.ControlHost, nil, nil)
			if r.StatusCode != 404 {
				t.Fatalf("unexpected public identity route: %s %s", tc.method, tc.path)
			}
			r.Body.Close()
		}
		if identityCalls.Load() != before || managementCalls.Load() != 0 {
			t.Fatal("denied public identity request reached a backend")
		}
		r := gatewayRequest(t, front, "GET", "/identity/jwks", c.ControlHost, http.Header{"Upgrade": {"websocket"}}, nil)
		if r.StatusCode != 404 {
			t.Fatal("identity upgrade was not denied")
		}
		r.Body.Close()
		key := gatewayRequest(t, front, "GET", "/key", c.ControlHost, nil, nil)
		api := gatewayRequest(t, admin, "GET", "/api/users", "admin.example.test:8444", nil, nil)
		if only && (key.StatusCode != 404 || api.StatusCode != 404) || !only && (key.StatusCode != 204 || api.StatusCode != 204) {
			t.Fatal("bootstrap identity-only boundary was not enforced")
		}
		key.Body.Close()
		api.Body.Close()
		managementCalls.Store(0)
		front.Close()
		admin.Close()
		g.Close()
	}
	if coordinatorCalls.Load() != 1 {
		t.Fatal("coordinator was reachable during identity-only bootstrap")
	}
}

func TestIdentityRoutesDisabledWithoutUpstream(t *testing.T) {
	_, front, _ := testGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("identity route reached coordinator") }), http.NotFoundHandler())
	for _, p := range []string{"/identity/jwks", "/identity/authorize", "/identity/.well-known/openid-configuration"} {
		r := gatewayRequest(t, front, "GET", p, "control.example.test", nil, nil)
		if r.StatusCode != 404 {
			t.Fatal("disabled identity route was exposed")
		}
		r.Body.Close()
	}
	c := Config{ControlHost: "control.test", ControlPort: "443", AdminHost: "admin.test", AdminPort: "8444", HeadscaleURL: "https://headscale:8443", ManagementURL: "https://management:8445", IdentityOnly: true}
	if err := c.validate(); err == nil {
		t.Fatal("identity-only mode accepted no identity upstream")
	}
	c.IdentityURL = "http://identity:8446"
	if err := c.validate(); err == nil {
		t.Fatal("unverified plaintext identity upstream accepted")
	}
}
