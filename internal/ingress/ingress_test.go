package ingress

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testGateway(t *testing.T, coordinator, management http.Handler) (*Gateway, *httptest.Server, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewTLSServer(coordinator)
	t.Cleanup(upstream.Close)
	admin := httptest.NewTLSServer(management)
	t.Cleanup(admin.Close)
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{ControlHost: "control.example.test", ControlPort: "443", AdminHost: "admin.example.test", AdminPort: "8444", HeadscaleURL: upstream.URL, ManagementURL: admin.URL, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	controlFront := httptest.NewTLSServer(g.ControlHandler())
	t.Cleanup(controlFront.Close)
	adminFront := httptest.NewTLSServer(g.AdminHandler())
	t.Cleanup(adminFront.Close)
	return g, controlFront, adminFront
}

func gatewayRequest(t *testing.T, front *httptest.Server, method, target, host string, headers http.Header, body io.Reader) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, front.URL+target, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host
	r.Header = headers
	response, err := front.Client().Do(r)
	if err != nil {
		t.Fatal("gateway request failed")
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func TestPublicAllowlistAndAdministrativeSegregation(t *testing.T) {
	var coordinatorCalls, adminCalls atomic.Int32
	_, control, admin := testGateway(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { coordinatorCalls.Add(1); w.WriteHeader(204) }),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { adminCalls.Add(1); w.WriteHeader(204) }),
	)
	id := "hskey-authreq-" + strings.Repeat("a", 24)
	allowed := []struct{ method, path string }{
		{"GET", "/key?v=131"}, {"GET", "/ts2021"}, {"POST", "/ts2021"},
		{"GET", "/register/" + id}, {"GET", "/auth/" + id},
		{"GET", "/register/confirm/" + id}, {"POST", "/register/confirm/" + id},
		{"GET", "/oidc/callback?code=example%2Bcode&state=example-state"},
		{"HEAD", "/machine/ping-response?id=example"}, {"GET", "/derp"},
		{"GET", "/derp/probe"}, {"HEAD", "/derp/probe"},
		{"GET", "/derp/latency-check"}, {"HEAD", "/derp/latency-check"}, {"GET", "/bootstrap-dns"},
	}
	for _, tc := range allowed {
		response := gatewayRequest(t, control, tc.method, tc.path, "control.example.test", nil, nil)
		if response.StatusCode != 204 {
			t.Fatalf("allowed %s route was rejected", tc.method)
		}
		response.Body.Close()
	}
	before := coordinatorCalls.Load()
	for _, p := range []string{"/", "/api", "/api/v1/users", "/swagger", "/swagger/v1/openapiv2.json", "/metrics", "/debug/pprof", "/version", "/health", "/verify", "/api/login"} {
		for _, method := range []string{"GET", "POST", "HEAD"} {
			response := gatewayRequest(t, control, method, p, "control.example.test:443", nil, nil)
			if response.StatusCode != 404 {
				t.Fatal("private route was not denied")
			}
			response.Body.Close()
		}
	}
	if coordinatorCalls.Load() != before || adminCalls.Load() != 0 {
		t.Fatal("denied public request reached a backend")
	}
	response := gatewayRequest(t, admin, "GET", "/api/users", "admin.example.test:8444", nil, nil)
	if response.StatusCode != 204 || adminCalls.Load() != 1 || coordinatorCalls.Load() != before {
		t.Fatal("private administration did not use its separate upstream")
	}
	response = gatewayRequest(t, admin, "GET", "/api/users", "control.example.test", nil, nil)
	if response.StatusCode != 421 || adminCalls.Load() != 1 {
		t.Fatal("public hostname was accepted by the private listener")
	}
}

func TestEncodedPathsAndMethodsCannotBypassAllowlist(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) })
	_, control, _ := testGateway(t, h, h)
	id := "hskey-authreq-" + strings.Repeat("a", 24)
	for _, target := range []string{
		"/%6bey", "/%2fkey", "/key%2f", "/%252fapi/v1/users", "/key/../api/v1/users", "/key/%2e%2e/api/v1/users",
		"//key", "/key/", "/key\\..\\api", "/key%00", "/key%3f/api/v1/users", "/register//" + id,
		"/register/" + id + "/extra", "/register/" + id[:len(id)-1], "/register/" + id + "x",
		"/auth/hskey-authreq-" + strings.Repeat("a", 23) + "!", "/register/confirm/" + id + "/..",
	} {
		response := gatewayRequest(t, control, "GET", target, "control.example.test", nil, nil)
		if response.StatusCode != 404 {
			t.Fatal("noncanonical or malformed enrollment path was accepted")
		}
		response.Body.Close()
	}
	for _, tc := range []struct{ method, path string }{{"POST", "/key"}, {"DELETE", "/ts2021"}, {"POST", "/auth/" + id}, {"POST", "/derp"}, {"GET", "/machine/ping-response"}, {"OPTIONS", "/oidc/callback"}} {
		response := gatewayRequest(t, control, tc.method, tc.path, "control.example.test", nil, nil)
		if response.StatusCode != 404 {
			t.Fatal("unlisted method was accepted")
		}
		response.Body.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("rejected requests reached the coordinator")
	}
}

func TestUnknownHostsAndUntrustedForwardingHeaders(t *testing.T) {
	var calls atomic.Int32
	_, control, _ := testGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		for _, header := range []string{"Forwarded", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix", "X-Forwarded-Port", "Proxy-Authorization"} {
			if r.Header.Get(header) != "" {
				t.Error("untrusted forwarding header reached upstream")
			}
		}
		if r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("X-Real-IP") != "127.0.0.1" || r.Header.Get("True-Client-IP") != "127.0.0.1" || r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("X-Forwarded-Host") != "control.example.test" || r.Host != "control.example.test" {
			t.Error("trusted forwarding metadata was not derived from the accepted request")
		}
		if r.URL.RawQuery != "code=example%2Bcode&state=example-state" {
			t.Error("OIDC callback query was changed")
		}
		w.WriteHeader(204)
	}), http.NotFoundHandler())
	for _, host := range []string{"attacker.test", "control.example.test.attacker.test", "control.example.test.", "control.example.test:80", "admin.example.test:8444"} {
		response := gatewayRequest(t, control, "GET", "/key", host, nil, nil)
		if response.StatusCode != 421 {
			t.Fatal("unrecognized public host was accepted")
		}
		response.Body.Close()
	}
	headers := http.Header{}
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Real-IP", "True-Client-IP", "X-Original-URL", "X-Rewrite-URL", "Proxy-Authorization"} {
		headers.Set(name, "untrusted-value")
	}
	response := gatewayRequest(t, control, "GET", "/oidc/callback?code=example%2Bcode&state=example-state", "control.example.test", headers, nil)
	if response.StatusCode != 204 || calls.Load() != 1 {
		t.Fatal("valid request with sanitized forwarding headers failed")
	}
}

func TestRequestBodyBoundAndPrivateUpgradeDenial(t *testing.T) {
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) })
	_, control, admin := testGateway(t, h, h)
	response := gatewayRequest(t, control, "POST", "/ts2021", "control.example.test", nil, strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	if response.StatusCode != 413 || calls.Load() != 0 {
		t.Fatal("oversized request reached upstream")
	}
	response = gatewayRequest(t, admin, "GET", "/", "admin.example.test:8444", http.Header{"Upgrade": []string{"websocket"}, "Connection": []string{"Upgrade"}}, nil)
	if response.StatusCode != 404 || calls.Load() != 0 {
		t.Fatal("private administration accepted a protocol upgrade")
	}
}

func TestBidirectionalCustomProtocolUpgrades(t *testing.T) {
	for _, tc := range []struct {
		method, path, protocol string
		early                  bool
	}{{"POST", "/ts2021", "tailscale-control-protocol", false}, {"GET", "/ts2021", "websocket", false}, {"GET", "/derp", "DERP", false}, {"POST", "/ts2021", "tailscale-control-protocol", true}} {
		t.Run(fmt.Sprintf("%s%s/early=%t", tc.method, tc.path, tc.early), func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != tc.path || r.Header.Get("Upgrade") != tc.protocol {
					t.Error("upgrade metadata changed")
					w.WriteHeader(400)
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\nserver-first", tc.protocol)
				rw.Flush()
				buffer := make([]byte, len("client-payload"))
				if _, err := io.ReadFull(rw, buffer); err != nil || string(buffer) != "client-payload" {
					t.Error("upgraded client payload did not reach upstream")
					return
				}
				rw.WriteString("server-reply")
				rw.Flush()
			})
			_, front, _ := testGateway(t, h, http.NotFoundHandler())
			roots := x509.NewCertPool()
			roots.AddCert(front.Certificate())
			conn, err := tls.Dial("tcp", front.Listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			earlyPayload := ""
			if tc.early {
				earlyPayload = "client-payload"
			}
			fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: control.example.test\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n%s", tc.method, tc.path, tc.protocol, earlyPayload)
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: tc.method})
			if err != nil || response.StatusCode != 101 || response.Header.Get("Upgrade") != tc.protocol {
				t.Fatal("custom upgrade handshake failed")
			}
			serverFirst := make([]byte, len("server-first"))
			if _, err := io.ReadFull(reader, serverFirst); err != nil || string(serverFirst) != "server-first" {
				t.Fatal("upstream's unsolicited upgraded data was lost")
			}
			if !tc.early {
				if _, err := io.WriteString(conn, "client-payload"); err != nil {
					t.Fatal(err)
				}
			}
			reply := make([]byte, len("server-reply"))
			if _, err := io.ReadFull(reader, reply); err != nil || string(reply) != "server-reply" {
				t.Fatal("bidirectional upgraded stream failed")
			}
		})
	}
}

func TestUpstreamCertificateVerificationAndSanitizedErrors(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted upstream received a request") }))
	defer upstream.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "wrong-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{ControlHost: "control.example.test", ControlPort: "443", AdminHost: "admin.example.test", AdminPort: "8444", HeadscaleURL: upstream.URL, ManagementURL: upstream.URL, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	front := httptest.NewTLSServer(g.ControlHandler())
	defer front.Close()
	response := gatewayRequest(t, front, "GET", "/oidc/callback?code=sensitive-code&state=sensitive-state", "control.example.test", nil, nil)
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 502 || strings.Contains(string(body), "sensitive") || strings.Contains(string(body), upstream.URL) || strings.Contains(string(body), "certificate") {
		t.Fatal("untrusted upstream was accepted or proxy error disclosed request metadata")
	}
}

func TestUpstreamAndHostConfigurationRejectAmbiguity(t *testing.T) {
	for _, raw := range []string{"http://headscale:8443", "https://user:password@headscale:8443", "https://headscale:8443/api", "https://headscale:8443?target=example", "https://headscale:8443#fragment"} {
		if _, err := upstreamURL(raw); err == nil {
			t.Fatal("unsafe upstream configuration was accepted")
		}
	}
	for _, host := range []string{"", "control.example.test:443", "control.example.test.", "control/example.test", "*.example.test", "control..example.test"} {
		if validHost(host) {
			t.Fatal("ambiguous host configuration was accepted")
		}
	}
	r := httptest.NewRequest("GET", "https://control.example.test/key", nil)
	if canonicalPath(r) {
		t.Fatal("absolute-form proxy request was accepted")
	}
	r.URL = &url.URL{Path: "/key", RawPath: "/%6bey"}
	if canonicalPath(r) {
		t.Fatal("alternate encoded path spelling was accepted")
	}
}

func TestInNetworkConsoleListenerServesOnlyTheConsoleUnderItsOwnName(t *testing.T) {
	var adminCalls, coordinatorCalls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { coordinatorCalls.Add(1); w.WriteHeader(204) }))
	t.Cleanup(upstream.Close)
	admin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminCalls.Add(1)
		if r.Host != "console.mesh.example.test" {
			t.Errorf("console saw host %q", r.Host)
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(admin.Close)
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	base := Config{ControlHost: "control.example.test", ControlPort: "443", AdminHost: "admin.example.test", AdminPort: "8444", HeadscaleURL: upstream.URL, ManagementURL: admin.URL, CAFile: ca}
	if g, err := New(base); err != nil || g.MeshHandler() != nil {
		t.Fatalf("without a console host there must be no in-network listener: %v", err)
	}
	for _, bad := range []string{"control.example.test", "admin.example.test", "bad host", "console.example.test."} {
		c := base
		c.MeshHost = bad
		if _, err := New(c); err == nil {
			t.Fatalf("console host %q accepted", bad)
		}
	}
	c := base
	c.MeshHost = "console.mesh.example.test"
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	mesh := httptest.NewTLSServer(g.MeshHandler())
	t.Cleanup(mesh.Close)
	response := gatewayRequest(t, mesh, "GET", "/api/users", "console.mesh.example.test", nil, nil)
	if response.StatusCode != 204 || adminCalls.Load() != 1 {
		t.Fatalf("console request status %d", response.StatusCode)
	}
	for _, host := range []string{"control.example.test", "admin.example.test:8444", "console.mesh.example.test:8447"} {
		if response := gatewayRequest(t, mesh, "GET", "/api/users", host, nil, nil); response.StatusCode != 421 {
			t.Fatalf("host %s got %d", host, response.StatusCode)
		}
	}
	upgrade := http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}
	if response := gatewayRequest(t, mesh, "GET", "/api/users", "console.mesh.example.test", upgrade, nil); response.StatusCode != 404 {
		t.Fatalf("upgrade got %d", response.StatusCode)
	}
	if adminCalls.Load() != 1 || coordinatorCalls.Load() != 0 {
		t.Fatal("refused requests reached a backend, or the console listener reached the coordinator")
	}
}
