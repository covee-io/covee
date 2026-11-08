package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mesh = "mesh.covee.io"

func host(name string, port int, path string) map[string]any {
	return map[string]any{"name": name + "." + mesh, "address": "100.64.0.7", "port": port,
		"path": path, "scheme": "http", "verify": true, "device": "mac-mini"}
}

func hostsJSON(t *testing.T, hosts ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"hosts": hosts})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func with(h map[string]any, key string, value any) map[string]any {
	out := map[string]any{}
	for k, v := range h {
		out[k] = v
	}
	if value == nil {
		delete(out, key)
	} else {
		out[key] = value
	}
	return out
}

func TestHostsFileIsCheckedStrictly(t *testing.T) {
	good := host("grafana", 8080, "/some/sub/service")
	hosts, err := parseHosts(hostsJSON(t, good, with(host("files", 443, ""), "scheme", "https"), with(host("wiki", 80, "/"), "verify", nil)))
	if err != nil || len(hosts) != 3 {
		t.Fatalf("good file = %v, %v", hosts, err)
	}
	want := Host{Name: "grafana.mesh.covee.io", Address: "100.64.0.7", Port: 8080, Path: "/some/sub/service", Scheme: "http", Verify: true, Device: "mac-mini"}
	if hosts[0] != want {
		t.Fatalf("parsed %+v, want %+v", hosts[0], want)
	}
	if !hosts[2].Verify {
		t.Fatal("an entry without verify must check the certificate")
	}
	// Fields this version does not know, such as deploy.py's node_id, are ignored.
	for _, nodeID := range []any{"12", 12} {
		extra := with(with(good, "node_id", nodeID), "future", map[string]any{"a": []int{1}})
		raw, _ := json.Marshal(map[string]any{"hosts": []map[string]any{extra}, "version": 2})
		if hosts, err := parseHosts(raw); err != nil || len(hosts) != 1 || hosts[0] != want {
			t.Fatalf("extra fields (node_id %v) = %v, %v", nodeID, hosts, err)
		}
	}
	for _, path := range []string{"/", "/a//b", "//x", "/a%20b", "/a%2Fb", "/a%3Fb", "/./x", "/é", "/a:b@c"} {
		if _, err := parseHosts(hostsJSON(t, with(good, "path", path))); err != nil {
			t.Errorf("path %q was refused: %v", path, err)
		}
	}
	if hosts, err := parseHosts(hostsJSON(t, with(good, "address", "fd7a:115c:a1e0::7"))); err != nil || len(hosts) != 1 {
		t.Fatalf("IPv6 target = %v, %v", hosts, err)
	}

	tooMany := make([]map[string]any, maxHosts+1)
	for i := range tooMany {
		tooMany[i] = host(fmt.Sprintf("h%d", i), 80, "")
	}
	bad := map[string][]byte{
		"not JSON":            []byte(`{"hosts": [`),
		"uppercase name":      hostsJSON(t, with(good, "name", "Grafana."+mesh)),
		"single label":        hostsJSON(t, with(good, "name", "grafana")),
		"trailing dot":        hostsJSON(t, with(good, "name", "grafana."+mesh+".")),
		"leading hyphen":      hostsJSON(t, with(good, "name", "-grafana."+mesh)),
		"underscore":          hostsJSON(t, with(good, "name", "gra_fana."+mesh)),
		"empty label":         hostsJSON(t, with(good, "name", "grafana.."+mesh)),
		"long label":          hostsJSON(t, with(good, "name", strings.Repeat("a", 64)+"."+mesh)),
		"duplicate":           hostsJSON(t, good, with(good, "port", 9090)),
		"public address":      hostsJSON(t, with(good, "address", "203.0.113.7")),
		"server address":      hostsJSON(t, with(good, "address", "127.0.0.1")),
		"hostname address":    hostsJSON(t, with(good, "address", "mac-mini")),
		"mapped address":      hostsJSON(t, with(good, "address", "::ffff:100.64.0.7")),
		"port 0":              hostsJSON(t, with(good, "port", 0)),
		"port too large":      hostsJSON(t, with(good, "port", 65536)),
		"relative path":       hostsJSON(t, with(good, "path", "some/service")),
		"dot-dot":             hostsJSON(t, with(good, "path", "/a/../etc")),
		"dots in a segment":   hostsJSON(t, with(good, "path", "/a..b")),
		"half-encoded dots":   hostsJSON(t, with(good, "path", "/.%2e/etc")),
		"backslash":           hostsJSON(t, with(good, "path", "/a\\b")),
		"encoded backslash":   hostsJSON(t, with(good, "path", "/a%5Cb")),
		"control character":   hostsJSON(t, with(good, "path", "/a\tb")),
		"encoded newline":     hostsJSON(t, with(good, "path", "/a%0Ab")),
		"encoded NUL":         hostsJSON(t, with(good, "path", "/a%00b")),
		"long path":           hostsJSON(t, with(good, "path", "/"+strings.Repeat("a", maxPathLength))),
		"encoded dot-dot":     hostsJSON(t, with(good, "path", "/a/%2e%2e/etc")),
		"query in path":       hostsJSON(t, with(good, "path", "/a?b=c")),
		"fragment in path":    hostsJSON(t, with(good, "path", "/a#b")),
		"space in path":       hostsJSON(t, with(good, "path", "/a b")),
		"bad escape in path":  hostsJSON(t, with(good, "path", "/a%zz")),
		"scheme ftp":          hostsJSON(t, with(good, "scheme", "ftp")),
		"scheme missing":      hostsJSON(t, with(good, "scheme", nil)),
		"scheme uppercase":    hostsJSON(t, with(good, "scheme", "HTTP")),
		"bad device name":     hostsJSON(t, with(good, "device", "mac mini")),
		"too many hosts":      hostsJSON(t, tooMany...),
		"hosts is not a list": []byte(`{"hosts": {}}`),
	}
	for name, raw := range bad {
		if hosts, err := parseHosts(raw); err == nil {
			t.Errorf("%s: accepted %v", name, hosts)
		}
	}

	path := filepath.Join(t.TempDir(), "hosts.json")
	if hosts, err := readHosts(path); err != nil || len(hosts) != 0 {
		t.Fatalf("missing file = %v, %v", hosts, err)
	}
	if err := os.WriteFile(path, append([]byte(`{"hosts": []}`), make([]byte, maxHostsFileSize)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHosts(path); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("a file over 1 MiB = %v", err)
	}
}

// devices dials network addresses at local test servers instead, as the
// network device would dial the devices themselves.
type devices map[string]string

func (d devices) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	local, ok := d[addr]
	if !ok {
		return nil, errors.New("no route to " + addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, local)
}

func addrOf(s *httptest.Server) string {
	return strings.TrimPrefix(strings.TrimPrefix(s.URL, "http://"), "https://")
}

// echo answers with what it received, as JSON.
func echo() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"uri": r.RequestURI, "host": r.Host, "header": r.Header})
	}))
}

type echoed struct {
	URI    string      `json:"uri"`
	Host   string      `json:"host"`
	Header http.Header `json:"header"`
}

func get(t *testing.T, handler http.Handler, hostHeader, target string, header http.Header) (*http.Response, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = hostHeader
	for k, v := range header {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w.Result(), w.Body.String()
}

func mustParse(t *testing.T, hosts ...map[string]any) []Host {
	t.Helper()
	out, err := parseHosts(hostsJSON(t, hosts...))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRequestPathIsJoinedToTheTargetPath(t *testing.T) {
	backend := echo()
	defer backend.Close()
	rt := newRouter(devices{"100.64.0.7:8080": addrOf(backend)}.dial, nil, t.Logf)
	rt.install(mustParse(t,
		host("root", 8080, ""), host("slash", 8080, "/"), host("svc", 8080, "/some/sub/service"),
		host("trailing", 8080, "/svc/"), host("encoded", 8080, "/a%20b"),
		host("double", 8080, "//x"), host("inner", 8080, "/a//b"), host("slash2f", 8080, "/%2Fx")))
	cases := []struct{ name, request, want string }{
		{"root", "/", "/"},
		{"root", "/a?b=1&c", "/a?b=1&c"},
		{"slash", "/", "/"},
		{"slash", "/x/y", "/x/y"},
		{"svc", "/", "/some/sub/service/"},
		{"svc", "/a?b", "/some/sub/service/a?b"},
		{"svc", "/a/b/?q=%2F", "/some/sub/service/a/b/?q=%2F"},
		{"svc", "/a%2Fb", "/some/sub/service/a%2Fb"},
		{"svc", "/a?x=1;y=2&z=%zz", "/some/sub/service/a?x=1;y=2&z=%zz"},
		{"trailing", "/", "/svc/"},
		{"trailing", "/a/", "/svc/a/"},
		{"encoded", "/c", "/a%20b/c"},
		{"double", "/", "//x/"},
		{"double", "/a?b", "//x/a?b"},
		{"inner", "/c", "/a//b/c"},
		{"slash2f", "/c", "/%2Fx/c"},
	}
	for _, c := range cases {
		resp, body := get(t, rt, c.name+"."+mesh, c.request, nil)
		var got echoed
		if err := json.Unmarshal([]byte(body), &got); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s %s: %d %s", c.name, c.request, resp.StatusCode, body)
		}
		if got.URI != c.want {
			t.Errorf("%s %s reached %s, want %s", c.name, c.request, got.URI, c.want)
		}
	}
}

func TestRequestCannotClimbOutOfTheTargetPath(t *testing.T) {
	backend := echo()
	defer backend.Close()
	rt := newRouter(devices{"100.64.0.7:8080": addrOf(backend)}.dial, nil, t.Logf)
	rt.install(mustParse(t, host("svc", 8080, "/some/service"), host("root", 8080, "")))
	for _, request := range []string{"/../other", "/a/../../other", "/%2e%2e/other", "/a/..%2f..%2fother", "/..%5cother"} {
		if resp, body := get(t, rt, "svc."+mesh, request, nil); resp.StatusCode != 400 {
			t.Errorf("%s: %d %s", request, resp.StatusCode, body)
		}
	}
	// Names that merely contain dots stay, and a host without a path has nothing to leave.
	if resp, _ := get(t, rt, "svc."+mesh, "/file..txt", nil); resp.StatusCode != 200 {
		t.Errorf("/file..txt: %d", resp.StatusCode)
	}
	if resp, _ := get(t, rt, "root."+mesh, "/a/../b", nil); resp.StatusCode != 200 {
		t.Errorf("no path: %d", resp.StatusCode)
	}
}

func TestHostHeaderChoosesTheHost(t *testing.T) {
	grafana, wiki := echo(), echo()
	defer grafana.Close()
	defer wiki.Close()
	rt := newRouter(devices{"100.64.0.7:8080": addrOf(grafana), "100.64.0.7:9090": addrOf(wiki)}.dial, nil, t.Logf)
	rt.install(mustParse(t, host("grafana", 8080, "/g"), host("wiki", 9090, "/w")))
	for hostHeader, want := range map[string]string{
		"grafana.mesh.covee.io":      "/g/",
		"GRAFANA.Mesh.Covee.IO":      "/g/",
		"grafana.mesh.covee.io:443":  "/g/",
		"grafana.mesh.covee.io.":     "/g/",
		"Wiki.mesh.covee.io.:8443":   "/w/",
		"wiki.mesh.covee.io":         "/w/",
		"grafana.other.example:443":  "",
		"hosts.mesh.covee.io":        "",
		"100.64.0.9":                 "",
		"[fd7a:115c:a1e0::9]:443":    "",
		"mac-mini." + mesh + ":8080": "",
	} {
		resp, body := get(t, rt, hostHeader, "/", nil)
		if want == "" {
			name := hostName(hostHeader)
			if resp.StatusCode != 404 || body != "No host named "+name+" in this network.\n" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
				t.Errorf("%s: %d %q", hostHeader, resp.StatusCode, body)
			}
			continue
		}
		var got echoed
		json.Unmarshal([]byte(body), &got)
		if resp.StatusCode != 200 || got.URI != want {
			t.Errorf("%s: %d reached %s, want %s", hostHeader, resp.StatusCode, got.URI, want)
		}
		// The service sees the name it was opened by.
		if got.Host != hostHeader {
			t.Errorf("%s: the service saw Host %s", hostHeader, got.Host)
		}
	}
}

func TestForwardedHeadersAreOverwritten(t *testing.T) {
	backend := echo()
	defer backend.Close()
	rt := newRouter(devices{"100.64.0.7:8080": addrOf(backend)}.dial, nil, t.Logf)
	rt.install(mustParse(t, host("grafana", 8080, "")))
	_, body := get(t, rt, "grafana.mesh.covee.io", "/", http.Header{
		"X-Forwarded-For":   {"203.0.113.9"},
		"X-Forwarded-Host":  {"bank.example"},
		"X-Forwarded-Proto": {"http"},
		"Forwarded":         {"for=203.0.113.9;proto=http"},
		"Cookie":            {"session=1"},
	})
	var got echoed
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(body)
	}
	h := got.Header
	if v := h.Values("X-Forwarded-For"); len(v) != 1 || v[0] != "192.0.2.1" { // httptest.NewRequest's client
		t.Errorf("X-Forwarded-For = %v", v)
	}
	if v := h.Values("X-Forwarded-Host"); len(v) != 1 || v[0] != "grafana.mesh.covee.io" {
		t.Errorf("X-Forwarded-Host = %v", v)
	}
	if v := h.Values("X-Forwarded-Proto"); len(v) != 1 || v[0] != "https" {
		t.Errorf("X-Forwarded-Proto = %v", v)
	}
	if v := h.Values("Forwarded"); len(v) != 0 {
		t.Errorf("Forwarded = %v", v)
	}
	if h.Get("Cookie") != "session=1" {
		t.Errorf("other headers must pass through: %v", h)
	}
}

func TestOnlyCurrentDevicesAreDialed(t *testing.T) {
	backend := echo()
	defer backend.Close()
	current := map[netip.Addr]bool{netip.MustParseAddr("100.64.0.7"): true}
	var connected []netip.AddrPort
	dial := peersOnly(func(ip netip.Addr) bool { return current[ip] }, func(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
		connected = append(connected, target)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addrOf(backend))
	})
	for _, c := range [][2]string{{"tcp", "100.64.0.8:8080"}, {"tcp", "mac-mini:8080"}, {"tcp", "100.64.0.7"}, {"udp", "100.64.0.7:8080"}} {
		if _, err := dial(context.Background(), c[0], c[1]); !errors.Is(err, errNotADevice) {
			t.Errorf("%s %s: %v", c[0], c[1], err)
		}
	}
	if len(connected) != 0 {
		t.Fatalf("connected to %v", connected)
	}

	rt := newRouter(dial, nil, t.Logf)
	rt.install(mustParse(t, host("grafana", 8080, ""), with(host("gone", 8080, ""), "address", "100.64.0.8")))
	if resp, _ := get(t, rt, "grafana."+mesh, "/", nil); resp.StatusCode != 200 {
		t.Errorf("a current device: %d", resp.StatusCode)
	}
	// The normal 502 page, without a word of the request reaching anything.
	resp, body := get(t, rt, "gone."+mesh, "/", http.Header{"Cookie": {"session=1"}})
	if resp.StatusCode != 502 || !strings.Contains(body, "mac-mini") || !strings.Contains(body, "8080") {
		t.Errorf("a removed device: %d %q", resp.StatusCode, body)
	}
	if len(connected) != 1 || connected[0].Addr().String() != "100.64.0.7" {
		t.Errorf("connected to %v", connected)
	}
}

func TestUnreachableTargetIs502(t *testing.T) {
	rt := newRouter(devices{}.dial, nil, t.Logf)
	rt.install(mustParse(t, host("grafana", 8080, "/x")))
	resp, body := get(t, rt, "grafana.mesh.covee.io", "/", nil)
	if resp.StatusCode != 502 || !strings.Contains(body, "mac-mini") || !strings.Contains(body, "8080") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

// newCert makes a self-signed certificate for names, valid from notBefore.
func newCert(t *testing.T, notBefore time.Time, names ...string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: notBefore, NotAfter: notBefore.Add(24 * time.Hour), DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), cert
}

func TestHTTPSTargets(t *testing.T) {
	selfSigned := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "self-signed") }))
	defer selfSigned.Close()

	certPEM, keyPEM, cert := newCert(t, time.Now().Add(-time.Hour), "mac-mini."+mesh)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	named := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "named "+r.TLS.ServerName) }))
	named.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	named.StartTLS()
	defer named.Close()
	otherPEM, otherKeyPEM, other := newCert(t, time.Now().Add(-time.Hour), "other.example")
	otherPair, err := tls.X509KeyPair(otherPEM, otherKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	misnamed := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "misnamed") }))
	misnamed.TLS = &tls.Config{Certificates: []tls.Certificate{otherPair}}
	misnamed.StartTLS()
	defer misnamed.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	roots.AddCert(other)

	rt := newRouter(devices{"100.64.0.7:8443": addrOf(selfSigned), "100.64.0.7:9443": addrOf(named), "100.64.0.7:7443": addrOf(misnamed)}.dial, roots, t.Logf)
	https := func(name string, port int, verify bool) map[string]any {
		return with(with(host(name, port, ""), "scheme", "https"), "verify", verify)
	}
	rt.install(mustParse(t, https("insecure", 8443, false), https("checked", 8443, true), https("trusted", 9443, true),
		https("misnamed", 7443, true), https("anyname", 7443, false)))

	if resp, body := get(t, rt, "insecure."+mesh, "/", nil); resp.StatusCode != 200 || body != "self-signed" {
		t.Errorf("verify false: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, rt, "checked."+mesh, "/", nil); resp.StatusCode != 502 || !strings.Contains(body, "--no-verify") || !strings.Contains(body, "mac-mini") {
		t.Errorf("verify true with an untrusted certificate: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, rt, "misnamed."+mesh, "/", nil); resp.StatusCode != 502 || !strings.Contains(body, "--no-verify") {
		t.Errorf("verify true with a trusted certificate for another name: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, rt, "anyname."+mesh, "/", nil); resp.StatusCode != 200 || body != "misnamed" {
		t.Errorf("verify false with a certificate for another name: %d %q", resp.StatusCode, body)
	}
	// Checked against the device's network name, which is also sent as SNI.
	if resp, body := get(t, rt, "trusted."+mesh, "/", nil); resp.StatusCode != 200 || body != "named mac-mini."+mesh {
		t.Errorf("verify true with a trusted certificate: %d %q", resp.StatusCode, body)
	}
}

// listen serves handler on a local port through srv.
func listen(t *testing.T, srv *http.Server, useTLS bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if useTLS {
			srv.ServeTLS(ln, "", "")
		} else {
			srv.Serve(ln)
		}
	}()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func writeCert(t *testing.T, dir string, certPEM, keyPEM []byte, mod time.Time) {
	t.Helper()
	for name, b := range map[string][]byte{"fullchain.pem": certPEM, "privkey.pem": keyPEM} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path+".new", b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path+".new", mod, mod); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".new", path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWebsocketUpgradePassesThrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(w, "not an upgrade", 400)
			return
		}
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		// Echoes lines until the client closes.
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				return
			}
			buf.WriteString("echo " + line)
			buf.Flush()
		}
	}))
	defer backend.Close()

	dir := t.TempDir()
	certPEM, keyPEM, cert := newCert(t, time.Now().Add(-time.Hour), "*."+mesh)
	writeCert(t, dir, certPEM, keyPEM, time.Now())
	rt := newRouter(devices{"100.64.0.7:8080": addrOf(backend)}.dial, nil, t.Logf)
	rt.install(mustParse(t, host("chat", 8080, "/ws")))
	secure, _ := servers(rt, &certificate{certPath: filepath.Join(dir, "fullchain.pem"), keyPath: filepath.Join(dir, "privkey.pem"), every: time.Hour, logf: t.Logf})
	addr := listen(t, secure, true)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "chat." + mesh, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: chat.%s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", mesh)
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("upgrade answered %d", resp.StatusCode)
	}
	for _, msg := range []string{"one", "two"} {
		fmt.Fprintf(conn, "%s\n", msg)
		line, err := r.ReadString('\n')
		if err != nil || line != "echo "+msg+"\n" {
			t.Fatalf("after the upgrade: %q, %v", line, err)
		}
	}
}

func TestStreamsAreNotBuffered(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "second\n")
	}))
	defer backend.Close()
	defer close(release)
	rt := newRouter(devices{"100.64.0.7:8080": addrOf(backend)}.dial, nil, t.Logf)
	rt.install(mustParse(t, host("events", 8080, "")))
	front := httptest.NewServer(rt)
	defer front.Close()
	req, _ := http.NewRequest("GET", front.URL+"/", nil)
	req.Host = "events." + mesh
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("the first event did not arrive while the stream stayed open: %q, %v", line, err)
	}
}

func TestConfigAndHealth(t *testing.T) {
	for _, control := range []string{"", "http://covee.example.com", "https://covee.example.com/path", "https://user@covee.example.com"} {
		t.Setenv("COVEE_CONTROL_URL", control)
		if _, err := load(); err == nil {
			t.Errorf("control URL %q was accepted", control)
		}
	}
	t.Setenv("COVEE_CONTROL_URL", "https://covee.example.com")
	c, err := load()
	want := config{control: "https://covee.example.com", hostname: "hosts", state: "/var/lib/covee-hosts-node",
		hosts: "/etc/covee-hosts/hosts.json", cert: "/run/covee-hosts-tls/fullchain.pem", key: "/run/covee-hosts-tls/privkey.pem"}
	if err != nil || c != want {
		t.Fatalf("defaults = %+v, %v", c, err)
	}
	t.Setenv("COVEE_HOSTS_HOSTNAME", "not.a.label")
	if _, err := load(); err == nil {
		t.Error("a device name with dots was accepted")
	}

	c = config{state: t.TempDir()}
	path := filepath.Join(c.state, healthFile)
	if checkHealth(c) != 1 {
		t.Error("healthy without a health file")
	}
	os.WriteFile(path, []byte("Running\n"), 0o600)
	if checkHealth(c) != 0 {
		t.Error("not healthy while running")
	}
	stale := time.Now().Add(-2 * time.Minute)
	os.Chtimes(path, stale, stale)
	if checkHealth(c) != 1 {
		t.Error("healthy with a stale health file")
	}
	os.WriteFile(path, []byte("NeedsLogin\n"), 0o600)
	if checkHealth(c) != 1 {
		t.Error("healthy while not joined")
	}

	keyFile := filepath.Join(c.state, "join-key")
	if k, err := authKey(keyFile); err != nil || k != "" {
		t.Errorf("no key file = %q, %v", k, err)
	}
	os.WriteFile(keyFile, []byte(" key \n"), 0o600)
	if k, err := authKey(keyFile); err != nil || k != "key" {
		t.Errorf("key file = %q, %v", k, err)
	}
}

func TestPortEightyRedirectsToHTTPS(t *testing.T) {
	rt := newRouter(devices{}.dial, nil, t.Logf)
	rt.install(mustParse(t, host("grafana", 8080, "/x")))
	_, redirect := servers(rt, &certificate{every: time.Hour, logf: t.Logf})
	addr := listen(t, redirect, false)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, hostHeader, path string) *http.Response {
		req, _ := http.NewRequest(method, "http://"+addr+path, nil)
		req.Host = hostHeader
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := do("GET", "Grafana.mesh.covee.io:80", "/a/b?c=d"); resp.StatusCode != 301 || resp.Header.Get("Location") != "https://grafana.mesh.covee.io/a/b?c=d" {
		t.Errorf("GET: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := do("POST", "grafana.mesh.covee.io", "/form"); resp.StatusCode != 308 || resp.Header.Get("Location") != "https://grafana.mesh.covee.io/form" {
		t.Errorf("POST: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := do("GET", "elsewhere.example", "/"); resp.StatusCode != 404 || resp.Header.Get("Location") != "" {
		t.Errorf("unknown name: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestReloadKeepsTheLastGoodHosts(t *testing.T) {
	backend := echo()
	defer backend.Close()
	rt := newRouter(devices{"100.64.0.7:8080": addrOf(backend)}.dial, nil, t.Logf)
	path := filepath.Join(t.TempDir(), "hosts.json")
	f := &hostsFile{path: path}
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	write := func(raw []byte, mod time.Time) {
		t.Helper()
		if err := os.WriteFile(path+".new", raw, 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(path+".new", mod, mod)
		if err := os.Rename(path+".new", path); err != nil {
			t.Fatal(err)
		}
	}
	serves := func(name string) bool {
		resp, _ := get(t, rt, name+"."+mesh, "/", nil)
		return resp.StatusCode == 200
	}
	base := time.Now().Add(-time.Hour)

	followHosts(context.Background(), f, rt, 0, logf) // no file yet: no hosts
	if serves("grafana") {
		t.Fatal("served a host without a hosts file")
	}
	write(hostsJSON(t, host("grafana", 8080, "")), base)
	followHosts(context.Background(), f, rt, 0, logf)
	if !serves("grafana") {
		t.Fatal("the hosts file was not loaded")
	}
	route := rt.lookup("grafana." + mesh)

	write([]byte(`{"hosts": [{"name": "grafana.mesh.covee.io", "address": "8.8.8.8"`), base.Add(time.Second))
	followHosts(context.Background(), f, rt, 0, logf)
	followHosts(context.Background(), f, rt, 0, logf)
	if !serves("grafana") {
		t.Fatal("a malformed file replaced the hosts served")
	}
	if n := strings.Count(strings.Join(logged, "\n"), "keeping the hosts served"); n != 1 {
		t.Fatalf("the bad file was reported %d times: %v", n, logged)
	}

	write(hostsJSON(t, host("grafana", 8080, ""), host("wiki", 8080, "")), base.Add(2*time.Second))
	followHosts(context.Background(), f, rt, 0, logf)
	if !serves("grafana") || !serves("wiki") {
		t.Fatal("the corrected file was not loaded")
	}
	if rt.lookup("grafana."+mesh) != route {
		t.Fatal("an unchanged host lost its route")
	}

	os.Remove(path)
	followHosts(context.Background(), f, rt, 0, logf)
	if serves("grafana") || serves("wiki") {
		t.Fatal("a removed hosts file must mean no hosts")
	}
}

func TestCertificateIsReloadedWhenReplaced(t *testing.T) {
	dir := t.TempDir()
	first := time.Now().Add(-2 * time.Hour)
	certA, keyA, _ := newCert(t, first, "*."+mesh)
	writeCert(t, dir, certA, keyA, first)
	c := &certificate{certPath: filepath.Join(dir, "fullchain.pem"), keyPath: filepath.Join(dir, "privkey.pem"), every: time.Hour, logf: t.Logf}
	notBefore := func() time.Time {
		t.Helper()
		got, err := c.get(nil)
		if err != nil {
			t.Fatal(err)
		}
		return got.Leaf.NotBefore
	}
	if !notBefore().Equal(first.Truncate(time.Second)) {
		t.Fatal("the first certificate was not served")
	}

	second := time.Now().Add(-time.Hour)
	certB, keyB, _ := newCert(t, second, "*."+mesh)
	writeCert(t, dir, certB, keyB, second)
	if !notBefore().Equal(first.Truncate(time.Second)) {
		t.Fatal("the files were looked at again before the interval passed")
	}
	c.mu.Lock()
	c.checked = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()
	if !notBefore().Equal(second.Truncate(time.Second)) {
		t.Fatal("the replaced certificate was not loaded")
	}

	// Only the certificate replaced, not yet its key: the pair does not match,
	// and the certificate in use stays.
	certC, _, _ := newCert(t, time.Now(), "*."+mesh)
	os.WriteFile(c.certPath, certC, 0o600)
	os.Chtimes(c.certPath, time.Now(), time.Now())
	c.mu.Lock()
	c.checked = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()
	if !notBefore().Equal(second.Truncate(time.Second)) {
		t.Fatal("a mismatched pair replaced the certificate in use")
	}

	missing := &certificate{certPath: filepath.Join(dir, "none.pem"), keyPath: filepath.Join(dir, "none.key"), every: time.Hour, logf: t.Logf}
	if _, err := missing.get(nil); err == nil {
		t.Fatal("served without a certificate")
	}
}

func TestConnectionsAreCapped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := &limitListener{Listener: ln, slots: make(chan struct{}, 1)}
	defer limited.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	first, _ := net.Dial("tcp", ln.Addr().String())
	defer first.Close()
	held := <-accepted
	second, _ := net.Dial("tcp", ln.Addr().String())
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a connection over the cap was not closed: %v", err)
	}
	held.Close()
	third, _ := net.Dial("tcp", ln.Addr().String())
	defer third.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("a closed connection did not free its slot")
	}
}
