// Package ingress exposes only the coordinator's client protocol publicly.
// Administration uses a separate listener and a different fixed upstream.
package ingress

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const maxRequestBytes = 1 << 20

type Config struct {
	ControlHost, ControlPort, AdminHost, AdminPort string
	HeadscaleURL, ManagementURL, CAFile            string
	IdentityURL                                    string
	IdentityOnly                                   bool
	ControlListen, AdminListen                     string
	// MeshHost, when set, serves the admin console at https://MeshHost on
	// MeshListen. That listener is never published: only the console node,
	// which joins the network as that device, connects to it.
	MeshHost, MeshListen            string
	ControlCertFile, ControlKeyFile string
	AdminCertFile, AdminKeyFile     string
}

func ConfigFromEnv() (Config, error) {
	c := Config{
		ControlHost: os.Getenv("COVEE_CONTROL_HOST"), ControlPort: env("COVEE_PUBLIC_PORT", "443"),
		AdminHost: os.Getenv("COVEE_ADMIN_HOST"), AdminPort: env("COVEE_ADMIN_PORT", "8444"),
		HeadscaleURL:  env("COVEE_HEADSCALE_UPSTREAM", "https://headscale:8443"),
		ManagementURL: env("COVEE_MANAGEMENT_UPSTREAM", "https://management:8445"),
		IdentityURL:   os.Getenv("COVEE_IDENTITY_UPSTREAM"),
		IdentityOnly:  os.Getenv("COVEE_IDENTITY_ONLY") == "true",
		CAFile:        env("COVEE_INTERNAL_CA_FILE", "/run/covee/internal-ca.crt"),
		ControlListen: env("COVEE_INGRESS_CONTROL_LISTEN", ":8443"), AdminListen: env("COVEE_INGRESS_ADMIN_LISTEN", ":8444"),
		MeshHost: os.Getenv("COVEE_MESH_CONSOLE_HOST"), MeshListen: env("COVEE_INGRESS_MESH_LISTEN", ":8447"),
		ControlCertFile: env("COVEE_CONTROL_CERT_FILE", "/run/covee/ingress-control.crt"),
		ControlKeyFile:  env("COVEE_CONTROL_KEY_FILE", "/run/covee/ingress-control.key"),
		AdminCertFile:   env("COVEE_ADMIN_CERT_FILE", "/run/covee/ingress-admin.crt"),
		AdminKeyFile:    env("COVEE_ADMIN_KEY_FILE", "/run/covee/ingress-admin.key"),
	}
	return c, c.validate()
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func (c Config) validate() error {
	for _, host := range []string{c.ControlHost, c.AdminHost} {
		if !validHost(host) {
			return errors.New("control and administration hosts must be plain ASCII DNS hostnames or IPv4 addresses")
		}
	}
	if c.MeshHost != "" && (!validHost(c.MeshHost) || strings.EqualFold(c.MeshHost, c.ControlHost) || strings.EqualFold(c.MeshHost, c.AdminHost)) {
		return errors.New("the in-network console host must be its own plain DNS hostname")
	}
	for _, port := range []string{c.ControlPort, c.AdminPort} {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return errors.New("public and administration ports must be canonical decimal ports")
		}
	}
	for _, target := range []string{c.HeadscaleURL, c.ManagementURL} {
		if _, err := upstreamURL(target); err != nil {
			return err
		}
	}
	if c.IdentityURL != "" {
		if _, err := upstreamURL(c.IdentityURL); err != nil {
			return err
		}
	}
	if c.IdentityOnly && c.IdentityURL == "" {
		return errors.New("identity-only ingress requires a configured identity upstream")
	}
	return nil
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func upstreamURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("both fixed upstreams require an HTTPS origin without credentials, path, query or fragment")
	}
	u.Path = ""
	return u, nil
}

type Gateway struct {
	control, admin, mesh http.Handler
	transport            *http.Transport
}

func New(c Config) (*Gateway, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, errors.New("internal CA could not be read")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("internal CA contains no certificates")
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10, MaxConnsPerHost: 256, MaxIdleConns: 64, MaxIdleConnsPerHost: 32,
		IdleConnTimeout: 60 * time.Second, ForceAttemptHTTP2: false,
	}
	controlURL, _ := upstreamURL(c.HeadscaleURL)
	adminURL, _ := upstreamURL(c.ManagementURL)
	g := &Gateway{transport: transport}
	control := proxy(controlURL, transport)
	routes := publicRoute
	if c.IdentityURL != "" {
		identityURL, _ := upstreamURL(c.IdentityURL)
		identity := proxy(identityURL, transport)
		routes = func(r *http.Request) bool { return publicRoute(r) || identityRoute(r) }
		coordinator := control
		control = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if identityRoute(r) {
				identity.ServeHTTP(w, r)
				return
			}
			coordinator.ServeHTTP(w, r)
		})
	}
	if c.IdentityOnly {
		routes = identityRoute
	}
	g.control = guard(c.ControlHost, c.ControlPort, routes, control, 256)
	administration := adminRoute
	if c.IdentityOnly {
		administration = func(*http.Request) bool { return false }
	}
	g.admin = guard(c.AdminHost, c.AdminPort, administration, proxy(adminURL, transport), 32)
	if c.MeshHost != "" && !c.IdentityOnly {
		// The browser reaches it as https://MeshHost (port 443 in the network).
		g.mesh = guard(c.MeshHost, "443", adminRoute, proxy(adminURL, transport), 32)
	}
	return g, nil
}

func (g *Gateway) ControlHandler() http.Handler { return g.control }
func (g *Gateway) AdminHandler() http.Handler   { return g.admin }

// MeshHandler serves the in-network console, or is nil when it is not configured.
func (g *Gateway) MeshHandler() http.Handler { return g.mesh }
func (g *Gateway) Close()                    { g.transport.CloseIdleConnections() }

func proxy(target *url.URL, transport *http.Transport) http.Handler {
	p := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			// Never trust values from the public request or an ambient proxy.
			for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Real-IP", "True-Client-IP", "X-Original-URL", "X-Rewrite-URL", "Proxy-Authorization"} {
				r.Out.Header.Del(header)
			}
			r.SetXForwarded()
			r.Out.Header.Set("X-Forwarded-Proto", "https")
			if host, _, err := net.SplitHostPort(r.In.RemoteAddr); err == nil {
				r.Out.Header.Set("X-Real-IP", host)
				r.Out.Header.Set("True-Client-IP", host)
			}
		},
		Transport: transport,
		ErrorLog:  log.New(io.Discard, "", 0), // Transport errors may contain enrollment URLs.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(upgradeWriter{ResponseWriter: w}, r)
	})
}

// net/http may read the beginning of an upgraded protocol while parsing the
// HTTP request. ReverseProxy copies from the hijacked connection directly;
// retain its buffered reader so those already-received bytes are not lost.
type upgradeWriter struct{ http.ResponseWriter }

func (w upgradeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w upgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return bufferedConn{Conn: conn, reader: rw.Reader}, rw, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c bufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return http.ErrNotSupported
}

func guard(host, port string, route func(*http.Request) bool, next http.Handler, capacity int) http.Handler {
	slots := make(chan struct{}, capacity)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if !expectedHost(r.Host, host, port) {
			http.Error(w, "unexpected host", http.StatusMisdirectedRequest)
			return
		}
		if !canonicalPath(r) || !route(r) {
			http.NotFound(w, r)
			return
		}
		if len(r.RequestURI) > 16<<10 || r.ContentLength > maxRequestBytes {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "capacity unavailable", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

func expectedHost(got, host, port string) bool {
	return strings.EqualFold(got, net.JoinHostPort(host, port)) || port == "443" && strings.EqualFold(got, host)
}

func canonicalPath(r *http.Request) bool {
	p := r.URL.Path
	if r.URL.IsAbs() || r.URL.Opaque != "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\%") || strings.Contains(r.URL.EscapedPath(), "%") || strings.Contains(p, "//") || path.Clean(p) != p {
		return false
	}
	for _, ch := range p {
		if ch <= 0x20 || ch >= 0x7f {
			return false
		}
	}
	return true
}

func publicRoute(r *http.Request) bool {
	method, p := r.Method, r.URL.Path
	switch p {
	case "/ts2021":
		return method == "GET" || method == "POST"
	case "/key", "/oidc/callback", "/derp", "/bootstrap-dns":
		return method == "GET"
	case "/derp/probe", "/derp/latency-check":
		return method == "GET" || method == "HEAD"
	case "/machine/ping-response":
		return method == "HEAD"
	}
	for _, prefix := range []string{"/register/confirm/", "/register/", "/auth/"} {
		if strings.HasPrefix(p, prefix) {
			return validAuthID(strings.TrimPrefix(p, prefix)) && (method == "GET" || prefix == "/register/confirm/" && method == "POST")
		}
	}
	return false
}

func validAuthID(id string) bool {
	const prefix = "hskey-authreq-"
	if !strings.HasPrefix(id, prefix) || len(id) != 38 {
		return false
	}
	for _, ch := range id[len(prefix):] {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

// The broker has a separate fixed backend. Never expose its whole URL prefix,
// health route, or any administration path through the public listener.
func identityRoute(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	switch r.URL.Path {
	case "/identity/.well-known/openid-configuration", "/identity/jwks", "/identity/authorize", "/identity/userinfo":
		return r.Method == http.MethodGet
	case "/identity/select", "/identity/token", "/identity/callback/apple":
		return r.Method == http.MethodPost
	case "/identity/callback/entra", "/identity/callback/google":
		return r.Method == http.MethodGet
	// Local Covee accounts: sign-in with a passkey or password, and invitations.
	case "/identity/local/app.js", "/identity/local/invite":
		return r.Method == http.MethodGet
	case "/identity/local/passkey/options", "/identity/local/passkey/finish", "/identity/local/password",
		"/identity/local/invite/info", "/identity/local/invite/passkey/options", "/identity/local/invite/passkey/finish",
		"/identity/local/invite/totp", "/identity/local/invite/password":
		return r.Method == http.MethodPost
	}
	return false
}

func adminRoute(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	switch r.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}
