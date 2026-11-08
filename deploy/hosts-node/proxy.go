package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dialFunc opens a connection to a target; in the running node it is
// peersOnly over the network's own stack (networkDial).
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

const dialTimeout = 10 * time.Second

// errNotADevice refuses an address that is not a current device: one that was
// removed from the network, for example, while the hosts file still names it.
var errNotADevice = errors.New("not a device in the network now")

// peersOnly dials address with connect if isPeer says it is a current device,
// and refuses it otherwise. The caller's connect must stay inside the network:
// the general network dialer hands an address it finds no device for to the
// operating system, which would send the request, cookies and all, to whatever
// holds that address on the server's own upstream.
func peersOnly(isPeer func(netip.Addr) bool, connect func(context.Context, netip.AddrPort) (net.Conn, error)) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		target, err := netip.ParseAddrPort(address)
		if err != nil || network != "tcp" {
			return nil, fmt.Errorf("%s %s: %w", network, address, errNotADevice)
		}
		if !isPeer(target.Addr()) {
			return nil, fmt.Errorf("%s: %w", target.Addr(), errNotADevice)
		}
		return connect(ctx, target)
	}
}

// router serves each request by its Host header, passing it on to the
// device, port and path that host names.
type router struct {
	dial  dialFunc
	roots *x509.CertPool // nil: the system's roots
	logf  func(string, ...any)

	mu     sync.Mutex // serializes install
	routes atomic.Pointer[map[string]*route]
}

type route struct {
	host      Host
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

func newRouter(dial dialFunc, roots *x509.CertPool, logf func(string, ...any)) *router {
	rt := &router{dial: dial, roots: roots, logf: logf}
	rt.routes.Store(&map[string]*route{})
	return rt
}

// install replaces the hosts served. A host that is unchanged keeps its
// route, and with it its open connections to the device.
func (rt *router) install(hosts []Host) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	old := make(map[Host]*route)
	for _, r := range *rt.routes.Load() {
		old[r.host] = r
	}
	next := make(map[string]*route, len(hosts))
	for _, h := range hosts {
		if r, ok := old[h]; ok {
			next[h.Name] = r
			delete(old, h)
			continue
		}
		next[h.Name] = rt.newRoute(h)
	}
	rt.routes.Store(&next)
	for _, r := range old {
		r.transport.CloseIdleConnections()
	}
}

func (rt *router) lookup(name string) *route {
	return (*rt.routes.Load())[name]
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := hostName(r.Host)
	route := rt.lookup(name)
	if route == nil {
		plain(w, http.StatusNotFound, "No host named "+name+" in this network.\n")
		return
	}
	if route.host.Path != "" && climbsOut(r.URL.Path) {
		plain(w, http.StatusBadRequest, "This address leaves the path this host stands for.\n")
		return
	}
	route.proxy.ServeHTTP(w, r)
}

// climbsOut reports whether a decoded request path has a ".." segment, which
// joined to a host's path would leave it. Browsers remove these themselves.
func climbsOut(path string) bool {
	for _, segment := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return true
		}
	}
	return false
}

// redirect answers plain http on port 80 by sending the browser to the same
// address over https. Only names this node serves are redirected.
func (rt *router) redirect(w http.ResponseWriter, r *http.Request) {
	name := hostName(r.Host)
	if rt.lookup(name) == nil {
		plain(w, http.StatusNotFound, "No host named "+name+" in this network.\n")
		return
	}
	code := http.StatusPermanentRedirect // keeps the method and body
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		code = http.StatusMovedPermanently
	}
	w.Header().Set("Location", "https://"+name+r.URL.RequestURI())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
}

// hostName is the name a Host header asks for: without its port or a
// trailing dot, in lowercase.
func hostName(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	return strings.ToLower(host)
}

func plain(w http.ResponseWriter, code int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprint(w, text)
}

func (rt *router) newRoute(h Host) *route {
	target := &url.URL{Scheme: h.Scheme, Host: net.JoinHostPort(h.Address, strconv.Itoa(h.Port))}
	if h.Path != "" {
		// Not url.Parse, which would take a path beginning // for a host. checkPath
		// has accepted the escapes; RawPath keeps them exactly as written.
		if plain, err := url.PathUnescape(h.Path); err == nil {
			target.Path, target.RawPath = plain, h.Path
		}
	}
	device := h.Device
	if device == "" {
		device = h.Address
	}
	t := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			return rt.dial(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
	}
	if h.Scheme == "https" {
		t.TLSClientConfig = rt.targetTLS(h)
	}
	proxy := &httputil.ReverseProxy{
		Transport: t,
		// Before Rewrite runs, the proxy has removed hop-by-hop headers and any
		// Forwarded, X-Forwarded-For, -Host and -Proto the client sent.
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Joins the target path and the request path with exactly one slash.
			pr.SetURL(target)
			// The proxy drops query parameters it cannot parse, for the sake of
			// proxies that read them. This one does not, so the service gets
			// the query exactly as it was sent.
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			// The service sees the name it was opened by, as with Cloudflare.
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				rt.logf("%s: %s port %d: %v", h.Name, device, h.Port, err)
			}
			var bad *certificateError
			if errors.As(err, &bad) {
				plain(w, http.StatusBadGateway, fmt.Sprintf("Could not trust the certificate of the service on %s, port %d. If it uses a self-signed certificate, add this host with --no-verify.\n", device, h.Port))
				return
			}
			plain(w, http.StatusBadGateway, fmt.Sprintf("Could not reach %s on port %d. Check that the device is online and the service is running.\n", device, h.Port))
		},
	}
	return &route{host: h, transport: t, proxy: proxy}
}

// certificateError is a target's certificate failing its check.
type certificateError struct{ reason string }

func (e *certificateError) Error() string { return "the service's certificate: " + e.reason }

// targetTLS is how an https target is checked. Without verification any
// certificate is accepted (services with their own self-signed one). With it,
// the certificate must chain to a trusted root and be valid for the device's
// network name (device.<mesh domain>), its plain device name, or its address.
func (rt *router) targetTLS(h Host) *tls.Config {
	names := []string{h.Address}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if h.Device != "" {
		_, base, _ := strings.Cut(h.Name, ".")
		cfg.ServerName = h.Device + "." + base
		names = []string{cfg.ServerName, h.Device, h.Address}
	}
	// The chain and the name are checked in VerifyConnection instead, because
	// more than one name is acceptable.
	cfg.InsecureSkipVerify = true
	if !h.Verify {
		return cfg
	}
	roots := rt.roots
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return &certificateError{"none was sent"}
		}
		leaf := cs.PeerCertificates[0]
		opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(opts); err != nil {
			return &certificateError{err.Error()}
		}
		for _, n := range names {
			if leaf.VerifyHostname(n) == nil {
				return nil
			}
		}
		return &certificateError{"not valid for " + strings.Join(names, ", ")}
	}
	return cfg
}

// limitListener accepts at most cap(slots) connections at once, shared by
// every listener given the same slots; a connection beyond that is closed
// at once.
type limitListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &slotConn{Conn: c, slots: l.slots}, nil
		default:
			c.Close()
		}
	}
}

type slotConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
