// Command covee-hosts-node serves network-only hosts: names such as
// grafana.<mesh domain> that open a service on a device in the network.
//
// It joins the network's own coordinator as the tagged device "hosts" (tsnet,
// entirely in user space). The coordinator's DNS points every host name at
// this device. It listens in the network on port 443, with the network's
// public certificate (which covers every name under the mesh domain), and
// passes each request by its Host header to the device, port and path that
// name stands for, reached through the network. Port 80 sends browsers to
// https. Nothing here is reachable from the internet: only devices in the
// network that the access policy lets reach tag:covee-hosts can connect, and
// this device reaches only the targets the policy grants it.
//
//	COVEE_CONTROL_URL              the coordinator, for example https://covee.example.com
//	COVEE_HOSTS_HOSTNAME           the device name (default hosts)
//	COVEE_HOSTS_NODE_STATE         state directory (default /var/lib/covee-hosts-node)
//	COVEE_HOSTS_NODE_AUTHKEY_FILE  one-time tagged key, needed only to join the first time
//	COVEE_HOSTS_FILE               the hosts served (default /etc/covee-hosts/hosts.json)
//	COVEE_HOSTS_CERT               certificate chain (default /run/covee-hosts-tls/fullchain.pem)
//	COVEE_HOSTS_KEY                its private key (default /run/covee-hosts-tls/privkey.pem)
//	COVEE_HOSTS_NODE_VERBOSE=1     also print the networking library's own log
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"
)

const (
	// maxConnections caps the connections open at once, on both ports together.
	maxConnections = 256
	maxHeaderBytes = 64 << 10
	// How often the hosts file and the certificate files are looked at.
	hostsEvery = 2 * time.Second
	certEvery  = 10 * time.Second
)

type config struct {
	control, hostname, state, keyFile, hosts, cert, key string
}

func load() (config, error) {
	c := config{
		control:  os.Getenv("COVEE_CONTROL_URL"),
		hostname: envOr("COVEE_HOSTS_HOSTNAME", "hosts"),
		state:    envOr("COVEE_HOSTS_NODE_STATE", "/var/lib/covee-hosts-node"),
		keyFile:  os.Getenv("COVEE_HOSTS_NODE_AUTHKEY_FILE"),
		hosts:    envOr("COVEE_HOSTS_FILE", "/etc/covee-hosts/hosts.json"),
		cert:     envOr("COVEE_HOSTS_CERT", "/run/covee-hosts-tls/fullchain.pem"),
		key:      envOr("COVEE_HOSTS_KEY", "/run/covee-hosts-tls/privkey.pem"),
	}
	u, err := url.Parse(c.control)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return c, errors.New("COVEE_CONTROL_URL must be the coordinator's https:// origin")
	}
	if c.hostname == "" || strings.ContainsAny(c.hostname, " ./") {
		return c, errors.New("COVEE_HOSTS_HOSTNAME must be a single DNS label")
	}
	return c, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// authKey reads the one-time key, if present. A device that already joined
// keeps its identity in the state directory and needs no key.
func authKey(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func main() {
	health := flag.Bool("health", false, "exit 0 when this device is connected to the network")
	flag.Parse()
	c, err := load()
	if err != nil {
		log.Fatal(err)
	}
	if *health {
		os.Exit(checkHealth(c))
	}
	key, err := authKey(c.keyFile)
	if err != nil {
		log.Fatalf("reading the join key: %v", err)
	}
	if err := run(c, key); err != nil {
		log.Fatal(err)
	}
}

func run(c config, key string) error {
	// Tailscale pins its sockets to the default-route interface so they cannot
	// loop through its own tunnel. This node has no tunnel (tsnet runs in user
	// space), and its sockets must follow the container's routes: the coordinator
	// is on the internal backend network, not on the default route. Plain routing
	// is correct here, and needs no capabilities.
	netns.SetEnabled(false)
	srv := &tsnet.Server{Dir: c.state, Hostname: c.hostname, ControlURL: c.control, AuthKey: key,
		Logf: func(string, ...any) {}, UserLogf: log.Printf}
	if os.Getenv("COVEE_HOSTS_NODE_VERBOSE") == "1" {
		srv.Logf = log.Printf
	}
	defer srv.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, srv, c)
}

// serve brings the device up in the network and serves the hosts until ctx ends.
func serve(ctx context.Context, srv *tsnet.Server, c config) error {
	cert := &certificate{certPath: c.cert, keyPath: c.key, every: certEvery, logf: log.Printf}
	cert.get(nil) // loads it now, so a missing certificate shows in the log at start
	if _, err := srv.Up(ctx); err != nil {
		return fmt.Errorf("joining the network: %w", err)
	}
	rt := newRouter(networkDial(srv), nil, log.Printf)
	hosts := &hostsFile{path: c.hosts}
	followHosts(ctx, hosts, rt, 0, log.Printf)
	// Tells the deployment tool this device has joined and needs no new key.
	if err := os.WriteFile(filepath.Join(c.state, joinedFile), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		log.Printf("recording the join: %v", err)
	}
	ln443, err := srv.Listen("tcp", ":443")
	if err != nil {
		return fmt.Errorf("listening on the network: %w", err)
	}
	ln80, err := srv.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("listening on the network: %w", err)
	}
	go recordHealth(ctx, srv, c.state)
	go followHosts(ctx, hosts, rt, hostsEvery, log.Printf)

	slots := make(chan struct{}, maxConnections)
	secure, redirect := servers(rt, cert)
	errc := make(chan error, 2)
	go func() { errc <- secure.ServeTLS(&limitListener{Listener: ln443, slots: slots}, "", "") }()
	go func() { errc <- redirect.Serve(&limitListener{Listener: ln80, slots: slots}) }()
	log.Printf("hosts reachable in the network through %s, ports 443 and 80", c.hostname)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	secure.Shutdown(shutdown)
	redirect.Shutdown(shutdown)
	// Upgraded connections (websockets) are not waited for by Shutdown.
	secure.Close()
	redirect.Close()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("serving: %w", serveErr)
	}
	return nil
}

// networkDial reaches targets through the network's own stack, so the access
// policy applies, and only while they are current devices. srv.Dial is not used
// because it falls back to the operating system for an address it finds no
// device for. Connecting directly also means a device removed just after the
// check is dropped by the network instead of reaching that fallback. This
// device's own addresses are refused too, as a target there would loop.
//
// The lookup is the one srv.Dial uses, an in-memory map; it runs when a new
// connection to a target is needed, not on every request.
func networkDial(srv *tsnet.Server) dialFunc {
	dialer := srv.Sys().Dialer.Get()
	return peersOnly(func(ip netip.Addr) bool {
		v4, v6 := srv.TailscaleIPs()
		return ip != v4 && ip != v6 && dialer.UseNetstackForIP(ip)
	}, dialer.NetstackDialTCP)
}

// servers returns the https server for port 443 and the redirecting server
// for port 80. Neither has a write timeout, so long-lived streams and
// websockets stay open.
func servers(rt *router, cert *certificate) (secure, redirect *http.Server) {
	secure = &http.Server{
		Handler: rt,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: cert.get,
			NextProtos:     []string{"h2", "http/1.1"},
		},
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	redirect = &http.Server{
		Handler:           http.HandlerFunc(rt.redirect),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	return secure, redirect
}

// followHosts serves the hosts in the hosts file and keeps them current,
// looking at the file every `every`; with every 0 it looks once and returns.
func followHosts(ctx context.Context, f *hostsFile, rt *router, every time.Duration, logf func(string, ...any)) {
	last := ""
	for {
		hosts, changed, err := f.check()
		switch {
		case err != nil:
			if msg := err.Error(); msg != last {
				logf("hosts: %v; keeping the hosts served", err)
				last = msg
			}
		case changed:
			last = ""
			rt.install(hosts)
			logf("hosts: serving %d", len(hosts))
		}
		if every == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// The running instance records its state for the container health check,
// because a second tsnet instance must not open the same state directory.
const healthFile = "covee-health"

// joinedFile is written once the device has joined the network.
const joinedFile = "covee-joined"

func recordHealth(ctx context.Context, srv *tsnet.Server, dir string) {
	lc, err := srv.LocalClient()
	if err != nil {
		log.Printf("health: %v", err)
		return
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		state := "Unknown"
		if st, err := lc.StatusWithoutPeers(ctx); err == nil {
			state = st.BackendState
		}
		_ = os.WriteFile(filepath.Join(dir, healthFile), []byte(state+"\n"), 0o600)
		select {
		case <-ctx.Done():
			os.Remove(filepath.Join(dir, healthFile))
			return
		case <-tick.C:
		}
	}
}

func checkHealth(c config) int {
	path := filepath.Join(c.state, healthFile)
	info, err := os.Stat(path)
	b, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || time.Since(info.ModTime()) > 90*time.Second || strings.TrimSpace(string(b)) != ipn.Running.String() {
		fmt.Fprintln(os.Stderr, "not connected to the network")
		return 1
	}
	return 0
}
