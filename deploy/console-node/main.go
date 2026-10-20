// Command covee-console-node puts the admin console inside the network.
//
// It joins the network's own coordinator as the tagged device "console"
// (tsnet, entirely in user space) and passes each connection to that device's
// port 443 on to the TLS gateway's network-only console listener. Nothing
// here is reachable from the internet: only devices in the network that the
// access policy lets reach tag:covee-console on port 443 can connect, and the
// console still requires an administrator's sign-in.
//
//	COVEE_CONTROL_URL          the coordinator, for example https://covee.example.com
//	COVEE_CONSOLE_TARGET       the gateway's console listener, for example ingress:8447
//	COVEE_CONSOLE_HOSTNAME     the device name (default console)
//	COVEE_CONSOLE_NODE_STATE   state directory (default /var/lib/covee-console-node)
//	COVEE_CONSOLE_NODE_AUTHKEY_FILE  one-time tagged key, needed only to join the first time
//	COVEE_CONSOLE_NODE_VERBOSE=1     also print the networking library's own log
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"
)

const maxConnections = 64

type config struct {
	control, target, hostname, state, keyFile string
}

func load() (config, error) {
	c := config{
		control:  os.Getenv("COVEE_CONTROL_URL"),
		target:   os.Getenv("COVEE_CONSOLE_TARGET"),
		hostname: envOr("COVEE_CONSOLE_HOSTNAME", "console"),
		state:    envOr("COVEE_CONSOLE_NODE_STATE", "/var/lib/covee-console-node"),
		keyFile:  os.Getenv("COVEE_CONSOLE_NODE_AUTHKEY_FILE"),
	}
	u, err := url.Parse(c.control)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return c, errors.New("COVEE_CONTROL_URL must be the coordinator's https:// origin")
	}
	if _, port, err := net.SplitHostPort(c.target); err != nil || port == "" {
		return c, errors.New("COVEE_CONSOLE_TARGET must be host:port")
	}
	if c.hostname == "" || strings.ContainsAny(c.hostname, " ./") {
		return c, errors.New("COVEE_CONSOLE_HOSTNAME must be a single DNS label")
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
	// Tailscale pins its sockets to the default-route interface so they cannot
	// loop through its own tunnel. This node has no tunnel (tsnet runs in user
	// space) and lives on an internal network without a default route, where
	// that pinning would choose loopback and no connection could leave the
	// container. Plain routing is correct here, and needs no capabilities.
	netns.SetEnabled(false)
	srv := &tsnet.Server{Dir: c.state, Hostname: c.hostname, ControlURL: c.control, AuthKey: key,
		Logf: func(string, ...any) {}, UserLogf: log.Printf}
	if os.Getenv("COVEE_CONSOLE_NODE_VERBOSE") == "1" {
		srv.Logf = log.Printf
	}
	defer srv.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if _, err := srv.Up(ctx); err != nil {
		log.Fatalf("joining the network: %v", err)
	}
	// Tells the deployment tool this device has joined and needs no new key.
	if err := os.WriteFile(c.state+"/"+joinedFile, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		log.Printf("recording the join: %v", err)
	}
	ln, err := srv.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("listening on the network: %v", err)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	go recordHealth(ctx, srv, c.state)
	log.Printf("console reachable in the network as %s, port 443 -> %s", c.hostname, c.target)
	serve(ctx, ln, c.target)
}

// serve passes each accepted connection to target, at most maxConnections at once.
func serve(ctx context.Context, ln net.Listener, target string) {
	slots := make(chan struct{}, maxConnections)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			forward(conn, target)
		}()
	}
}

func forward(client net.Conn, target string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("console listener unavailable: %v", err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if tcp, ok := dst.(interface{ CloseWrite() error }); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
	<-done
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
		_ = os.WriteFile(dir+"/"+healthFile, []byte(state+"\n"), 0o600)
		select {
		case <-ctx.Done():
			os.Remove(dir + "/" + healthFile)
			return
		case <-tick.C:
		}
	}
}

func checkHealth(c config) int {
	path := c.state + "/" + healthFile
	info, err := os.Stat(path)
	b, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || time.Since(info.ModTime()) > 90*time.Second || strings.TrimSpace(string(b)) != ipn.Running.String() {
		fmt.Fprintln(os.Stderr, "not connected to the network")
		return 1
	}
	return 0
}
