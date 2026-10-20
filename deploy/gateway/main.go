// Command covee-gateway carries members' traffic from the network to places
// only the server can reach, such as a cloud provider's private networks, or
// out through the server's own internet address for allowlists.
//
// It joins the network's own coordinator as the tagged device "gateway",
// entirely in user space, and offers the routes the admin console chose
// (written by the management service to COVEE_GATEWAY_ROUTES). Traffic for
// those routes is forwarded by connecting from this container, so it leaves
// with the server's address. Which members may use each route is the
// coordinator's access policy, also kept by the console.
//
//	COVEE_CONTROL_URL           the coordinator, for example https://covee.example.com
//	COVEE_GATEWAY_HOSTNAME      the device name (default gateway)
//	COVEE_GATEWAY_STATE         state directory (default /var/lib/covee-gateway)
//	COVEE_GATEWAY_AUTHKEY_FILE  one-time tagged key, needed only to join the first time
//	COVEE_GATEWAY_ROUTES        the routes file (default /etc/covee-gateway/routes.json)
//	COVEE_GATEWAY_VERBOSE=1     also print the networking library's own log
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tailscale.com/control/controlclient"
	_ "tailscale.com/feature/condregister"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
)

type config struct {
	control, hostname, state, keyFile, routes string
}

func load() (config, error) {
	c := config{
		control:  os.Getenv("COVEE_CONTROL_URL"),
		hostname: envOr("COVEE_GATEWAY_HOSTNAME", "gateway"),
		state:    envOr("COVEE_GATEWAY_STATE", "/var/lib/covee-gateway"),
		keyFile:  os.Getenv("COVEE_GATEWAY_AUTHKEY_FILE"),
		routes:   envOr("COVEE_GATEWAY_ROUTES", "/etc/covee-gateway/routes.json"),
	}
	u, err := url.Parse(c.control)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return c, errors.New("COVEE_CONTROL_URL must be the coordinator's https:// origin")
	}
	if c.hostname == "" || strings.ContainsAny(c.hostname, " ./") {
		return c, errors.New("COVEE_GATEWAY_HOSTNAME must be a single DNS label")
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
		os.Exit(checkHealth(c.state))
	}
	key, err := authKey(c.keyFile)
	if err != nil {
		log.Fatalf("reading the join key: %v", err)
	}
	// Tailscale pins its sockets to the default-route interface so they cannot
	// loop through its own tunnel. This device has no tunnel (it runs in user
	// space), so plain routing is correct and needs no capabilities.
	netns.SetEnabled(false)
	logf := logger.Discard
	if os.Getenv("COVEE_GATEWAY_VERBOSE") == "1" {
		logf = log.Printf
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	gw, err := start(ctx, c, key, logf)
	if err != nil {
		log.Fatal(err)
	}
	defer gw.close()
	if err := gw.waitRunning(ctx, 2*time.Minute); err != nil {
		log.Fatal(err)
	}
	// Tells the deployment tool this device has joined and needs no new key.
	if err := os.WriteFile(filepath.Join(c.state, joinedFile), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		log.Printf("recording the join: %v", err)
	}
	log.Printf("gateway connected to the network as %s", c.hostname)
	go recordHealth(ctx, gw.lb, c.state)
	gw.followRoutes(ctx, c.routes, 10*time.Second, log.Printf)
}

type gateway struct {
	lb     *ipnlocal.LocalBackend
	closer []func()
}

// start brings the device up in user space, with packets for its offered
// routes handled by netstack, which connects to each destination itself.
func start(ctx context.Context, c config, key string, logf logger.Logf) (*gateway, error) {
	gw := &gateway{}
	fail := func(err error) (*gateway, error) { gw.close(); return nil, err }
	if err := os.MkdirAll(c.state, 0o700); err != nil {
		return fail(err)
	}
	sys := tsd.NewSystem()
	st, err := store.New(logf, filepath.Join(c.state, "tailscaled.state"))
	if err != nil {
		return fail(fmt.Errorf("opening the device state: %w", err))
	}
	sys.Set(st)
	nm, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return fail(err)
	}
	gw.closer = append(gw.closer, func() { nm.Close() })
	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	gw.closer = append(gw.closer, func() { dialer.Close() })
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		EventBus: sys.Bus.Get(), NetMon: nm, Dialer: dialer, SetSubsystem: sys.Set,
		ControlKnobs: sys.ControlKnobs(), HealthTracker: sys.HealthTracker.Get(), Metrics: sys.UserMetricsRegistry(),
	})
	if err != nil {
		return fail(fmt.Errorf("starting the packet engine: %w", err))
	}
	sys.Set(eng)
	sys.HealthTracker.Get().SetMetricsRegistry(sys.UserMetricsRegistry())
	ns, err := netstack.Create(logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		eng.Close()
		return fail(fmt.Errorf("starting the forwarder: %w", err))
	}
	sys.Tun.Get().Start()
	sys.Set(ns)
	// As tailscaled does in user space: this device's own addresses and its
	// offered routes are handled here, and forwarded by dialing out.
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	gw.closer = append(gw.closer, func() { ns.Close() })
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, controlclient.LoginDefault|controlclient.LocalBackendStartKeyOSNeutral)
	if err != nil {
		return fail(fmt.Errorf("starting the backend: %w", err))
	}
	lb.SetVarRoot(c.state)
	gw.lb = lb
	gw.closer = append(gw.closer, lb.Shutdown)
	if err := ns.Start(lb); err != nil {
		return fail(fmt.Errorf("starting the forwarder: %w", err))
	}
	routes, err := readRoutes(c.routes)
	if err != nil {
		logf("routes: %v; offering none until the file is valid", err)
	}
	prefs := ipn.NewPrefs()
	prefs.Hostname = c.hostname
	prefs.ControlURL = c.control
	prefs.WantRunning = true
	prefs.CorpDNS = false // the gateway resolves names with the server's own DNS
	prefs.RouteAll = false
	prefs.AdvertiseRoutes = routes
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs, AuthKey: key}); err != nil {
		return fail(fmt.Errorf("starting the backend: %w", err))
	}
	if lb.State() == ipn.NeedsLogin {
		if key == "" {
			return fail(errors.New("this device has not joined the network and has no join key"))
		}
		// Registers with the key given to Start, as tsnet does.
		if err := lb.StartLoginInteractive(ctx); err != nil {
			return fail(fmt.Errorf("joining the network: %w", err))
		}
	}
	return gw, nil
}

func (gw *gateway) close() {
	for i := len(gw.closer) - 1; i >= 0; i-- {
		gw.closer[i]()
	}
	gw.closer = nil
}

func (gw *gateway) waitRunning(ctx context.Context, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		if gw.lb.State() == ipn.Running {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not connected to the network after %s (state %s)", limit, gw.lb.State())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// followRoutes offers the routes in path and keeps them current. An invalid
// file is reported and the routes on offer stay as they were.
func (gw *gateway) followRoutes(ctx context.Context, path string, every time.Duration, logf logger.Logf) {
	last := ""
	for {
		routes, err := readRoutes(path)
		switch {
		case err != nil:
			if msg := err.Error(); msg != last {
				logf("routes: %v; keeping the routes on offer", err)
				last = msg
			}
		default:
			last = ""
			if !samePrefixes(gw.lb.Prefs().AdvertiseRoutes().AsSlice(), routes) {
				_, err := gw.lb.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{AdvertiseRoutes: routes}, AdvertiseRoutesSet: true})
				if err != nil {
					logf("routes: offering %d routes failed: %v", len(routes), err)
				} else {
					logf("routes: offering %d", len(routes))
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// The running instance records its state for the container health check,
// because a second instance must not open the same state directory.
const healthFile = "covee-health"

// joinedFile is written once the device has joined the network.
const joinedFile = "covee-joined"

func recordHealth(ctx context.Context, lb *ipnlocal.LocalBackend, dir string) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		_ = os.WriteFile(filepath.Join(dir, healthFile), []byte(lb.State().String()+"\n"), 0o600)
		select {
		case <-ctx.Done():
			os.Remove(filepath.Join(dir, healthFile))
			return
		case <-tick.C:
		}
	}
}

func checkHealth(dir string) int {
	path := filepath.Join(dir, healthFile)
	info, err := os.Stat(path)
	b, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || time.Since(info.ModTime()) > 90*time.Second || strings.TrimSpace(string(b)) != ipn.Running.String() {
		fmt.Fprintln(os.Stderr, "not connected to the network")
		return 1
	}
	return 0
}
