package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// A member device opens a host through the hosts node, in a real network of
// three tsnet devices with a local coordinator and relay: the node's own
// listeners, its dialing through the network, and the addresses it sees.
func TestMemberOpensAServiceOnAnotherDevice(t *testing.T) {
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	relay := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	ctl := &testcontrol.Server{DERPMap: relay, Logf: logger.Discard}
	ctl.HTTPTestServer = httptest.NewServer(ctl)
	t.Cleanup(ctl.HTTPTestServer.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	device := func(name string) *tsnet.Server {
		s := &tsnet.Server{Dir: filepath.Join(dir, name), Hostname: name, ControlURL: ctl.HTTPTestServer.URL, Logf: logger.Discard, Ephemeral: true}
		t.Cleanup(func() { s.Close() })
		if _, err := s.Up(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}

	macMini := device("mac-mini")
	service, err := macMini.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(service, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"uri": r.RequestURI, "host": r.Host, "header": r.Header})
	}))
	macMiniIP, _ := macMini.TailscaleIPs()
	member := device("member")
	memberIP, _ := member.TailscaleIPs()

	certPEM, keyPEM, cert := newCert(t, time.Now().Add(-time.Hour), "*."+mesh)
	writeCert(t, dir, certPEM, keyPEM, time.Now())
	c := config{hostname: "hosts", state: filepath.Join(dir, "hosts-node"), hosts: filepath.Join(dir, "hosts.json"),
		cert: filepath.Join(dir, "fullchain.pem"), key: filepath.Join(dir, "privkey.pem")}
	if err := os.MkdirAll(c.state, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(hosts ...map[string]any) {
		t.Helper()
		if err := os.WriteFile(c.hosts+".new", hostsJSON(t, hosts...), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(c.hosts+".new", c.hosts); err != nil {
			t.Fatal(err)
		}
	}
	grafana := with(host("grafana", 8080, "/some/service"), "address", macMiniIP.String())
	write(grafana)
	node := &tsnet.Server{Dir: c.state, Hostname: c.hostname, ControlURL: ctl.HTTPTestServer.URL, AuthKey: "test-join-key", Logf: logger.Discard, UserLogf: t.Logf, Ephemeral: true}
	t.Cleanup(func() { node.Close() })
	serving, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- serve(serving, node, c) }()
	waitFor(t, "the node to join and record it", func() bool {
		_, err := os.Stat(filepath.Join(c.state, joinedFile))
		return err == nil
	})
	waitFor(t, "the node to report itself healthy", func() bool { return checkHealth(c) == 0 })
	nodeIP, _ := node.TailscaleIPs()

	// The member's own dialer, with every name going to the hosts node, as the
	// network's DNS does.
	dial := func(port string) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, _ string) (net.Conn, error) {
			return member.Dial(ctx, network, net.JoinHostPort(nodeIP.String(), port))
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	browser := &http.Client{
		Transport: &http.Transport{DialContext: dial("443"), TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true},
		Timeout:   30 * time.Second,
	}
	var got echoed
	var proto int
	waitFor(t, "the member to open the host", func() bool {
		resp, err := browser.Get("https://grafana." + mesh + "/x?y=1")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		proto = resp.ProtoMajor
		return resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&got) == nil
	})
	if got.URI != "/some/service/x?y=1" || got.Host != "grafana."+mesh {
		t.Errorf("the service saw %s for %s", got.URI, got.Host)
	}
	if v := got.Header.Get("X-Forwarded-For"); v != memberIP.String() {
		t.Errorf("X-Forwarded-For = %s, want the member's address %s", v, memberIP)
	}
	if proto != 2 {
		t.Errorf("answered over HTTP/%d, want HTTP/2", proto)
	}

	// Port 80 sends the browser to https.
	plainHTTP := &http.Client{
		Transport:     &http.Transport{DialContext: dial("80")},
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := plainHTTP.Get("http://grafana." + mesh + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "https://grafana."+mesh+"/x" {
		t.Errorf("port 80: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	status := func(name string) (int, string) {
		resp, err := browser.Get(fmt.Sprintf("https://%s.%s/", name, mesh))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// A new host, whose device does not answer on that port, appears in the
	// running node without a restart.
	write(grafana, with(host("closed", 9999, ""), "address", macMiniIP.String()))
	waitFor(t, "the new host to be served", func() bool {
		code, _ := status("closed")
		return code != 404
	})
	if code, body := status("closed"); code != 502 || !strings.Contains(body, "mac-mini") || !strings.Contains(body, "9999") {
		t.Errorf("a closed port: %d %q", code, body)
	}
	if code, body := status("unknown"); code != 404 || body != "No host named unknown."+mesh+" in this network.\n" {
		t.Errorf("an unknown name: %d %q", code, body)
	}

	// The dialer refuses what is not a current device, where the general one
	// would hand it to the operating system.
	nodeDial := networkDial(node)
	system := node.Sys().Dialer.Get()
	stranger := netip.MustParseAddr("100.64.99.99")
	if system.UseNetstackForIP(stranger) {
		t.Fatalf("%s is a device; this test needs an address that is not", stranger)
	}
	dialResult := func(address string) error {
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		defer dcancel()
		conn, err := nodeDial(dctx, "tcp", address)
		if err == nil {
			conn.Close()
		}
		return err
	}
	if err := dialResult(net.JoinHostPort(stranger.String(), "8080")); !errors.Is(err, errNotADevice) {
		t.Errorf("an address with no device: %v", err)
	}
	if err := dialResult(net.JoinHostPort(nodeIP.String(), "443")); !errors.Is(err, errNotADevice) {
		t.Errorf("this device's own address: %v", err)
	}
	if err := dialResult(net.JoinHostPort(macMiniIP.String(), "8080")); err != nil {
		t.Errorf("a current device: %v", err)
	}

	// A device removed from the network while the hosts file still names it:
	// the node's map no longer has it, and it gets the normal 502.
	gone := device("gone")
	goneIP, _ := gone.TailscaleIPs()
	goneService, err := gone.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(goneService, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "still here") }))
	goneAddress := net.JoinHostPort(goneIP.String(), "8080")
	waitFor(t, "the node to reach the new device", func() bool { return dialResult(goneAddress) == nil })
	goneLocal, err := gone.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	goneStatus, err := goneLocal.StatusWithoutPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodeLocal, err := node.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	nodeStatus, err := nodeLocal.StatusWithoutPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	goneNode := ctl.Node(goneStatus.Self.PublicKey)
	if goneNode == nil {
		t.Fatal("the coordinator does not know the device")
	}
	waitFor(t, "the node to learn the device was removed", func() bool {
		ctl.AddRawMapResponse(nodeStatus.Self.PublicKey, &tailcfg.MapResponse{PeersRemoved: []tailcfg.NodeID{goneNode.ID}})
		return !system.UseNetstackForIP(goneIP)
	})
	if err := dialResult(goneAddress); !errors.Is(err, errNotADevice) {
		t.Errorf("a removed device: %v", err)
	}
	write(grafana, with(with(host("gone", 8080, ""), "address", goneIP.String()), "device", "gone"))
	waitFor(t, "the removed device's host to be served", func() bool {
		code, _ := status("gone")
		return code != 404
	})
	if code, body := status("gone"); code != 502 || !strings.Contains(body, "gone") || !strings.Contains(body, "8080") || strings.Contains(body, "still here") {
		t.Errorf("a removed device: %d %q", code, body)
	}

	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Error("the node did not stop")
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
