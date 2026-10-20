package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

func writeRoutes(t *testing.T, path string, routes ...string) {
	t.Helper()
	raw, _ := json.Marshal(map[string][]string{"routes": routes})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRoutesFileIsCheckedStrictly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if r, err := readRoutes(path); err != nil || len(r) != 0 {
		t.Fatalf("missing file = %v, %v", r, err)
	}
	writeRoutes(t, path, "10.20.0.0/16", "168.63.129.16/32", "10.2.0.0/16", "10.2.0.0/16")
	r, err := readRoutes(path)
	if err != nil || len(r) != 3 || r[0].String() != "10.2.0.0/16" {
		t.Fatalf("routes = %v, %v", r, err)
	}
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"::/0"}, {"10.0.0.1/8"}, {"100.64.0.0/24"}, {"fd7a:115c:a1e0::/64"}, {"example.com"}} {
		writeRoutes(t, path, bad...)
		if _, err := readRoutes(path); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
	os.WriteFile(path, []byte("{"), 0o600)
	if _, err := readRoutes(path); err == nil {
		t.Error("broken JSON was accepted")
	}
}

// localAddress is an address of this computer other than loopback, which the
// gateway can reach and a test device can only reach through the gateway.
func localAddress(t *testing.T) netip.Addr {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !strings.HasPrefix(ip.String(), "100.") {
				return ip
			}
		}
	}
	t.Skip("this computer has no non-loopback IPv4 address")
	return netip.Addr{}
}

// A member device reaches a TCP and a UDP service behind the gateway, which
// offers the routes from its file and follows changes to it.
func TestGatewayForwardsTCPAndUDPForItsRoutes(t *testing.T) {
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	relay := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	ctl := &testcontrol.Server{DERPMap: relay, Logf: logger.Discard}
	ctl.HTTPTestServer = httptest.NewServer(ctl)
	t.Cleanup(ctl.HTTPTestServer.Close)

	target := localAddress(t)
	tcpService, err := net.Listen("tcp", net.JoinHostPort(target.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpService.Close()
	go func() {
		for {
			c, err := tcpService.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte("tcp:" + line))
			}()
		}
	}()
	udpService, err := net.ListenPacket("udp", net.JoinHostPort(target.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpService.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := udpService.ReadFrom(buf)
			if err != nil {
				return
			}
			udpService.WriteTo(append([]byte("udp:"), buf[:n]...), from)
		}
	}()

	dir := t.TempDir()
	routes := filepath.Join(dir, "routes.json")
	route := netip.PrefixFrom(target, 32)
	writeRoutes(t, routes, "10.99.0.0/16")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw, err := start(ctx, config{control: ctl.HTTPTestServer.URL, hostname: "gateway", state: filepath.Join(dir, "gw"), routes: routes}, "test-join-key", logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.close()
	if err := gw.waitRunning(ctx, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	go gw.followRoutes(ctx, routes, 100*time.Millisecond, logger.Discard)
	// The coordinator approves what the console chose; here the test does.
	writeRoutes(t, routes, route.String(), "10.99.0.0/16")
	gwKey := gw.lb.Status().Self.PublicKey
	waitFor(t, "the gateway to offer the new route", func() bool {
		n := ctl.Node(gwKey)
		return n != nil && n.Hostinfo.Valid() && slices.Contains(n.Hostinfo.RoutableIPs().AsSlice(), route)
	})
	ctl.SetSubnetRoutes(gwKey, []netip.Prefix{route})

	member := &tsnet.Server{Dir: filepath.Join(dir, "member"), Hostname: "member", ControlURL: ctl.HTTPTestServer.URL,
		Logf: logger.Discard, Ephemeral: true}
	defer member.Close()
	if _, err := member.Up(ctx); err != nil {
		t.Fatal(err)
	}
	lc, _ := member.LocalClient()
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true}); err != nil {
		t.Fatal(err)
	}

	// The member must send the target through the network, where only the
	// gateway offers it, not dial it directly from this computer.
	viaNetwork := func() bool { return member.Sys().Dialer.Get().UseNetstackForIP(target) }
	waitFor(t, "the member to route the target through the network", viaNetwork)
	st, err := lc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	offered := false
	for _, p := range st.Peer {
		if p.HostName == "gateway" && p.PrimaryRoutes != nil && slices.Contains(p.PrimaryRoutes.AsSlice(), route) {
			offered = true
		}
	}
	if !offered {
		t.Fatal("the member does not see the gateway offering the route")
	}

	tcpAddr := tcpService.Addr().String()
	var got string
	waitFor(t, "a TCP answer through the gateway", func() bool {
		dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
		defer dcancel()
		c, err := member.Dial(dctx, "tcp", tcpAddr)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("hello\n"))
		got, _ = bufio.NewReader(c).ReadString('\n')
		return got == "tcp:hello\n"
	})

	udpAddr := udpService.LocalAddr().String()
	waitFor(t, "a UDP answer through the gateway", func() bool {
		dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
		defer dcancel()
		c, err := member.Dial(dctx, "udp", udpAddr)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte("ping"))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		return err == nil && string(buf[:n]) == "udp:ping"
	})

	// Removing the route from the file withdraws it.
	writeRoutes(t, routes, "10.99.0.0/16")
	waitFor(t, "the gateway to withdraw the route", func() bool {
		n := ctl.Node(gwKey)
		return n != nil && n.Hostinfo.Valid() && !slices.Contains(n.Hostinfo.RoutableIPs().AsSlice(), route)
	})
	ctl.SetSubnetRoutes(gwKey, nil)
	waitFor(t, "the member to stop routing the target through the network", func() bool { return !viaNetwork() })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
