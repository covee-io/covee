package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/logger"
)

// This runs real coordination, WireGuard and DERP against local test servers.
// It proves our custom TUN adapter carries raw packets in both directions. It
// does not install an Apple VPN or substitute for signed device acceptance.
// startTestEngine runs a real engine against control, acknowledging every
// network event and forwarding it to settings when there is room.
func startTestEngine(t *testing.T, control *testcontrol.Server, name string, settings chan networkSettings) *engine {
	t.Helper()
	s, err := newKeychainStore([]byte(`{}`), func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(engineConfig{ControlURL: control.HTTPTestServer.URL, Hostname: name, RequireNetworkAck: true, AcceptRoutes: true}, s)
	t.Cleanup(e.stop)
	go func() {
		for {
			raw, code := e.nextEvent(maxEventBytes + 1)
			if code == codeClosed {
				return
			}
			if code <= 0 {
				continue
			}
			var event struct {
				Type    string          `json:"type"`
				Network networkSettings `json:"network"`
			}
			if json.Unmarshal(raw, &event) == nil && event.Type == "network" {
				select {
				case settings <- event.Network:
				default:
				}
				e.acknowledge(event.Network.Generation, "")
			}
		}
	}()
	if err := e.start(); err != nil {
		t.Fatal(err)
	}
	return e
}

// awaitPeers waits until both engines run and see each other.
func awaitPeers(t *testing.T, a, b *engine) (netip.Addr, netip.Addr) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		aStatus, bStatus := a.backend.Status(), b.backend.Status()
		if aStatus.BackendState == "Running" && bStatus.BackendState == "Running" && len(aStatus.TailscaleIPs) > 0 && len(bStatus.TailscaleIPs) > 0 && len(aStatus.Peer) > 0 && len(bStatus.Peer) > 0 {
			return aStatus.TailscaleIPs[0], bStatus.TailscaleIPs[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("local coordinated peers did not become Running")
	return netip.Addr{}, netip.Addr{}
}

func TestEncryptedPacketFlowBetweenRealEngines(t *testing.T) {
	netns.SetEnabled(false) // process-local socket binding; no host routes changed
	t.Cleanup(func() { netns.SetEnabled(true) })
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "covee.test", Logf: logger.Discard,
	}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	settingsApplied := make(chan networkSettings, 32)
	start := func(name string) *engine { return startTestEngine(t, control, name, settingsApplied) }
	a, b := start("apple-engine-a"), start("apple-engine-b")
	aip, bip := awaitPeers(t, a, b)
	if !aip.Is4() || !bip.Is4() {
		t.Fatal("local coordinated peers have no IPv4 addresses")
	}
	payload := []byte("covee-native-encrypted-packet-proof-v1")
	header := packet.UDP4Header{IP4Header: packet.IP4Header{Src: aip, Dst: bip}, SrcPort: 41234, DstPort: 41235}
	outgoing := packet.Generate(header, payload)
	deliver := func(from, to *engine, p []byte, src, dst netip.Addr, dstPort uint16) {
		t.Helper()
		retry := time.NewTicker(100 * time.Millisecond)
		defer retry.Stop()
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		if err := from.tun.inject(p); err != nil {
			t.Fatal(err)
		}
		for {
			select {
			case <-retry.C:
				if err := from.tun.inject(p); err != nil {
					t.Fatal(err)
				}
			case received := <-to.tun.incoming:
				var parsed packet.Parsed
				parsed.Decode(received)
				if parsed.Dst.Port() != dstPort {
					continue
				}
				if parsed.Src.Addr() != src || parsed.Dst.Addr() != dst || !bytes.Equal(parsed.Payload(), payload) {
					t.Fatal("decrypted packet addresses/payload differ")
				}
				return
			case <-timer.C:
				t.Fatal(fmt.Sprintf("encrypted payload was not delivered %s -> %s", src, dst))
			}
		}
	}
	deliver(a, b, outgoing, aip, bip, 41235)
	header.ToResponse()
	deliver(b, a, packet.Generate(header, payload), bip, aip, 41234)

	// The network's name service: A asks 100.100.100.100 for B's device name.
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x2c4b, RecursionDesired: true}, Questions: []dnsmessage.Question{{
		Name: dnsmessage.MustNewName("apple-engine-b.covee.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	quad100 := netip.MustParseAddr("100.100.100.100")
	lookup := packet.Generate(packet.UDP4Header{IP4Header: packet.IP4Header{Src: aip, Dst: quad100}, SrcPort: 53535, DstPort: 53}, wire)
	answered := func() bool {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		retry := time.NewTicker(250 * time.Millisecond)
		defer retry.Stop()
		if err := a.tun.inject(lookup); err != nil {
			t.Fatal(err)
		}
		for {
			select {
			case <-retry.C:
				_ = a.tun.inject(lookup)
			case received := <-a.tun.incoming:
				var parsed packet.Parsed
				parsed.Decode(received)
				if parsed.Src.Addr() != quad100 || parsed.Dst.Port() != 53535 {
					continue
				}
				var reply dnsmessage.Message
				if err := reply.Unpack(parsed.Payload()); err != nil || reply.ID != query.ID {
					continue
				}
				for _, answer := range reply.Answers {
					if a4, ok := answer.Body.(*dnsmessage.AResource); ok && netip.AddrFrom4(a4.A) == bip {
						return true
					}
				}
				t.Fatalf("the name service answered without B's address: %+v", reply.Answers)
			case <-timer.C:
				return false
			}
		}
	}
	if !answered() {
		t.Fatal("nothing answered the network's name service at 100.100.100.100")
	}
	addressed, dnsConfigured := false, false
	for len(settingsApplied) > 0 {
		n := <-settingsApplied
		addressed = addressed || len(n.Addresses) > 0
		dnsConfigured = dnsConfigured || len(n.DNSServers) > 0
	}
	if !addressed || !dnsConfigured {
		t.Fatal("engine did not deliver addressed network and DNS settings to native ACK boundary")
	}
	t.Log("bidirectional raw IPv4 UDP payload decrypted by real engines; native address/DNS settings acknowledged; no host TUN opened")
}

func TestEnrollmentProfilePersistenceFailureStopsRealEngine(t *testing.T) {
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{DERPMap: derpMap, Logf: logger.Discard}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	var mu sync.Mutex
	var durable map[string][]byte
	machineSaved, profileRejected := false, false
	writes := 0
	s, err := newKeychainStore([]byte(`{}`), func(raw []byte) error {
		var next map[string][]byte
		if err := json.Unmarshal(raw, &next); err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		writes++
		for name, value := range next {
			if !strings.HasPrefix(name, "profile-") {
				continue
			}
			var prefs ipn.Prefs
			if err := json.Unmarshal(value, &prefs); err != nil {
				return err
			}
			if prefs.Persist != nil && !prefs.Persist.PrivateNodeKey.IsZero() && prefs.Persist.NodeID != "" {
				profileRejected = true
				return errors.New("simulated locked Keychain during enrolled node save")
			}
		}
		durable = next
		machineSaved = len(next[string(ipn.MachineKeyStateKey)]) > 0
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(engineConfig{ControlURL: control.HTTPTestServer.URL, Hostname: "apple-engine-unsaved-profile", RequireNetworkAck: true}, s)
	t.Cleanup(e.stop)
	// start itself can emit network configurations, just as the native provider
	// starts its event reader before calling start on the separate worker queue.
	started := make(chan error, 1)
	go func() { started <- e.start() }()
	deadline := time.Now().Add(20 * time.Second)
	gotFatal := false
	for time.Now().Before(deadline) {
		raw, code := e.nextEvent(maxEventBytes + 1)
		if code == codeClosed {
			break
		}
		if code <= 0 {
			continue
		}
		var event struct {
			Type    string          `json:"type"`
			Code    string          `json:"code"`
			Error   string          `json:"error"`
			Network networkSettings `json:"network"`
			Status  engineStatus    `json:"status"`
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		switch event.Type {
		case "network":
			e.acknowledge(event.Network.Generation, "")
		case "status":
			if event.Status.BackendState == "Running" {
				t.Fatal("unsaved enrollment was reported Running")
			}
		case "error":
			if event.Code == "persistence" && event.Error == persistenceFailure {
				gotFatal = true
			}
		}
		if gotFatal {
			break
		}
	}
	if !gotFatal || !e.fatal.Load() {
		t.Fatal("late enrolled-profile write failure did not produce explicit fatal persistence error")
	}
	mu.Lock()
	if !machineSaved || !profileRejected || writes < 2 {
		t.Error("did not first save machine identity and then reject enrolled node/profile credentials")
	}
	for name := range durable {
		if strings.HasPrefix(name, "profile-") {
			t.Error("failed profile credentials advanced durable state")
		}
	}
	mu.Unlock()
	if err := e.tun.inject(ipv4Packet()); !errors.Is(err, io.EOF) {
		t.Fatal("real engine accepted forwarding after fatal enrollment failure")
	}
	if _, code := e.readPacket(maxPacketBytes); code != codeClosed {
		t.Fatal("real engine delivered output after fatal enrollment failure")
	}
	if _, code := e.nextEvent(maxEventBytes + 1); code != codeClosed {
		t.Fatal("real engine reported connected/status after fatal enrollment failure")
	}
	select {
	case err := <-started:
		if err != nil && !strings.Contains(err.Error(), persistenceFailure) {
			t.Fatalf("unexpected startup error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fatal enrollment failure did not release startup")
	}
	stopped := make(chan struct{})
	go func() { e.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("fatal enrollment failure deadlocked backend shutdown")
	}
	t.Log("machine identity durably saved; real enrolled node/profile save rejected; explicit persistence error; no Running or forwarding; backend shutdown completed")
}

func TestExitNodeIsOfferedChosenRefusedAndCleared(t *testing.T) {
	netns.SetEnabled(false) // process-local socket binding; no host routes changed
	t.Cleanup(func() { netns.SetEnabled(true) })
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "covee.test", Logf: logger.Discard,
	}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	settings := make(chan networkSettings, 64)
	a := startTestEngine(t, control, "apple-exit-client", settings)
	b := startTestEngine(t, control, "apple-exit-node", make(chan networkSettings, 64))
	awaitPeers(t, a, b)
	bID := string(b.backend.Status().Self.ID)

	// Before B offers anything, choosing it is refused and nothing changes.
	if err := a.setExitNode([]byte(`{"id":"` + bID + `","allowLAN":false}`)); !errors.Is(err, errNoExitNode) {
		t.Fatalf("choosing a peer that offers no exit node: %v", err)
	}
	// The coordinator approves B's exit routes.
	control.SetSubnetRoutes(b.backend.Status().Self.PublicKey, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("192.168.77.0/24")})
	peerB := func() peerStatus {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			for _, p := range a.buildStatus(a.backend).Peers {
				if p.ID == bID && p.ExitNodeOption {
					return p
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("the approved exit node is not offered in the published status")
		return peerStatus{}
	}
	offered := peerB()
	if offered.ExitNode {
		t.Fatal("an offered exit node was used before it was chosen")
	}
	for _, bad := range []string{`{"id":"nUnknownPeer","allowLAN":false}`, `{"id":1}`, `{"id":"x","extra":true}`, `not json`, `{"id":"a b"}`} {
		if err := a.setExitNode([]byte(bad)); err == nil {
			t.Fatalf("request %s was accepted", bad)
		}
	}
	if got := string(a.backend.Prefs().ExitNodeID()); got != "" {
		t.Fatalf("a refused request changed the exit node to %q", got)
	}

	for len(settings) > 0 {
		<-settings
	}
	if err := a.setExitNode([]byte(`{"id":"` + bID + `","allowLAN":true}`)); err != nil {
		t.Fatalf("choosing the offered exit node: %v", err)
	}
	if prefs := a.backend.Prefs(); string(prefs.ExitNodeID()) != bID || !prefs.ExitNodeAllowLANAccess() {
		t.Fatalf("prefs after choosing: exit node %q, LAN access %v", prefs.ExitNodeID(), prefs.ExitNodeAllowLANAccess())
	}
	// The native side receives default routes, and DNS for all domains.
	sawDefault, sawAllDNS := false, false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !(sawDefault && sawAllDNS) {
		select {
		case n := <-settings:
			for _, r := range n.Routes {
				sawDefault = sawDefault || r == "0.0.0.0/0"
			}
			sawAllDNS = sawAllDNS || (len(n.DNSServers) > 0 && len(n.MatchDomains) == 0)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !sawDefault || !sawAllDNS {
		t.Fatalf("exit node settings reached the native side incompletely: default route %v, all-domain DNS %v", sawDefault, sawAllDNS)
	}
	status := a.buildStatus(a.backend)
	if status.ExitNodeID != bID || !status.ExitNodeAllowLANAccess {
		t.Fatalf("published exit node %q, LAN access %v", status.ExitNodeID, status.ExitNodeAllowLANAccess)
	}
	var routes []string
	for _, p := range status.Peers {
		if p.ID == bID {
			routes = p.Routes
		}
	}
	if len(routes) == 0 {
		t.Fatalf("the subnet B serves is not published: %v", routes)
	}

	if err := a.setExitNode([]byte(`{"id":"","allowLAN":false}`)); err != nil {
		t.Fatalf("clearing the exit node: %v", err)
	}
	if got := string(a.backend.Prefs().ExitNodeID()); got != "" {
		t.Fatalf("exit node after clearing: %q", got)
	}
	a.stop()
	if err := a.setExitNode([]byte(`{"id":""}`)); !errors.Is(err, io.EOF) {
		t.Fatalf("a stopped engine accepted a change: %v", err)
	}
}

// hostIPv4 is a non-loopback IPv4 address of this machine outside the
// network's own 100.64.0.0/10 range, and its local network, standing in for
// a host the exit node reaches.
func hostIPv4(t *testing.T) (netip.Addr, netip.Prefix) {
	t.Helper()
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				ip = ip.Unmap()
				if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !cgnat.Contains(ip) {
					bits, _ := n.Mask.Size()
					return ip, netip.PrefixFrom(ip, bits).Masked()
				}
			}
		}
	}
	t.Skip("this machine has no non-loopback IPv4 address to stand in for the internet")
	return netip.Addr{}, netip.Prefix{}
}

func TestThisDeviceOffersAndRelaysAsExitNode(t *testing.T) {
	netns.SetEnabled(false) // process-local socket binding; no host routes changed
	t.Cleanup(func() { netns.SetEnabled(true) })
	// Like Tailscale, an exit node keeps its own local network out of what it
	// relays unless that network is offered too. The test's outside host is
	// on this machine's local network, so B also offers that network, which
	// checks that the exit node switch keeps a separately offered network.
	internet, lan := hostIPv4(t)
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "covee.test", Logf: logger.Discard,
	}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	a := startTestEngine(t, control, "apple-exit-user", make(chan networkSettings, 64))
	b := startTestEngine(t, control, "apple-mac-exit-node", make(chan networkSettings, 64))
	aip, _ := awaitPeers(t, a, b)
	bID := string(b.backend.Status().Self.ID)

	for _, bad := range []string{`{}`, `{"offer":1}`, `{"offer":true,"extra":1}`, `not json`, `{"offer":true}{}`} {
		if err := b.setOfferExitNode([]byte(bad)); !errors.Is(err, errInvalidOffer) {
			t.Fatalf("offer request %s: %v", bad, err)
		}
	}
	if _, err := b.backend.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{AdvertiseRoutes: []netip.Prefix{lan}}, AdvertiseRoutesSet: true}); err != nil {
		t.Fatal(err)
	}
	if err := b.setOfferExitNode([]byte(`{"offer":true}`)); err != nil {
		t.Fatalf("offering: %v", err)
	}
	if routes := b.backend.Prefs().AdvertiseRoutes(); routes.Len() != 3 || routes.At(0) != lan {
		t.Fatalf("offered routes: %v", routes)
	}
	if status := b.buildStatus(b.backend); !status.OffersExitNode || status.ExitNodeApproved {
		t.Fatalf("before approval: offers %v, approved %v", status.OffersExitNode, status.ExitNodeApproved)
	}
	// Hostinfo tells the coordinator what B offers.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if node := control.Node(b.backend.Status().Self.PublicKey); node != nil && node.Hostinfo.Valid() && tsaddr.ContainsExitRoutes(node.Hostinfo.RoutableIPs()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the coordinator never learned that B offers an exit node")
		}
		time.Sleep(50 * time.Millisecond)
	}
	control.SetSubnetRoutes(b.backend.Status().Self.PublicKey, append(tsaddr.ExitRoutes(), lan))
	for deadline = time.Now().Add(15 * time.Second); !b.buildStatus(b.backend).ExitNodeApproved; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("B never saw its exit node approved")
		}
	}
	// An exit node cannot use another one, and a device using one cannot offer one.
	aID := string(a.backend.Status().Self.ID)
	if err := b.setExitNode([]byte(`{"id":"` + aID + `","allowLAN":false}`)); !errors.Is(err, errOfferingExit) {
		t.Fatalf("an exit node chose another exit node: %v", err)
	}
	for deadline = time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if err := a.setExitNode([]byte(`{"id":"` + bID + `","allowLAN":false}`)); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("A could not choose B: %v", err)
		}
	}
	if err := a.setOfferExitNode([]byte(`{"offer":true}`)); !errors.Is(err, errUsingExit) {
		t.Fatalf("a device using an exit node offered one: %v", err)
	}

	// A's traffic to an outside address goes through B, which relays it from
	// its own sockets and returns the reply.
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: internet.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var reached atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "covee-exit-ping" {
				reached.Add(1)
				listener.WriteToUDP([]byte("covee-exit-pong"), from)
			}
		}
	}()
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
	ping := packet.Generate(packet.UDP4Header{IP4Header: packet.IP4Header{Src: aip, Dst: internet}, SrcPort: 47001, DstPort: port}, []byte("covee-exit-ping"))
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	_ = a.tun.inject(ping)
	for relayed := false; !relayed; {
		select {
		case <-retry.C:
			_ = a.tun.inject(ping)
		case received := <-a.tun.incoming:
			var parsed packet.Parsed
			parsed.Decode(received)
			relayed = parsed.Src.Addr() == internet && parsed.Src.Port() == port && parsed.Dst.Port() == 47001 && string(parsed.Payload()) == "covee-exit-pong"
		case <-timer.C:
			t.Fatalf("no reply came back through the exit node (the outside host received %d pings)", reached.Load())
		}
	}

	// Stopping the offer keeps nothing behind.
	if err := a.setExitNode([]byte(`{"id":"","allowLAN":false}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.setOfferExitNode([]byte(`{"offer":false}`)); err != nil {
		t.Fatalf("stopping the offer: %v", err)
	}
	if routes := b.backend.Prefs().AdvertiseRoutes(); routes.Len() != 1 || routes.At(0) != lan {
		t.Fatalf("after stopping, offered routes are %v; want only the local network", routes)
	}
	if status := b.buildStatus(b.backend); status.OffersExitNode || status.ExitNodeApproved {
		t.Fatalf("after stopping: offers %v, approved %v", status.OffersExitNode, status.ExitNodeApproved)
	}
}

// A network that moves to a new name keeps its devices: given the new address,
// a device reconnects with the keys it has, without signing in again.
func TestANewCoordinatorAddressKeepsTheDeviceAndItsSignIn(t *testing.T) {
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{DERPMap: derpMap, Logf: logger.Discard}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	var mu sync.Mutex
	var saved []byte
	run := func(controlURL string, state []byte) *engine {
		t.Helper()
		s, err := newKeychainStore(state, func(raw []byte) error {
			mu.Lock()
			defer mu.Unlock()
			saved = append([]byte(nil), raw...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		e := newEngine(engineConfig{ControlURL: controlURL, Hostname: "moving-mac", RequireNetworkAck: true}, s)
		t.Cleanup(e.stop)
		go func() {
			for {
				raw, code := e.nextEvent(maxEventBytes + 1)
				if code == codeClosed {
					return
				}
				var event struct {
					Type    string          `json:"type"`
					Network networkSettings `json:"network"`
				}
				if code > 0 && json.Unmarshal(raw, &event) == nil && event.Type == "network" {
					e.acknowledge(event.Network.Generation, "")
				}
			}
		}()
		if err := e.start(); err != nil {
			t.Fatal(err)
		}
		return e
	}
	running := func(e *engine) (key string, ip netip.Addr) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if st := e.backend.Status(); st.BackendState == "Running" && len(st.TailscaleIPs) > 0 && st.Self != nil {
				return st.Self.PublicKey.String(), st.TailscaleIPs[0]
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("the device did not reach Running")
		return "", netip.Addr{}
	}

	first := run(control.HTTPTestServer.URL, []byte(`{}`))
	keyBefore, ipBefore := running(first)
	first.stop()
	mu.Lock()
	state := saved
	mu.Unlock()

	// The same coordinator under another name, as after `covee rename`.
	moved := strings.Replace(control.HTTPTestServer.URL, "127.0.0.1", "localhost", 1)
	second := run(moved, state)
	keyAfter, ipAfter := running(second)
	if keyAfter != keyBefore || ipAfter != ipBefore {
		t.Fatalf("the device came back as a different device: key %s -> %s, address %s -> %s", keyBefore, keyAfter, ipBefore, ipAfter)
	}
	if n := len(control.AllNodes()); n != 1 {
		t.Fatalf("the coordinator registered %d devices; the device signed in again", n)
	}
	if got := second.backend.Prefs().ControlURL(); got != moved {
		t.Fatalf("the device uses %s, not the new address %s", got, moved)
	}
}
