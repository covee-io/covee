package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/router"
)

func ipv4Packet() []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	copy(p[12:16], []byte{100, 64, 0, 1})
	copy(p[16:20], []byte{100, 64, 0, 2})
	return p
}

func fixtureEngine(t *testing.T, ack bool) *engine {
	t.Helper()
	store, err := newKeychainStore([]byte(`{}`), func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(engineConfig{ControlURL: "http://127.0.0.1:9", Hostname: "covee-test", RequireNetworkAck: ack}, store)
	t.Cleanup(e.stop)
	return e
}

func TestStatePersistenceFailureDoesNotAdvanceState(t *testing.T) {
	var saved []byte
	fail := false
	store, err := newKeychainStore([]byte(`{"node":"b2xk"}`), func(raw []byte) error {
		if fail {
			return errors.New("Keychain is locked")
		}
		saved = bytes.Clone(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := store.WriteState(ipn.StateKey("node"), []byte("new")); err == nil {
		t.Fatal("failed durable write reported success")
	}
	got, _ := store.ReadState(ipn.StateKey("node"))
	if string(got) != "old" {
		t.Fatalf("failure changed in-memory state: %q", got)
	}
	fail = false
	if err := store.WriteState(ipn.StateKey("node"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newKeychainStore(saved, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	got, _ = reloaded.ReadState(ipn.StateKey("node"))
	if string(got) != "new" {
		t.Fatal("restart did not restore new state")
	}
	got[0] = '!'
	again, _ := reloaded.ReadState(ipn.StateKey("node"))
	if string(again) != "new" {
		t.Fatal("read exposed mutable state")
	}
	if err := store.WriteState(ipn.StateKey("node"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadState(ipn.StateKey("node")); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatalf("deleted state read: %v", err)
	}
}

func TestPacketCopiesAndShortReadPreservesPayload(t *testing.T) {
	tun := newPacketDevice()
	defer tun.Close()
	p := ipv4Packet()
	if err := tun.inject(p); err != nil {
		t.Fatal(err)
	}
	p[8] = 0
	sizes := make([]int, 1)
	if _, err := tun.Read([][]byte{make([]byte, 10)}, sizes, 0); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short buffer: %v", err)
	}
	buf := make([]byte, 40)
	if n, err := tun.Read([][]byte{buf}, sizes, 4); n != 1 || err != nil || sizes[0] != 20 {
		t.Fatalf("read: %v %v %v", n, sizes, err)
	}
	if buf[4+8] != 64 {
		t.Fatal("injection retained caller-owned bytes")
	}
	if !bytes.Equal(buf[:4], make([]byte, 4)) {
		t.Fatal("offset headroom overwritten")
	}
}

func TestPacketBoundsAndStopUnblocksReaders(t *testing.T) {
	e := fixtureEngine(t, false)
	invalid := ipv4Packet()
	invalid[2], invalid[3] = 0, 21
	if e.tun.inject(invalid) == nil {
		t.Fatal("accepted truncated IPv4")
	}
	for i := 0; i < cap(e.tun.outgoing); i++ {
		if err := e.tun.inject(ipv4Packet()); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(e.tun.inject(ipv4Packet()), errQueueFull) {
		t.Fatal("input queue did not bound memory")
	}
	finished := make(chan int, 1)
	go func() { _, code := e.readPacket(65536); finished <- code }()
	e.stop()
	select {
	case code := <-finished:
		if code != codeClosed {
			t.Fatalf("closed read: %d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("read did not unblock on stop")
	}
}

func TestOutputPacketAndEventRetry(t *testing.T) {
	e := fixtureEngine(t, false)
	p := ipv4Packet()
	if _, err := e.tun.Write([][]byte{p}, 0); err != nil {
		t.Fatal(err)
	}
	p[8] = 0
	if _, code := e.readPacket(10); code != codeSmall {
		t.Fatalf("short native read: %d", code)
	}
	got, code := e.readPacket(65536)
	if code != 20 || got[8] != 64 {
		t.Fatal("short native read consumed or aliased payload")
	}
	e.settings <- []byte(`{"type":"network"}`)
	if _, code := e.nextEvent(5); code != codeSmall {
		t.Fatal("event was not preserved")
	}
	got, code = e.nextEvent(1024)
	if code != len(got) || !bytes.Contains(got, []byte("network")) {
		t.Fatal("event retry lost payload")
	}
}

func TestFatalPersistenceSupersedesHeldEventsAndPackets(t *testing.T) {
	e := fixtureEngine(t, false)
	e.store.persist = func([]byte) error { return errors.New("secret platform error privkey:abc123") }
	e.statuses <- []byte(`{"type":"status","status":{"backendState":"Running"}}`)
	if _, code := e.nextEvent(1); code != codeSmall {
		t.Fatal("did not hold an undersized Running event")
	}
	e.settings <- []byte(`{"type":"network"}`)
	p := ipv4Packet()
	if _, err := e.tun.Write([][]byte{p}, 0); err != nil {
		t.Fatal(err)
	}
	if _, code := e.readPacket(1); code != codeSmall {
		t.Fatal("did not hold an undersized packet")
	}
	if err := e.tun.inject(p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.tun.Read([][]byte{make([]byte, 1)}, []int{0}, 0); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("did not hold a WireGuard input packet")
	}
	if err := e.store.WriteState("node", []byte("unsaved")); err == nil || !e.fatal.Load() {
		t.Fatal("failed identity write did not latch synchronously")
	}
	// The latch precedes asynchronous backend shutdown, including all held data.
	if _, code := e.readPacket(maxPacketBytes); code != codeClosed {
		t.Fatal("returned a held packet after persistence failure")
	}
	if err := e.tun.inject(p); !errors.Is(err, io.EOF) {
		t.Fatal("accepted input after persistence failure")
	}
	if _, err := e.tun.Read([][]byte{make([]byte, maxPacketBytes)}, []int{0}, 0); !errors.Is(err, io.EOF) {
		t.Fatal("returned held WireGuard input after persistence failure")
	}
	if _, err := e.tun.Write([][]byte{p}, 0); !errors.Is(err, io.EOF) {
		t.Fatal("accepted engine output after persistence failure")
	}
	e.publishStatus(nil) // fatal path must not query a stopped backend
	e.recordError(errors.New("a later backend error"))
	if _, code := e.nextEvent(1); code != codeSmall {
		t.Fatal("fatal event short-buffer retry was not retained")
	}
	raw, code := e.nextEvent(maxEventBytes + 1)
	if code <= 0 || !bytes.Equal(raw, persistenceEvent) {
		t.Fatalf("fatal event did not supersede held Running/network: %s (%d)", raw, code)
	}
	if _, code := e.nextEvent(maxEventBytes + 1); code != codeClosed {
		t.Fatal("delivered another event after fatal envelope")
	}
	// A subsequent successful platform callback cannot revive this state store.
	e.store.persist = func([]byte) error { t.Error("retried persistence after fatal failure"); return nil }
	if err := e.store.WriteState("node", []byte("later")); err == nil {
		t.Fatal("failed store resumed accepting writes")
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if e.lastError != persistenceFailure {
		t.Fatal("fatal safe error was overwritten")
	}
}

func TestNativeNetworkAcknowledgementPropagatesFailureAndStop(t *testing.T) {
	e := fixtureEngine(t, true)
	result := make(chan error, 1)
	go func() { result <- e.applyNetwork(&router.Config{}, &dns.OSConfig{}) }()
	raw, code := e.nextEvent(maxEventBytes + 1)
	if code <= 0 {
		t.Fatalf("missing network event: %d", code)
	}
	var event struct {
		Network networkSettings `json:"network"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	select {
	case <-result:
		t.Fatal("configuration succeeded before native acknowledgement")
	default:
	}
	if err := e.acknowledge(event.Network.Generation, "OS rejected routes"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "OS rejected") {
			t.Fatalf("native failure not propagated: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("acknowledgement did not unblock")
	}
	go func() { result <- e.applyNetwork(&router.Config{}, nil) }()
	if _, code := e.nextEvent(maxEventBytes + 1); code <= 0 {
		t.Fatalf("missing next network event: %d", code)
	}
	e.stop()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("stop did not release acknowledgement wait")
	}
}

func TestConfigRejectsUnsafeControllerAndSecretErrors(t *testing.T) {
	for _, origin := range []string{"http://controller.example", "https://user:password@example.com", "https://example.com?token=secret", "file:///tmp/controller", "https://example.com/machine"} {
		raw, _ := json.Marshal(engineConfig{ControlURL: origin, Hostname: "device"})
		if _, err := parseConfig(raw); err == nil {
			t.Errorf("accepted unsafe controller %s", origin)
		}
	}
	for _, name := range []string{"utun0\x00ignored", "utun wrong", "utunπ", "interface-name-too-long"} {
		raw, _ := json.Marshal(engineConfig{ControlURL: "https://controller.example", Hostname: "device", TunnelInterfaceName: name})
		if _, err := parseConfig(raw); err == nil {
			t.Errorf("accepted invalid interface name %q", name)
		}
	}
	configured := fixtureEngine(t, false)
	configured.cfg.TunnelInterfaceName = "utun42"
	configured = newEngine(configured.cfg, configured.store)
	defer configured.stop()
	if name, _ := configured.tun.Name(); name != "utun42" {
		t.Fatal("real network extension interface name was not preserved")
	}
	e := fixtureEngine(t, false)
	e.cfg.AuthKey = "very-private-enrollment-value"
	e.recordError(errors.New("failed very-private-enrollment-value tskey-auth-secret hskey-secret privkey:abc123"))
	raw, code := e.nextEvent(maxEventBytes + 1)
	if code <= 0 || bytes.Contains(raw, []byte("very-private")) || bytes.Contains(raw, []byte("abc123")) || bytes.Contains(raw, []byte("hskey")) {
		t.Fatalf("error exposed secret: %q", raw)
	}
}

// nameLookup is a DNS packet between a device and the network's name service:
// a query, or with answer its reply.
func nameLookup(src netip.Addr, port, id uint16, answer bool) []byte {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload, id)
	if src.Is4() {
		h := packet.UDP4Header{IP4Header: packet.IP4Header{IPProto: ipproto.UDP, Src: src, Dst: netip.AddrFrom4(nameServiceV4)}, SrcPort: port, DstPort: 53}
		if answer {
			h.ToResponse()
		}
		return packet.Generate(h, payload)
	}
	h := packet.UDP6Header{IP6Header: packet.IP6Header{IPProto: ipproto.UDP, Src: src, Dst: netip.AddrFrom16(nameServiceV6)}, SrcPort: port, DstPort: 53}
	if answer {
		h.ToResponse()
	}
	return packet.Generate(h, payload)
}

func TestLookupsWaitingForTheNameServiceAreBounded(t *testing.T) {
	d := newPacketDevice()
	defer d.Close()
	me := netip.MustParseAddr("100.64.0.6")
	for i := 0; i < maxWaitingLookups; i++ {
		if err := d.inject(nameLookup(me, uint16(1000+i), 7, false)); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.inject(nameLookup(me, 5000, 7, false)); err != nil || len(d.outgoing) != maxWaitingLookups {
		t.Fatalf("a lookup beyond the limit was passed on: %v, %d queued", err, len(d.outgoing))
	}
	// Asking the same question again adds nothing to wait for.
	if err := d.inject(nameLookup(me, 1000, 7, false)); err != nil || len(d.outgoing) != maxWaitingLookups+1 {
		t.Fatalf("a repeated lookup was refused: %v, %d queued", err, len(d.outgoing))
	}
	// An answer makes room.
	if _, err := d.Write([][]byte{nameLookup(me, 1001, 7, true)}, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.inject(nameLookup(me, 5000, 7, false)); err != nil || len(d.outgoing) != maxWaitingLookups+2 {
		t.Fatalf("a lookup was refused after an answer made room: %v, %d queued", err, len(d.outgoing))
	}
	// Lookups that never got an answer stop counting after a while.
	d.lookups.mu.Lock()
	for key := range d.lookups.waiting {
		d.lookups.waiting[key] = time.Now().Add(-lookupWait - time.Second)
	}
	d.lookups.mu.Unlock()
	if err := d.inject(nameLookup(me, 5001, 7, false)); err != nil || len(d.outgoing) != maxWaitingLookups+3 {
		t.Fatalf("expired lookups still blocked a new one: %v, %d queued", err, len(d.outgoing))
	}
	d.lookups.mu.Lock()
	left := len(d.lookups.waiting)
	d.lookups.mu.Unlock()
	if left != 1 {
		t.Fatalf("%d lookups still counted after the others expired", left)
	}
	// IPv6 lookups count too; other traffic is never held back.
	key, ok := lookupKey(nameLookup(netip.MustParseAddr("fd7a:115c:a1e0::6"), 2000, 9, false), true)
	if !ok || key != 2000<<16|9 {
		t.Fatalf("IPv6 lookup key %x %v", key, ok)
	}
	if _, ok := lookupKey(ipv4Packet(), true); ok {
		t.Fatal("an ICMP packet was taken for a lookup")
	}
	other := packet.Generate(packet.UDP4Header{IP4Header: packet.IP4Header{IPProto: ipproto.UDP, Src: me, Dst: netip.MustParseAddr("100.64.0.4")}, SrcPort: 1000, DstPort: 53}, make([]byte, 12))
	if _, ok := lookupKey(other, true); ok {
		t.Fatal("DNS to another device was taken for a lookup to the name service")
	}
}

func TestAPassingProblemStopsShowingOnceTheConnectionRunsAgain(t *testing.T) {
	e := fixtureEngine(t, false)
	e.recordError(errors.New("native network settings acknowledgement timed out"))
	running := ipn.Running.String()
	if got := e.currentError(running); got == "" {
		t.Fatal("a new problem was not reported")
	}
	e.errMu.Lock()
	e.lastErrorAt = time.Now().Add(-staleErrorAge - time.Second)
	e.errMu.Unlock()
	if got := e.currentError(ipn.Starting.String()); got == "" {
		t.Fatal("a problem stopped showing before the connection ran again")
	}
	if got := e.currentError(running); got != "" {
		t.Fatalf("an old problem still showed while running: %q", got)
	}

	fatal := fixtureEngine(t, false)
	fatal.failPersistence()
	fatal.errMu.Lock()
	fatal.lastErrorAt = time.Now().Add(-time.Hour)
	fatal.errMu.Unlock()
	if got := fatal.currentError(running); got != persistenceFailure {
		t.Fatalf("the failure that stopped the tunnel stopped showing: %q", got)
	}
}

func TestActualBackendStartsWithoutOpeningHostTUN(t *testing.T) {
	var mu sync.Mutex
	writes := 0
	store, err := newKeychainStore([]byte(`{}`), func([]byte) error { mu.Lock(); writes++; mu.Unlock(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(engineConfig{ControlURL: "http://127.0.0.1:9", Hostname: "covee-engine-test"}, store)
	t.Cleanup(e.stop)
	if err := e.start(); err != nil {
		t.Fatal(err)
	}
	if e.backend == nil || e.tun.File() != nil {
		t.Fatal("real backend or packet-flow adapter missing")
	}
	mu.Lock()
	count := writes
	mu.Unlock()
	if count == 0 {
		t.Fatal("backend initialization did not persist identity/preferences")
	}
	e.stop()
}

func TestTheNetworksRoutesCanBeTurnedOffAndOnWhileRunning(t *testing.T) {
	store, err := newKeychainStore([]byte(`{}`), func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(engineConfig{ControlURL: "http://127.0.0.1:9", Hostname: "covee-routes-test", AcceptRoutes: true}, store)
	t.Cleanup(e.stop)
	if err := e.start(); err != nil {
		t.Fatal(err)
	}
	if !e.buildStatus(e.backend).AcceptRoutes {
		t.Fatal("the configured setting was not applied")
	}
	if err := e.setAcceptRoutes([]byte(`{"accept":false}`)); err != nil {
		t.Fatal(err)
	}
	if e.buildStatus(e.backend).AcceptRoutes || e.backend.Prefs().RouteAll() {
		t.Fatal("routes are still accepted")
	}
	for _, bad := range []string{`{}`, `{"accept":"no"}`, `{"accept":true,"x":1}`, `{"accept":true}{}`} {
		if err := e.setAcceptRoutes([]byte(bad)); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if err := e.setAcceptRoutes([]byte(`{"accept":true}`)); err != nil || !e.backend.Prefs().RouteAll() {
		t.Fatalf("turning routes back on: %v", err)
	}
	e.stop()
	if err := e.setAcceptRoutes([]byte(`{"accept":true}`)); err == nil {
		t.Fatal("a stopped engine accepted a change")
	}
}
