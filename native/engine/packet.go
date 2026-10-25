package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

const maxPacketBytes = 65535

var errQueueFull = errors.New("packet queue is full")

// The network's name service (100.100.100.100, fd7a:115c:a1e0::53) answers for
// the network's own names and forwards other domains, such as a gateway's
// private DNS zones. When such a server cannot be reached, every lookup waits
// for its timeout and holds memory meanwhile; a phone's apps send hundreds a
// second, enough to pass the iPhone's 50 MB limit for a network extension,
// which ends the connection. At most maxWaitingLookups wait at once: more are
// dropped, as a busy DNS server's would be, and the apps ask again.
const (
	maxWaitingLookups = 32
	lookupWait        = 8 * time.Second
)

var (
	nameServiceV4 = [4]byte{100, 100, 100, 100}
	nameServiceV6 = netip.MustParseAddr("fd7a:115c:a1e0::53").As16()
)

// lookupGuard counts the lookups to the name service still waiting for an answer.
type lookupGuard struct {
	mu      sync.Mutex
	waiting map[uint32]time.Time // the asker's UDP port << 16 | DNS message ID
}

// admit reports whether a lookup may go to the name service now.
func (g *lookupGuard) admit(key uint32, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.waiting == nil {
		g.waiting = make(map[uint32]time.Time)
	}
	if _, asked := g.waiting[key]; !asked && len(g.waiting) >= maxWaitingLookups {
		for k, at := range g.waiting {
			if now.Sub(at) > lookupWait {
				delete(g.waiting, k)
			}
		}
		if len(g.waiting) >= maxWaitingLookups {
			return false
		}
	}
	g.waiting[key] = now
	return true
}

func (g *lookupGuard) answered(key uint32) {
	g.mu.Lock()
	delete(g.waiting, key)
	g.mu.Unlock()
}

// lookupKey identifies a UDP DNS lookup to the name service (query) or its
// answer (!query), by the asker's port and the message ID.
func lookupKey(p []byte, query bool) (uint32, bool) {
	var udp []byte
	switch p[0] >> 4 {
	case 4:
		header := int(p[0]&15) * 4
		if len(p) < header+10 || p[9] != 17 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return 0, false
		}
		address := p[16:20]
		if !query {
			address = p[12:16]
		}
		if [4]byte(address) != nameServiceV4 {
			return 0, false
		}
		udp = p[header:]
	case 6:
		if len(p) < 50 || p[6] != 17 {
			return 0, false
		}
		address := p[24:40]
		if !query {
			address = p[8:24]
		}
		if [16]byte(address) != nameServiceV6 {
			return 0, false
		}
		udp = p[40:]
	default:
		return 0, false
	}
	service, asker := udp[2:4], udp[0:2]
	if !query {
		service, asker = udp[0:2], udp[2:4]
	}
	if binary.BigEndian.Uint16(service) != 53 {
		return 0, false
	}
	return uint32(binary.BigEndian.Uint16(asker))<<16 | uint32(binary.BigEndian.Uint16(udp[8:10])), true
}

// packetDevice is the Apple packetFlow boundary. No host TUN is opened.
// outgoing is from Apple -> engine; incoming is engine -> Apple.
type packetDevice struct {
	outgoing chan []byte
	incoming chan []byte
	events   chan tun.Event
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex   // closes events without racing an event producer
	flowMu   sync.RWMutex // synchronizes final packet copies with Close
	readMu   sync.Mutex
	readHold []byte
	mtu      int
	name     string
	lookups  lookupGuard
}

func newPacketDevice() *packetDevice {
	t := &packetDevice{
		outgoing: make(chan []byte, 128),
		incoming: make(chan []byte, 128),
		events:   make(chan tun.Event, 1),
		done:     make(chan struct{}),
		mtu:      1280,
		name:     "covee-tun",
	}
	t.events <- tun.EventUp
	return t
}

func (t *packetDevice) File() *os.File           { return nil }
func (t *packetDevice) Name() (string, error)    { return t.name, nil }
func (t *packetDevice) MTU() (int, error)        { return t.mtu, nil }
func (t *packetDevice) Events() <-chan tun.Event { return t.events }
func (t *packetDevice) BatchSize() int           { return 1 }

func (t *packetDevice) Close() error {
	t.once.Do(func() {
		t.flowMu.Lock()
		defer t.flowMu.Unlock()
		t.mu.Lock()
		defer t.mu.Unlock()
		close(t.done)
		close(t.events)
	})
	return nil
}

func validIPPacket(p []byte) bool {
	if len(p) < 20 || len(p) > maxPacketBytes {
		return false
	}
	switch p[0] >> 4 {
	case 4:
		header := int(p[0]&15) * 4
		return header >= 20 && len(p) >= header && int(binary.BigEndian.Uint16(p[2:4])) == len(p)
	case 6:
		return len(p) >= 40 && int(binary.BigEndian.Uint16(p[4:6]))+40 == len(p)
	default:
		return false
	}
}

func (t *packetDevice) inject(p []byte) error {
	if !validIPPacket(p) {
		return errors.New("invalid IPv4 or IPv6 packet")
	}
	if key, ok := lookupKey(p, true); ok && !t.lookups.admit(key, time.Now()) {
		return nil
	}
	t.flowMu.RLock()
	defer t.flowMu.RUnlock()
	select {
	case <-t.done:
		return io.EOF
	default:
	}
	select {
	case <-t.done:
		return io.EOF
	case t.outgoing <- slices.Clone(p):
		return nil
	default:
		return errQueueFull
	}
}

func (t *packetDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) < 1 || len(sizes) < 1 || offset < 0 {
		return 0, errors.New("invalid packet read buffers")
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	select {
	case <-t.done:
		t.readHold = nil
		return 0, io.EOF
	default:
	}
	if t.readHold == nil {
		select {
		case <-t.done:
			return 0, io.EOF
		case t.readHold = <-t.outgoing:
		}
	}
	t.flowMu.RLock()
	defer t.flowMu.RUnlock()
	select {
	case <-t.done:
		t.readHold = nil
		return 0, io.EOF
	default:
	}
	if offset > len(bufs[0]) || len(t.readHold) > len(bufs[0])-offset {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(bufs[0][offset:], t.readHold)
	t.readHold = nil
	return 1, nil
}

func (t *packetDevice) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, errors.New("invalid packet write offset")
	}
	t.flowMu.RLock()
	defer t.flowMu.RUnlock()
	select {
	case <-t.done:
		return 0, io.EOF
	default:
	}
	for i, buf := range bufs {
		if offset > len(buf) {
			return i, errors.New("invalid packet write offset")
		}
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		if !validIPPacket(packet) {
			return i, errors.New("invalid IP packet from engine")
		}
		if key, ok := lookupKey(packet, false); ok {
			t.lookups.answered(key)
		}
		select {
		case <-t.done:
			return i, io.EOF
		case t.incoming <- slices.Clone(packet):
		default:
			// A saturated IP interface drops packets. Never block WireGuard
			// workers behind a suspended native packet-flow consumer.
		}
	}
	return len(bufs), nil
}
