package main

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"slices"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
)

const maxPacketBytes = 65535

var errQueueFull = errors.New("packet queue is full")

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
