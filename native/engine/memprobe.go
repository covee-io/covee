//go:build memprobe

package main

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// The measured side of memprobe_test.go: with COVEE_MEMPROBE=phone and
// COVEE_MEMPROBE_CONTROL=url, one engine joins that network and Go's memory
// is printed as it starts. Built only with the memprobe tag, never shipped.
func init() {
	if os.Getenv("COVEE_MEMPROBE") != "phone" {
		return
	}
	netns.SetEnabled(false)
	report := func(label string) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Printf("%-22s heap live %5.1f MB  heap held %5.1f MB  stacks %4.1f MB  Go total %5.1f MB  goroutines %d  GC runs %d  GC CPU %.1f%%\n",
			label, float64(m.HeapAlloc)/1e6, float64(m.HeapInuse)/1e6, float64(m.StackInuse)/1e6,
			float64(m.Sys-m.HeapReleased)/1e6, runtime.NumGoroutine(), m.NumGC, m.GCCPUFraction*100)
	}
	report("before the engine")
	s, err := newKeychainStore([]byte(`{}`), func([]byte) error { return nil })
	if err != nil {
		panic(err)
	}
	e := newEngine(engineConfig{ControlURL: os.Getenv("COVEE_MEMPROBE_CONTROL"), Hostname: "phone", RequireNetworkAck: true, AcceptRoutes: true}, s)
	go func() {
		for {
			raw, code := e.nextEvent(maxEventBytes + 1)
			if code == codeClosed {
				return
			}
			if code > 0 && len(raw) > 0 {
				for gen := e.nextGen.Load(); gen > 0; gen-- {
					if e.acknowledge(gen, "") == nil {
						break
					}
				}
			}
		}
	}()
	started := time.Now()
	if err := e.start(); err != nil {
		panic(err)
	}
	for e.backend.State().String() != "Running" && time.Since(started) < 30*time.Second {
		time.Sleep(20 * time.Millisecond)
	}
	report(fmt.Sprintf("running after %.1fs", time.Since(started).Seconds()))
	fmt.Printf("pid %d\n", os.Getpid())
	time.Sleep(5 * time.Second)
	report("idle at 5s")
	st := e.backend.Status()
	self := st.TailscaleIPs[0]
	var peer netip.Addr
	for _, p := range st.Peer {
		if len(p.TailscaleIPs) > 0 {
			peer = p.TailscaleIPs[0]
			break
		}
	}
	var received atomic.Int64
	go func() {
		for {
			select {
			case <-e.tun.incoming:
				received.Add(1)
			case <-e.done:
				return
			}
		}
	}()
	load := os.Getenv("COVEE_MEMPROBE_LOAD")
	var sent int64
	stop := time.Now().Add(30 * time.Second)
	next := time.Now().Add(3 * time.Second)
	for time.Now().Before(stop) {
		if load == "dns" || load == "both" {
			// Lookups under the split domains, whose server cannot be reached.
			for i := 0; i < 2; i++ {
				name := fmt.Sprintf("h%d.zone%d.example.net.", rand.IntN(1<<20), rand.IntN(16))
				b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(rand.IntN(65536)), RecursionDesired: true})
				b.StartQuestions()
				b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
				q, _ := b.Finish()
				h := packet.UDP4Header{IP4Header: packet.IP4Header{IPProto: ipproto.UDP, Src: self, Dst: netip.MustParseAddr("100.100.100.100")},
					SrcPort: uint16(20000 + rand.IntN(40000)), DstPort: 53}
				if e.tun.inject(packet.Generate(h, q)) == nil {
					sent++
				}
			}
		}
		if (load == "traffic" || load == "both") && peer.IsValid() {
			payload := make([]byte, 1200)
			h := packet.UDP4Header{IP4Header: packet.IP4Header{IPProto: ipproto.UDP, Src: self, Dst: peer}, SrcPort: 40000, DstPort: 40001}
			for i := 0; i < 60; i++ {
				if e.tun.inject(packet.Generate(h, payload)) == nil {
					sent++
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
		if time.Now().After(next) {
			next = next.Add(3 * time.Second)
			report(fmt.Sprintf("load %s sent %d got %d", load, sent, received.Load()))
		}
	}
	for i := 0; i < 4; i++ {
		time.Sleep(3 * time.Second)
		report(fmt.Sprintf("after load +%ds", 3*(i+1)))
	}
	e.stop()
	os.Exit(0)
}
