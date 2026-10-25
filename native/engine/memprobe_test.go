package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
)

// TestMemoryOfAStartedEngine measures one engine joining a network with a
// gateway's private DNS: seven other devices and sixteen split DNS domains
// whose server cannot be reached. It runs in two
// processes, so the measured one holds only the engine:
//
//	COVEE_MEMPROBE=network COVEE_MEMPROBE_DIR=dir: the coordinator, relay and
//	seven devices on this Mac; writes dir/control.txt and waits for dir/done.
//	The measured engine is memprobe.go (build tag memprobe), for example in the
//	iOS Simulator.
func TestMemoryOfAStartedEngine(t *testing.T) {
	switch os.Getenv("COVEE_MEMPROBE") {
	case "network":
		probeNetwork(t)
	default:
		t.Skip("set COVEE_MEMPROBE=network to start the measured engine's network")
	}
}

func probeNetwork(t *testing.T) {
	dir := os.Getenv("COVEE_MEMPROBE_DIR")
	netns.SetEnabled(false)
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	routes := map[string][]*dnstype.Resolver{}
	for i := 0; i < 16; i++ {
		routes[fmt.Sprintf("zone%d.example.net", i)] = []*dnstype.Resolver{{Addr: "192.0.2.53"}}
	}
	control := &testcontrol.Server{DERPMap: derpMap, DNSConfig: &tailcfg.DNSConfig{Proxied: true, Routes: routes},
		MagicDNSDomain: "covee.test", Logf: logger.Discard}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	settings := make(chan networkSettings, 1024)
	for i := 0; i < 7; i++ {
		startTestEngine(t, control, fmt.Sprintf("peer-%d", i), settings)
	}
	if err := os.WriteFile(filepath.Join(dir, "control.txt"), []byte(control.HTTPTestServer.URL), 0o600); err != nil {
		t.Fatal(err)
	}
	for start := time.Now(); time.Since(start) < 5*time.Minute; time.Sleep(time.Second) {
		if _, err := os.Stat(filepath.Join(dir, "done")); err == nil {
			return
		}
	}
}
