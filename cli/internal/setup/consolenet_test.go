package setup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupCanServeTheConsoleInsideTheNetwork(t *testing.T) {
	h := newHarness(t)
	setUpHome(t, h, map[string]string{"console_in_network": "yes"})
	n, _ := h.env.Records.Load("home")
	if !n.ConsoleInNetwork || strings.Join(h.ca.names, ",") != "control.coveetest.io,console.mesh.coveetest.io" {
		t.Fatalf("console %v, certificate names %v", n.ConsoleInNetwork, h.ca.names)
	}
	var spec map[string]any
	if err := json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec); err != nil {
		t.Fatal(err)
	}
	if spec["console_in_network"] != true {
		t.Fatalf("deployment config lacks the console setting: %v", spec)
	}
	if !strings.Contains(h.out.String(), "https://console.mesh.coveetest.io, for devices in the network only") {
		t.Fatalf("the summary does not explain the console:\n%s", h.out)
	}
}

func TestConsoleInNetworkTurnsItOnForARunningNetwork(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, map[string]string{"console_in_network": "no"})
	if n, _ := h.env.Records.Load("home"); n.ConsoleInNetwork || len(h.ca.names) != 1 {
		t.Fatalf("console turned on without asking: %v", h.ca.names)
	}

	// Older Covee files on the server: update first.
	h.env.Archive = func() ([]byte, string, error) { return []byte("newer"), "fedcba9876543210fedcba9876543210", nil }
	h.env.Ask = h.answers(nil)
	if err := ConsoleInNetwork(ctx, h.env, "home"); err == nil || !strings.Contains(err.Error(), "covee update home") {
		t.Fatalf("expected the update advice, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.state, "console-enable")); err == nil {
		t.Fatal("the server was changed although its files are older")
	}

	h.env.Archive = func() ([]byte, string, error) { return []byte("payload"), "0123456789abcdef0123456789abcdef", nil }
	before := h.ca.obtained
	if err := ConsoleInNetwork(ctx, h.env, "home"); err != nil {
		t.Fatalf("console in network: %v\n%s", err, h.out)
	}
	if h.ca.obtained != before+1 || strings.Join(h.ca.names, ",") != "control.coveetest.io,console.mesh.coveetest.io" {
		t.Fatalf("certificate names %v", h.ca.names)
	}
	command, _ := os.ReadFile(filepath.Join(h.state, "console-enable"))
	if !strings.Contains(string(command), "--cert /srv/covee/secrets/tls/fullchain.pem --key /srv/covee/secrets/tls/privkey.pem --directory '/srv/covee/runtime-1'") {
		t.Fatalf("enable command = %s", command)
	}
	n, _ := h.env.Records.Load("home")
	if !n.ConsoleInNetwork {
		t.Fatal("the record does not have the console setting")
	}
	var spec map[string]any
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if spec["console_in_network"] != true {
		t.Fatal("the server's deployment config was not updated")
	}
	if !strings.Contains(h.out.String(), "now at https://console.mesh.coveetest.io") {
		t.Fatalf("no confirmation:\n%s", h.out)
	}
	// Running it again changes nothing.
	obtained := h.ca.obtained
	if err := ConsoleInNetwork(ctx, h.env, "home"); err != nil || h.ca.obtained != obtained {
		t.Fatalf("second run: %v (certificates %d)", err, h.ca.obtained-obtained)
	}
	h.out.Reset()
	if err := Status(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "Console in the network: https://console.mesh.coveetest.io (console device healthy)") {
		t.Fatalf("status: %v\n%s", err, h.out)
	}
}
