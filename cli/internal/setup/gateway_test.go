package setup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayTurnsOnAndOffForARunningNetwork(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)

	// Older Covee files on the server: update first.
	h.env.Archive = func() ([]byte, string, error) { return []byte("newer"), "fedcba9876543210fedcba9876543210", nil }
	h.env.Ask = h.answers(nil)
	if err := Gateway(ctx, h.env, "home", false); err == nil || !strings.Contains(err.Error(), "covee update home") {
		t.Fatalf("expected the update advice, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.state, "gateway-command")); err == nil {
		t.Fatal("the server was changed although its files are older")
	}

	h.env.Archive = func() ([]byte, string, error) { return []byte("payload"), "0123456789abcdef0123456789abcdef", nil }
	if err := Gateway(ctx, h.env, "home", false); err != nil {
		t.Fatalf("gateway: %v\n%s", err, h.out)
	}
	command, _ := os.ReadFile(filepath.Join(h.state, "gateway-command"))
	if !strings.Contains(string(command), "deploy.py enable-gateway --directory '/srv/covee/runtime-1'") {
		t.Fatalf("enable command = %s", command)
	}
	if n, _ := h.env.Records.Load("home"); !n.Gateway {
		t.Fatal("the record does not have the gateway")
	}
	var spec map[string]any
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if spec["gateway"] != true {
		t.Fatalf("the server's deployment config lacks the gateway: %v", spec)
	}
	path, err := os.ReadFile(filepath.Join(h.state, "units", gatewayDNSPath))
	if err != nil || !strings.Contains(string(path), "PathChanged=/srv/covee/runtime-1/state/management/gateway/dns.json") {
		t.Fatalf("path unit = %s %v", path, err)
	}
	service, _ := os.ReadFile(filepath.Join(h.state, "units", gatewayDNSService))
	if !strings.Contains(string(service), "deploy.py apply-gateway-dns --directory /srv/covee/runtime-1") || !strings.Contains(string(service), "User=covee") {
		t.Fatalf("service unit = %s", service)
	}
	actions, _ := os.ReadFile(filepath.Join(h.state, "units", "actions"))
	if !strings.Contains(string(actions), "gateway-dns-started") {
		t.Fatalf("the DNS settings were not applied once: %s", actions)
	}
	firewall, err := os.ReadFile(filepath.Join(h.state, "firewall.json"))
	if err != nil || !strings.Contains(string(firewall), `"ssh_source_cidrs"`) {
		t.Fatalf("the firewall step got %s %v", firewall, err)
	}
	if !strings.Contains(h.out.String(), "console's Gateway page") {
		t.Fatalf("no pointer to the Gateway page:\n%s", h.out)
	}

	h.out.Reset()
	if err := Status(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "Gateway: device healthy") {
		t.Fatalf("status: %v\n%s", err, h.out)
	}

	// Off removes the device and the watcher; the record and config follow.
	if err := Gateway(ctx, h.env, "home", true); err != nil {
		t.Fatalf("gateway off: %v\n%s", err, h.out)
	}
	command, _ = os.ReadFile(filepath.Join(h.state, "gateway-command"))
	if !strings.Contains(string(command), "deploy.py disable-gateway") {
		t.Fatalf("disable command = %s", command)
	}
	actions, _ = os.ReadFile(filepath.Join(h.state, "units", "actions"))
	if !strings.Contains(string(actions), "gateway-dns-removed") {
		t.Fatalf("the DNS watcher stayed: %s", actions)
	}
	if n, _ := h.env.Records.Load("home"); n.Gateway {
		t.Fatal("the record still has the gateway")
	}
	spec = nil
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if _, on := spec["gateway"]; on {
		t.Fatal("the server's deployment config still has the gateway")
	}
	h.out.Reset()
	if err := Gateway(ctx, h.env, "home", true); err != nil || !strings.Contains(h.out.String(), "has no gateway") {
		t.Fatalf("second off: %v\n%s", err, h.out)
	}
}
