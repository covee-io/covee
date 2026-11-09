package setup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"

	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
)

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]record.Host{
		"mac-mini:8080":                        {Device: "mac-mini", Port: 8080, Scheme: "http"},
		"Mac-Mini:8080/":                       {Device: "mac-mini", Port: 8080, Scheme: "http"},
		"mac-mini:8080/some/sub/service":       {Device: "mac-mini", Port: 8080, Path: "/some/sub/service", Scheme: "http"},
		"mac-mini.mesh.covee.io:3000/grafana/": {Device: "mac-mini", Port: 3000, Path: "/grafana/", Scheme: "http"},
		"http://nas:80":                        {Device: "nas", Port: 80, Scheme: "http"},
		"https://nas:5001/admin":               {Device: "nas", Port: 5001, Path: "/admin", Scheme: "https"},
		"  printer:65535 ":                     {Device: "printer", Port: 65535, Scheme: "http"},
		"pi-4:1/a-b_c.d~e/%20f":                {Device: "pi-4", Port: 1, Path: "/a-b_c.d~e/%20f", Scheme: "http"},
	} {
		got, err := parseTarget(in, "mesh.covee.io")
		if err != nil || got != want {
			t.Errorf("parseTarget(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for in, hint := range map[string]string{
		"":                    "--to device:port",
		"mac-mini":            "the port its service listens on",
		"mac-mini:":           "the port its service listens on",
		"mac-mini/grafana":    "the port its service listens on",
		":8080":               "not a device name",
		"mac_mini:8080":       "not a device name",
		"mac-mini.lan:8080":   "not a device name",
		"100.64.0.7:8080":     "not a device name",
		"mac-mini:http":       "from 1 to 65535",
		"mac-mini:0":          "from 1 to 65535",
		"mac-mini:65536":      "from 1 to 65535",
		"mac-mini:080":        "from 1 to 65535",
		"mac-mini:+80":        "from 1 to 65535",
		"mac-mini:8080/a?b=c": "cannot contain ?",
		"mac-mini:8080/a#top": "cannot contain ?",
		"mac-mini:8080/a b":   "spaces",
		"ftp://mac-mini:21":   "only http and https",
	} {
		_, err := parseTarget(in, "mesh.covee.io")
		if err == nil || !strings.Contains(err.Error(), hint) {
			t.Errorf("parseTarget(%q) = %v; want an error mentioning %q", in, err, hint)
		}
	}
}

func TestTargetPathsFollowTheHostsDevicesRules(t *testing.T) {
	for _, ok := range []string{"", "/some/sub/service", "/svc/", "/a%20b", "/a%2Fb", "/a/./b", "/" + strings.Repeat("x", 1023)} {
		if err := checkTargetPath(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for bad, hint := range map[string]string{
		"/foo%":                         "two hexadecimal digits",
		"/a%zz":                         "two hexadecimal digits",
		"/a/../etc":                     "cannot contain ..",
		"/file..txt":                    "cannot contain ..",
		"/a/%2e%2e/etc":                 "cannot contain ..",
		"/a%2e%2e/b":                    "cannot contain ..",
		"/a%2E./b":                      "cannot contain ..",
		"/a%5Cb":                        "encoded backslash",
		"/a%00":                         "encoded backslash or control",
		"/a%0Ab":                        "encoded backslash or control",
		"/a%7f":                         "encoded backslash or control",
		"/a\\b":                         "backslashes",
		"/a b":                          "spaces",
		"/a\x00b":                       "control characters",
		"/café":                         "plain English",
		"/a?b=c":                        "? or #",
		"/a#b":                          "? or #",
		"//evil":                        "begin with //",
		"//":                            "begin with //",
		"/" + strings.Repeat("x", 1024): "longer than 1024",
	} {
		if err := checkTargetPath(bad); err == nil || !strings.Contains(err.Error(), hint) {
			t.Errorf("checkTargetPath(%q) = %v; want an error mentioning %q", bad, err, hint)
		}
	}
	// --to applies them.
	for _, bad := range []string{"mac-mini:8080/foo%", "mac-mini:8080/a%2e%2e/b", "mac-mini:8080/a%5Cb", "mac-mini:8080/a%00", "mac-mini:8080//x"} {
		if _, err := parseTarget(bad, "mesh.covee.io"); err == nil || !strings.Contains(err.Error(), "--to ") {
			t.Errorf("parseTarget(%q) = %v", bad, err)
		}
	}
}

func TestHostNamesFollowTheServersRules(t *testing.T) {
	for in, want := range map[string]string{"grafana": "grafana", "Home-Assistant": "home-assistant", "grafana.mesh.covee.io": "grafana", "a": "a", strings.Repeat("x", 63): strings.Repeat("x", 63)} {
		if got, err := hostName(in, "mesh.covee.io"); err != nil || got != want {
			t.Errorf("hostName(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-grafana", "grafana-", "graf_ana", "grafana.example.org", "a.b", strings.Repeat("x", 64), "hosts", "console", "gateway", "admin", "Console"} {
		if _, err := hostName(bad, "mesh.covee.io"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCertNamesCoverEveryNameUnderTheMeshDomainWithHosts(t *testing.T) {
	n := &record.Network{Hostname: "control.covee.io", DNSBaseDomain: "mesh.covee.io"}
	if got := strings.Join(certNames(n), ","); got != "control.covee.io" {
		t.Fatal(got)
	}
	n.ConsoleInNetwork = true
	if got := strings.Join(certNames(n), ","); got != "control.covee.io,console.mesh.covee.io" {
		t.Fatal(got)
	}
	n.HostsEnabled = true
	if got := strings.Join(certNames(n), ","); got != "control.covee.io,*.mesh.covee.io" {
		t.Fatal(got)
	}
	n.ConsoleInNetwork = false
	if got := strings.Join(certNames(n), ","); got != "control.covee.io,*.mesh.covee.io" {
		t.Fatal(got)
	}
	data, _ := deploymentConfig(&record.Network{Hostname: "control.covee.io", DNSBaseDomain: "mesh.covee.io", HostsEnabled: true, SignIn: record.SignIn{Local: &record.Local{}}}, nil)
	var spec map[string]any
	if err := json.Unmarshal(data, &spec); err != nil || spec["hosts"] != true {
		t.Fatalf("deployment config lacks hosts: %v %s", err, data)
	}
}

func TestRefusalShowsTheServersExplanation(t *testing.T) {
	err := refusal(errors.New("covee@192.168.50.20: exit status 1: Resolving... | ERROR: No device named mac-mini in this network"))
	if err.Error() != "No device named mac-mini in this network" {
		t.Fatal(err)
	}
	if err := refusal(errors.New("connection refused")); err.Error() != "connection refused" {
		t.Fatal(err)
	}
}

// hostsSent is the last list of hosts uploaded for set-hosts.
func hostsSent(t *testing.T, h *harness) []map[string]any {
	t.Helper()
	var sent struct {
		Hosts []map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(h.file(t, serverHosts)), &sent); err != nil {
		t.Fatal(err)
	}
	return sent.Hosts
}

func TestHostsFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(h.state, name)); return err == nil }
	load := func() *record.Network {
		n, err := h.env.Records.Load("home")
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Older Covee files on the server: update first, before asking anything.
	h.env.Archive = func() ([]byte, string, error) { return []byte("newer"), "fedcba9876543210fedcba9876543210", nil }
	h.env.Ask = h.answers(map[string]string{"hosts": "no"})
	before := h.ca.obtained
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080/some/sub/service", false, false); err == nil || !strings.Contains(err.Error(), "covee update home") {
		t.Fatalf("expected the update advice, got %v", err)
	}
	if exists("hosts-enable") || exists("hosts-calls") || h.ca.obtained != before {
		t.Fatal("the network was changed although its files are older")
	}

	// Saying no changes nothing.
	h.env.Archive = func() ([]byte, string, error) { return []byte("payload"), "0123456789abcdef0123456789abcdef", nil }
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080/some/sub/service", false, false); !errors.Is(err, prompt.ErrAborted) {
		t.Fatalf("declined: %v", err)
	}
	if exists("hosts-enable") || h.ca.obtained != before || load().HostsEnabled {
		t.Fatal("the network was changed although the admin said no")
	}

	// Bad input is refused before anything else.
	h.env.Ask = h.answers(nil)
	if err := HostAdd(ctx, h.env, "home", "console", "mac-mini:8080", false, false); err == nil || !strings.Contains(err.Error(), "uses itself") {
		t.Fatalf("reserved name: %v", err)
	}
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080", false, true); err == nil || !strings.Contains(err.Error(), "--https") {
		t.Fatalf("--no-verify without --https: %v", err)
	}

	// The enable step fails on the server: hosts stay off; the new certificate is kept.
	_ = os.WriteFile(filepath.Join(h.state, "fail-enable-hosts"), nil, 0o600)
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080/some/sub/service", false, false); err == nil || !strings.Contains(err.Error(), "did not join the network") {
		t.Fatalf("failed enable: %v", err)
	}
	if n := load(); n.HostsEnabled || len(n.Hosts) != 0 || exists("hosts-calls") {
		t.Fatalf("hosts recorded although the server refused: %+v", n.Hosts)
	}
	os.Remove(filepath.Join(h.state, "fail-enable-hosts"))

	// The first host turns hosts on.
	h.out.Reset()
	before = h.ca.obtained
	if err := HostAdd(ctx, h.env, "home", "Grafana", "mac-mini:8080/some/sub/service", false, false); err != nil {
		t.Fatalf("first add: %v\n%s", err, h.out)
	}
	if h.ca.obtained != before+1 || strings.Join(h.ca.names, ",") != "control.coveetest.io,*.mesh.coveetest.io" {
		t.Fatalf("certificate names %v", h.ca.names)
	}
	if h.file(t, "/srv/covee/secrets/tls/fullchain.pem") != "CHAIN for control.coveetest.io" || h.file(t, "/srv/covee/secrets/tls/privkey.pem") != "CERT KEY" {
		t.Fatal("the new certificate was not installed")
	}
	enable, _ := os.ReadFile(filepath.Join(h.state, "hosts-enable"))
	if !strings.Contains(string(enable), "deploy.py enable-hosts --cert /srv/covee/secrets/tls/fullchain.pem --key /srv/covee/secrets/tls/privkey.pem --directory '/srv/covee/runtime-1'") {
		t.Fatalf("enable command = %s", enable)
	}
	calls, _ := os.ReadFile(filepath.Join(h.state, "hosts-calls"))
	if !strings.Contains(string(calls), "deploy.py set-hosts --config /srv/covee/hosts.json --directory '/srv/covee/runtime-1'") {
		t.Fatalf("set-hosts command = %s", calls)
	}
	log, _ := os.ReadFile(filepath.Join(h.state, "log"))
	if e, s := strings.LastIndex(string(log), "enable-hosts"), strings.LastIndex(string(log), "set-hosts"); e < 0 || s < e {
		t.Fatal("set-hosts did not follow enable-hosts")
	}
	sent := hostsSent(t, h)
	if len(sent) != 1 || sent[0]["name"] != "grafana" || sent[0]["device"] != "mac-mini" || sent[0]["port"] != 8080.0 ||
		sent[0]["path"] != "/some/sub/service" || sent[0]["scheme"] != "http" || sent[0]["verify"] != true {
		t.Fatalf("sent %v", sent)
	}
	n := load()
	if !n.HostsEnabled || len(n.Hosts) != 1 || n.Hosts[0] != (record.Host{Name: "grafana", Device: "mac-mini", Port: 8080, Path: "/some/sub/service", Scheme: "http"}) {
		t.Fatalf("record: %v %+v", n.HostsEnabled, n.Hosts)
	}
	var spec map[string]any
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if spec["hosts"] != true {
		t.Fatalf("the server's deployment config lacks hosts: %v", spec)
	}
	if !strings.Contains(h.out.String(), "Devices in network home can now open https://grafana.mesh.coveetest.io → mac-mini:8080/some/sub/service.") {
		t.Fatalf("no confirmation:\n%s", h.out)
	}

	// Later adds only send the list: no new certificate, no restart.
	before = h.ca.obtained
	enableBefore, _ := os.ReadFile(filepath.Join(h.state, "hosts-enable"))
	if err := HostAdd(ctx, h.env, "home", "nas", "nas:5001", true, true); err != nil {
		t.Fatalf("second add: %v\n%s", err, h.out)
	}
	enableAfter, _ := os.ReadFile(filepath.Join(h.state, "hosts-enable"))
	if h.ca.obtained != before || string(enableAfter) != string(enableBefore) || strings.Count(string(mustRead(t, h, "log")), "enable-hosts") != 2 {
		t.Fatal("a later add enabled hosts again")
	}
	if sent = hostsSent(t, h); len(sent) != 2 || sent[1]["name"] != "nas" || sent[1]["scheme"] != "https" || sent[1]["verify"] != false || sent[1]["path"] != "" {
		t.Fatalf("sent %v", sent)
	}

	// A refused change leaves the record as it was.
	_ = os.WriteFile(filepath.Join(h.state, "fail-set-hosts"), nil, 0o600)
	if err := HostAdd(ctx, h.env, "home", "wiki", "mac-mini:3000", false, false); err == nil || !strings.Contains(err.Error(), "No device named mac-mini in this network") ||
		!strings.Contains(err.Error(), "kept its previous hosts") {
		t.Fatalf("refused add: %v", err)
	}
	if n := load(); len(n.Hosts) != 2 {
		t.Fatalf("record changed although the server refused: %+v", n.Hosts)
	}
	os.Remove(filepath.Join(h.state, "fail-set-hosts"))
	// So does a reply that does not match what was sent.
	_ = os.WriteFile(filepath.Join(h.state, "set-hosts-reply"), []byte(`{"hosts": [{"name": "grafana.mesh.coveetest.io", "target": "x"}], "changed": true}`+"\n"), 0o600)
	if err := HostAdd(ctx, h.env, "home", "wiki", "mac-mini:3000", false, false); err == nil || !strings.Contains(err.Error(), "did not confirm") {
		t.Fatalf("unconfirmed add: %v", err)
	}
	if n := load(); len(n.Hosts) != 2 {
		t.Fatalf("record changed although the server did not confirm: %+v", n.Hosts)
	}
	os.Remove(filepath.Join(h.state, "set-hosts-reply"))

	// Adding a host again changes where it goes.
	h.out.Reset()
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:3000", false, false); err != nil || !strings.Contains(h.out.String(), "now open https://grafana.mesh.coveetest.io → mac-mini:3000") {
		t.Fatalf("change: %v\n%s", err, h.out)
	}
	if n := load(); len(n.Hosts) != 2 || n.Hosts[0].Port != 3000 || n.Hosts[0].Path != "" {
		t.Fatalf("record: %+v", n.Hosts)
	}

	// List and status show them.
	h.out.Reset()
	if err := HostList(context.Background(), h.env, "home"); err != nil {
		t.Fatal(err)
	}
	if got := h.out.String(); !strings.HasSuffix(got, "https://grafana.mesh.coveetest.io → mac-mini:3000\nhttps://nas.mesh.coveetest.io → nas:5001 (https, its certificate is not checked)\n") {
		t.Fatalf("list:\n%s", got)
	}
	h.out.Reset()
	if err := Status(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "Hosts: 2, for devices in the network (hosts device healthy)") ||
		!strings.Contains(h.out.String(), "    https://nas.mesh.coveetest.io → nas:5001") {
		t.Fatalf("status: %v\n%s", err, h.out)
	}

	// Renewing keeps the wildcard. (The fake server does not answer
	// renew-certificates with its days left; only the names matter here.)
	before = h.ca.obtained
	_ = CertRenew(ctx, h.env, "home")
	if h.ca.obtained != before+1 || strings.Join(h.ca.names, ",") != "control.coveetest.io,*.mesh.coveetest.io" {
		t.Fatalf("renew names %v", h.ca.names)
	}

	// Renaming waits until hosts are off.
	if err := Rename(ctx, h.env, "home", "vpn.coveetest.io", ""); err == nil || !strings.Contains(err.Error(), "covee host off home") {
		t.Fatalf("rename: %v", err)
	}

	// Remove sends the rest; an unknown name is refused.
	if err := HostRemove(ctx, h.env, "home", "wiki"); err == nil || !strings.Contains(err.Error(), "no host named wiki") {
		t.Fatalf("unknown remove: %v", err)
	}
	h.out.Reset()
	if err := HostRemove(ctx, h.env, "home", "grafana.mesh.coveetest.io"); err != nil {
		t.Fatalf("remove: %v\n%s", err, h.out)
	}
	if sent = hostsSent(t, h); len(sent) != 1 || sent[0]["name"] != "nas" {
		t.Fatalf("sent %v", sent)
	}
	if n := load(); len(n.Hosts) != 1 || n.Hosts[0].Name != "nas" {
		t.Fatalf("record: %+v", n.Hosts)
	}
	// Removing the last one keeps hosts on.
	h.out.Reset()
	if err := HostRemove(ctx, h.env, "home", "nas"); err != nil || !strings.Contains(h.out.String(), "`covee host off home` turns it off") {
		t.Fatalf("last remove: %v\n%s", err, h.out)
	}
	if sent = hostsSent(t, h); len(sent) != 0 {
		t.Fatalf("sent %v", sent)
	}
	if n := load(); !n.HostsEnabled || n.Hosts != nil {
		t.Fatalf("record: %v %+v", n.HostsEnabled, n.Hosts)
	}
	h.out.Reset()
	if err := HostList(context.Background(), h.env, "home"); err != nil || !strings.Contains(h.out.String(), "has no hosts") {
		t.Fatalf("empty list: %v\n%s", err, h.out)
	}

	// Off removes the hosts device.
	if err := HostsOff(ctx, h.env, "home"); err != nil {
		t.Fatalf("off: %v\n%s", err, h.out)
	}
	if disable, _ := os.ReadFile(filepath.Join(h.state, "hosts-disable")); !strings.Contains(string(disable), "deploy.py disable-hosts --directory '/srv/covee/runtime-1'") {
		t.Fatalf("disable command = %s", disable)
	}
	if n := load(); n.HostsEnabled || n.Hosts != nil {
		t.Fatal("the record still has hosts")
	}
	spec = nil
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if _, on := spec["hosts"]; on {
		t.Fatal("the server's deployment config still has hosts")
	}
	// The console in the network (on by default in setup) is named again.
	if got := strings.Join(certNames(load()), ","); got != "control.coveetest.io,console.mesh.coveetest.io" {
		t.Fatalf("the next certificate would name %s", got)
	}
}

func TestTheConsolesHostsPageCanChangeTheListAfterTheFirstHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	h.env.Ask = h.answers(nil)
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080", false, false); err != nil {
		t.Fatalf("first add: %v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "console's Hosts page") {
		t.Fatalf("the page was not mentioned:\n%s", h.out)
	}
	for _, unit := range []string{consoleHostsService, consoleHostsPath} {
		if _, err := os.Stat(filepath.Join(h.state, "units", unit)); err != nil {
			t.Fatalf("%s was not installed: %v", unit, err)
		}
	}
	// The page adds a host: the command's list and status follow the server.
	serverFile := filepath.Join(h.state, "server-hosts.json")
	if err := os.WriteFile(serverFile, []byte(`{"hosts": [
	  {"name": "grafana.mesh.coveetest.io", "device": "mac-mini", "port": 8080, "path": "", "scheme": "http", "verify": true},
	  {"name": "wiki.mesh.coveetest.io", "device": "nas", "port": 3000, "path": "", "scheme": "http", "verify": true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.out.Reset()
	if err := HostList(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "https://wiki.mesh.coveetest.io → nas:3000") {
		t.Fatalf("list: %v\n%s", err, h.out)
	}
	// Turning hosts off removes the watcher.
	h.env.Ask = h.answers(nil)
	if err := HostsOff(ctx, h.env, "home"); err != nil {
		t.Fatalf("off: %v\n%s", err, h.out)
	}
	if actions, _ := os.ReadFile(filepath.Join(h.state, "units", "actions")); !strings.Contains(string(actions), "console-hosts-removed") {
		t.Fatalf("the watcher stayed: %s", actions)
	}
}

func TestHostListFallsBackToThisComputersCopy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	h.env.Ask = h.answers(nil)
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080", false, false); err != nil {
		t.Fatalf("first add: %v\n%s", err, h.out)
	}
	if err := os.WriteFile(filepath.Join(h.state, "fail-read-hosts"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.out.Reset()
	if err := HostList(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "last saw it") || !strings.Contains(h.out.String(), "https://grafana.mesh.coveetest.io") {
		t.Fatalf("list: %v\n%s", err, h.out)
	}
}

func TestConsoleHostsUnitsActOnTheConsolesRequests(t *testing.T) {
	service, path := consoleHostsUnits("/srv/covee/runtime-1")
	if !strings.Contains(service, "deploy.py apply-console-hosts --directory /srv/covee/runtime-1") || !strings.Contains(service, "User=covee") {
		t.Fatalf("service:\n%s", service)
	}
	if !strings.Contains(path, "PathChanged=/srv/covee/runtime-1/state/management/hosts/request.json") || !strings.Contains(path, "Unit="+consoleHostsService) {
		t.Fatalf("path:\n%s", path)
	}
}

func TestFirstHostCanFailAfterHostsAreOn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	h.env.Ask = h.answers(nil)
	_ = os.WriteFile(filepath.Join(h.state, "fail-set-hosts"), nil, 0o600)
	err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080", false, false)
	if err == nil || !strings.Contains(err.Error(), "hosts are on for home, but grafana was not added: No device named mac-mini in this network") {
		t.Fatalf("got %v", err)
	}
	n, _ := h.env.Records.Load("home")
	if !n.HostsEnabled || len(n.Hosts) != 0 {
		t.Fatalf("record: %v %+v", n.HostsEnabled, n.Hosts)
	}
	// Trying again with the right device only sends the list.
	os.Remove(filepath.Join(h.state, "fail-set-hosts"))
	before := h.ca.obtained
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-studio:8080", false, false); err != nil || h.ca.obtained != before {
		t.Fatalf("second try: %v (certificates %d)", err, h.ca.obtained-before)
	}
}

func TestFirstHostIsCheckedBeforeAnythingChanges(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	state := func(name string) string { b, _ := os.ReadFile(filepath.Join(h.state, name)); return string(b) }

	// A mistyped device costs no question, no certificate and no restart.
	before := h.ca.obtained
	_ = os.WriteFile(filepath.Join(h.state, "fail-check-hosts"), nil, 0o600)
	h.env.Ask = h.answers(map[string]string{"hosts": "no"})
	err := HostAdd(ctx, h.env, "home", "grafana", "mac-minni:8080", false, false)
	if err == nil || !strings.Contains(err.Error(), "nothing was changed: No device named mac-minni in this network") {
		t.Fatalf("refused check: %v", err)
	}
	if h.ca.obtained != before || state("hosts-enable") != "" || state("hosts-calls") != "" {
		t.Fatal("the network was changed although the check failed")
	}
	if n, _ := h.env.Records.Load("home"); n.HostsEnabled || len(n.Hosts) != 0 {
		t.Fatalf("record: %+v", n.Hosts)
	}
	if !strings.Contains(state("hosts-checks"), "deploy.py check-hosts --config /srv/covee/hosts.json --directory '/srv/covee/runtime-1'") {
		t.Fatalf("check command = %s", state("hosts-checks"))
	}
	os.Remove(filepath.Join(h.state, "fail-check-hosts"))

	// A passed check still asks, and only then takes a certificate.
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080", false, false); !errors.Is(err, prompt.ErrAborted) || h.ca.obtained != before {
		t.Fatalf("declined: %v (certificates %d)", err, h.ca.obtained-before)
	}
	if sent := hostsSent(t, h); len(sent) != 1 || sent[0]["device"] != "mac-mini" {
		t.Fatalf("checked %v", sent)
	}

	// The check is only for the first host.
	h.env.Ask = h.answers(nil)
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080", false, false); err != nil {
		t.Fatalf("first add: %v\n%s", err, h.out)
	}
	checks := strings.Count(state("hosts-checks"), "check-hosts")
	if err := HostAdd(ctx, h.env, "home", "wiki", "mac-mini:3000", false, false); err != nil {
		t.Fatalf("second add: %v\n%s", err, h.out)
	}
	if got := strings.Count(state("hosts-checks"), "check-hosts"); got != checks {
		t.Fatalf("checked again: %d, then %d", checks, got)
	}
}

func TestSetHostsWarningsAreShown(t *testing.T) {
	h := newHarness(t)
	setUpHome(t, h, nil)
	h.env.Ask = h.answers(nil)
	reply := `{"hosts": [{"name": "grafana.mesh.coveetest.io", "target": "x"}], "changed": true, "warnings": ["mac-mini has not been online for 3 days", "port 8080 is also used by wiki"]}` + "\n"
	_ = os.WriteFile(filepath.Join(h.state, "set-hosts-reply"), []byte(reply), 0o600)
	h.out.Reset()
	if err := HostAdd(context.Background(), h.env, "home", "grafana", "mac-mini:8080", false, false); err != nil {
		t.Fatalf("add: %v\n%s", err, h.out)
	}
	for _, want := range []string{"Note: mac-mini has not been online for 3 days", "Note: port 8080 is also used by wiki"} {
		if !strings.Contains(h.out.String(), want) {
			t.Fatalf("no %q:\n%s", want, h.out)
		}
	}
}

func TestAStaleRecordDoesNotDropHosts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	h.env.Ask = h.answers(nil)
	if err := HostAdd(ctx, h.env, "home", "grafana", "mac-mini:8080", false, false); err != nil {
		t.Fatalf("first add: %v\n%s", err, h.out)
	}
	serverFile := filepath.Join(h.state, "server-hosts.json")

	// Another computer added wiki, moved grafana, and this one still knows only grafana.
	other := `{"hosts": [
  {"name": "grafana.mesh.coveetest.io", "address": "100.64.0.7", "port": 9090, "path": "/g", "scheme": "https", "verify": false, "device": "mac-mini"},
  {"name": "wiki.mesh.coveetest.io", "address": "100.64.0.8", "port": 3000, "path": "", "scheme": "http", "verify": true, "device": "nas"}]}`
	_ = os.WriteFile(serverFile, []byte(other), 0o600)
	h.out.Reset()
	if err := HostAdd(ctx, h.env, "home", "photos", "nas:2342", false, false); err != nil {
		t.Fatalf("add: %v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "grafana goes elsewhere on the server, wiki is only on the server") {
		t.Fatalf("no explanation:\n%s", h.out)
	}
	sent := hostsSent(t, h)
	if len(sent) != 3 || sent[0]["port"] != 9090.0 || sent[0]["verify"] != false || sent[1]["name"] != "wiki" || sent[2]["name"] != "photos" {
		t.Fatalf("sent %v", sent)
	}
	if n, _ := h.env.Records.Load("home"); len(n.Hosts) != 3 || n.Hosts[0] != (record.Host{Name: "grafana", Device: "mac-mini", Port: 9090, Path: "/g", Scheme: "https", NoVerify: true}) {
		t.Fatalf("record: %+v", n.Hosts)
	}

	// In step again: nothing to say.
	h.out.Reset()
	if err := HostAdd(ctx, h.env, "home", "files", "nas:8000", false, false); err != nil || strings.Contains(h.out.String(), "differs") {
		t.Fatalf("add: %v\n%s", err, h.out)
	}

	// A host only the server knows can be removed; one it dropped cannot.
	_ = os.WriteFile(serverFile, []byte(other), 0o600)
	if err := HostRemove(ctx, h.env, "home", "photos"); err == nil || !strings.Contains(err.Error(), "no host named photos") {
		t.Fatalf("remove what the server no longer has: %v", err)
	}
	if n, _ := h.env.Records.Load("home"); len(n.Hosts) != 2 {
		t.Fatalf("the record did not catch up: %+v", n.Hosts)
	}
	if err := HostRemove(ctx, h.env, "home", "wiki"); err != nil {
		t.Fatalf("remove: %v\n%s", err, h.out)
	}
	if sent = hostsSent(t, h); len(sent) != 1 || sent[0]["name"] != "grafana" {
		t.Fatalf("sent %v", sent)
	}

	// If the server's list cannot be read, nothing is sent.
	calls := func() int { return strings.Count(string(mustRead(t, h, "hosts-calls")), "set-hosts") }
	before := calls()
	_ = os.WriteFile(filepath.Join(h.state, "fail-read-hosts"), nil, 0o600)
	if err := HostAdd(ctx, h.env, "home", "a1", "nas:1", false, false); err == nil || !strings.Contains(err.Error(), "reading the network's hosts") {
		t.Fatalf("unreadable: %v", err)
	}
	os.Remove(filepath.Join(h.state, "fail-read-hosts"))
	_ = os.WriteFile(serverFile, []byte("not json"), 0o600)
	if err := HostAdd(ctx, h.env, "home", "a1", "nas:1", false, false); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("damaged: %v", err)
	}
	os.Remove(serverFile)
	if err := HostAdd(ctx, h.env, "home", "a1", "nas:1", false, false); err == nil || !strings.Contains(err.Error(), "has no list of hosts") {
		t.Fatalf("missing: %v", err)
	}
	if calls() != before {
		t.Fatal("hosts were sent although the server's list could not be read")
	}
	if n, _ := h.env.Records.Load("home"); len(n.Hosts) != 1 {
		t.Fatalf("record: %+v", n.Hosts)
	}
}

const backupHostsFile = `{"hosts": [
  {"name": "grafana.mesh.coveetest.io", "address": "100.64.0.7", "port": 8080, "path": "/some/sub/service", "scheme": "http", "verify": true, "device": "mac-mini"},
  {"name": "nas.mesh.coveetest.io", "address": "100.64.0.8", "port": 5001, "path": "", "scheme": "https", "verify": false, "device": "nas"}]}`

func restoreBackupOf(t *testing.T, h *harness, spec map[string]any, files map[string]string) error {
	t.Helper()
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	archive, keyFile := filepath.Join(dir, "home.tar.age"), filepath.Join(dir, "backup.key")
	writeBackupOf(t, archive, id.Recipient(), "control.coveetest.io", spec, files)
	_ = os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600)
	// Saying no to the console must not matter: the restored network keeps what its backup has.
	h.env.Ask = h.answers(map[string]string{"start_from": labelBackup, "backup_file": archive, "backup_key": keyFile, "hostname": "", "sign_in": "", "console_in_network": "no"})
	return Run(context.Background(), h.env, Options{Network: "home"})
}

func TestRestoreKeepsHostsAndTheirCertificate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	err := restoreBackupOf(t, h, map[string]any{"hosts": true, "console_in_network": true}, map[string]string{serverHostsFile: backupHostsFile})
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, h.out)
	}
	n, _ := h.env.Records.Load("home")
	want := []record.Host{
		{Name: "grafana", Device: "mac-mini", Port: 8080, Path: "/some/sub/service", Scheme: "http"},
		{Name: "nas", Device: "nas", Port: 5001, Scheme: "https", NoVerify: true},
	}
	if !n.HostsEnabled || !n.ConsoleInNetwork || !slices.Equal(n.Hosts, want) {
		t.Fatalf("record: hosts %v console %v %+v", n.HostsEnabled, n.ConsoleInNetwork, n.Hosts)
	}
	if got := strings.Join(h.ca.names, ","); got != "control.coveetest.io,*.mesh.coveetest.io" {
		t.Fatalf("certificate names %s", got)
	}
	var spec map[string]any
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if spec["hosts"] != true || spec["console_in_network"] != true {
		t.Fatalf("the server's deployment config lost them: %v", spec)
	}
	if !strings.Contains(h.out.String(), "The backup's 2 host(s) carry over") {
		t.Fatalf("the summary does not mention them:\n%s", h.out)
	}
	// The next add keeps the restored hosts, and needs no new certificate.
	_ = os.WriteFile(filepath.Join(h.state, "server-hosts.json"), []byte(backupHostsFile), 0o600)
	h.out.Reset()
	before := h.ca.obtained
	h.env.Ask = h.answers(nil)
	if err := HostAdd(ctx, h.env, "home", "wiki", "nas:3000", false, false); err != nil {
		t.Fatalf("add: %v\n%s", err, h.out)
	}
	if sent := hostsSent(t, h); len(sent) != 3 || h.ca.obtained != before || strings.Contains(h.out.String(), "differs") {
		t.Fatalf("sent %v, certificates %d\n%s", sent, h.ca.obtained-before, h.out)
	}
}

func TestRestoreKeepsTheConsoleInTheNetwork(t *testing.T) {
	h := newHarness(t)
	if err := restoreBackupOf(t, h, map[string]any{"console_in_network": true}, nil); err != nil {
		t.Fatalf("restore: %v\n%s", err, h.out)
	}
	n, _ := h.env.Records.Load("home")
	if !n.ConsoleInNetwork || n.HostsEnabled || strings.Join(h.ca.names, ",") != "control.coveetest.io,console.mesh.coveetest.io" {
		t.Fatalf("console %v, hosts %v, names %v", n.ConsoleInNetwork, n.HostsEnabled, h.ca.names)
	}
}

func TestRestoreWithoutTheConsoleDoesNotAddIt(t *testing.T) {
	h := newHarness(t)
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	archive, keyFile := filepath.Join(dir, "home.tar.age"), filepath.Join(dir, "backup.key")
	writeBackup(t, archive, id.Recipient(), "control.coveetest.io")
	_ = os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600)
	// The question is not asked, so a yes does not turn it on.
	h.env.Ask = h.answers(map[string]string{"start_from": labelBackup, "backup_file": archive, "backup_key": keyFile, "hostname": "", "sign_in": "", "console_in_network": "yes"})
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("restore: %v\n%s", err, h.out)
	}
	n, _ := h.env.Records.Load("home")
	if n.ConsoleInNetwork || strings.Join(h.ca.names, ",") != "control.coveetest.io" {
		t.Fatalf("console %v, names %v", n.ConsoleInNetwork, h.ca.names)
	}
}

func TestRestoreReadsHostsOnlyWhenTheBackupHasThemOn(t *testing.T) {
	// Hosts on but no list: no hosts yet. Off: a leftover file is ignored.
	h := newHarness(t)
	if err := restoreBackupOf(t, h, map[string]any{"hosts": true}, nil); err != nil {
		t.Fatalf("restore: %v\n%s", err, h.out)
	}
	if n, _ := h.env.Records.Load("home"); !n.HostsEnabled || n.Hosts != nil {
		t.Fatalf("record: %v %+v", n.HostsEnabled, n.Hosts)
	}
	h = newHarness(t)
	if err := restoreBackupOf(t, h, nil, map[string]string{serverHostsFile: backupHostsFile}); err != nil {
		t.Fatalf("restore: %v\n%s", err, h.out)
	}
	if n, _ := h.env.Records.Load("home"); n.HostsEnabled || n.Hosts != nil {
		t.Fatalf("record: %v %+v", n.HostsEnabled, n.Hosts)
	}
	// A damaged list stops the restore: the next add would otherwise wipe the hosts.
	for body, hint := range map[string]string{
		"not json": "unreadable",
		`{"hosts": [{"name": "grafana.other.example.org", "device": "a", "port": 1}]}`: "not a name under mesh.coveetest.io",
		`{"hosts": [{"name": "a.b.mesh.coveetest.io", "device": "a", "port": 1}]}`:     "not a name under mesh.coveetest.io",
		`{"hosts": [{"name": "grafana.mesh.coveetest.io", "port": 1}]}`:                "no device and port",
	} {
		h = newHarness(t)
		err := restoreBackupOf(t, h, map[string]any{"hosts": true}, map[string]string{serverHostsFile: body})
		if err == nil || !strings.Contains(err.Error(), "the backup's hosts") || !strings.Contains(err.Error(), hint) {
			t.Errorf("%s: %v", body, err)
		}
	}
}

func TestRestoreRefusesNamesOutsideTheDNSZone(t *testing.T) {
	h := newHarness(t)
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	archive, keyFile := filepath.Join(dir, "home.tar.age"), filepath.Join(dir, "backup.key")
	writeBackupOf(t, archive, id.Recipient(), "control.coveetest.io", map[string]any{"hosts": true, "dns_base_domain": "mesh.elsewhere.example.org"}, nil)
	_ = os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600)
	h.env.Ask = h.answers(map[string]string{"start_from": labelBackup, "backup_file": archive, "backup_key": keyFile, "hostname": "", "sign_in": ""})
	err := Run(context.Background(), h.env, Options{Network: "home"})
	if err == nil || !strings.Contains(err.Error(), "outside the DNS zone") {
		t.Fatalf("got %v", err)
	}
	if h.ca.obtained != 0 {
		t.Fatal("a certificate was requested")
	}
}

func mustRead(t *testing.T, h *harness, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
