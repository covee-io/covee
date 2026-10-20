package setup

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"covee.io/cli/internal/record"
)

// providerPages answers Google's and Apple's sign-in pages: a return address
// counts as registered after the given number of questions. Everything else
// gets the network's discovery document.
func providerPages(googleAfter, appleAfter int) *http.Client {
	var mu sync.Mutex
	asked := map[string]int{}
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		asked[r.URL.Host]++
		n := asked[r.URL.Host]
		mu.Unlock()
		page := func(status int, body string, header http.Header) (*http.Response, error) {
			if header == nil {
				header = http.Header{}
			}
			return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		switch r.URL.Host {
		case "accounts.google.com":
			if n > googleAfter {
				return page(302, "", http.Header{"Location": {"https://accounts.google.com/v3/signin/identifier?client_id=x"}})
			}
			return page(302, "", http.Header{"Location": {"https://accounts.google.com/signin/oauth/error?authError=x"}})
		case "appleid.apple.com":
			if n > appleAfter {
				return page(200, "<html>Sign in with Apple</html>", nil)
			}
			return page(200, `{"direct":{"errorMessage":"Invalid web redirect url.","errorCode":"invalid_request"}}`, nil)
		}
		return page(200, `{"issuer":"https://control.coveetest.io/identity"}`, nil)
	})}
}

// setUpForRename builds network home with Microsoft, Google and Apple sign-in,
// the console in the network and the address updater, all on coveetest.io.
func setUpForRename(t *testing.T, h *harness) {
	t.Helper()
	h.env.Archive = updaterArchive("# updater\n")
	setUpHome(t, h, map[string]string{"console_in_network": "yes", "dynamic_address": "yes"})
	n, _ := h.env.Records.Load("home")
	n.Providers = []string{"entra", "google", "apple"}
	n.SignIn.Google = &record.Google{ClientID: "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com", SecretName: "/covee/home/google-client-secret"}
	n.SignIn.Apple = &record.Apple{TeamID: "87LFD98HJU", ServicesID: "io.covee.signin", KeyID: "ABCDE12345", SecretName: "/covee/home/apple-private-key"}
	if err := h.env.Records.Save(n); err != nil {
		t.Fatal(err)
	}
	h.r53.zones = map[string]string{"example-owner.net": "ZEXAMPLE"}
	h.r53.listA = true
	redirectPoll, redirectWait = time.Millisecond, time.Second
	t.Cleanup(func() { redirectPoll, redirectWait = 15*time.Second, 20*time.Minute })
}

func TestRenameMovesARunningNetworkToTheOwnersDomain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpForRename(t, h)
	if h.r53.a["control.coveetest.io."] != "203.0.113.9" {
		t.Fatalf("setup did not create the old record: %v", h.r53.a)
	}
	h.env.HTTP = providerPages(1, 2)
	h.env.Ask = h.answers(map[string]string{"rename": "yes", "google_redirect_done": "yes", "apple_redirect_done": "yes", "remove_old_record": "yes"})
	h.out.Reset()
	if err := Rename(ctx, h.env, "home", "control.example-owner.net", "home.example-owner.net"); err != nil {
		t.Fatalf("rename: %v\n%s", err, h.out)
	}
	out := h.out.String()

	// DNS: the new name points at the connection, the old one is gone.
	if h.r53.a["control.example-owner.net."] != "203.0.113.9" {
		t.Fatalf("new record = %v", h.r53.a)
	}
	if _, ok := h.r53.a["control.coveetest.io."]; ok {
		t.Fatal("the old record was not deleted")
	}
	// Sign-in: Microsoft gained the new address and kept the old one; Google and Apple were waited for.
	if len(h.appChanges) != 1 {
		t.Fatalf("Microsoft app changes = %v", h.appChanges)
	}
	uris, _ := json.Marshal(h.appChanges[0])
	if !strings.Contains(string(uris), `"https://control.coveetest.io/identity/callback/entra","https://control.example-owner.net/identity/callback/entra"`) {
		t.Fatalf("redirect URIs = %s", uris)
	}
	for _, want := range []string{"https://control.example-owner.net/identity/callback/google", "Google accepts the new address",
		"Domains and subdomains: control.example-owner.net", "https://control.example-owner.net/identity/callback/apple", "Apple accepts the new address"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	// Certificate for both new names, then the server switch with it.
	if strings.Join(h.ca.names, ",") != "control.example-owner.net,console.home.example-owner.net" {
		t.Fatalf("certificate names %v", h.ca.names)
	}
	command, _ := os.ReadFile(filepath.Join(h.state, "rename-command"))
	if !strings.Contains(string(command), "scripts/deploy.py rename --control-host 'control.example-owner.net' --dns-base-domain 'home.example-owner.net' --cert /srv/covee/secrets/tls/next-fullchain.pem --key /srv/covee/secrets/tls/next-privkey.pem --directory '/srv/covee/runtime-1'") {
		t.Fatalf("rename command = %s", command)
	}
	if h.file(t, "/srv/covee/secrets/tls/next-fullchain.pem") != "CHAIN for control.example-owner.net" {
		t.Fatal("the new certificate was not sent to the server")
	}
	if moved, _ := os.ReadFile(filepath.Join(h.state, "moved")); !strings.Contains(string(moved), "next-fullchain.pem /srv/covee/secrets/tls/fullchain.pem") {
		t.Fatalf("the server does not keep the new certificate: %s", moved)
	}
	// The record and the server's settings follow.
	n, _ := h.env.Records.Load("home")
	if n.Hostname != "control.example-owner.net" || n.DNSBaseDomain != "home.example-owner.net" || n.DNS.ZoneID != "ZEXAMPLE" || n.DNS.Zone != "example-owner.net" || n.PublicAddress != "203.0.113.9" {
		t.Fatalf("record = %s %s %+v", n.Hostname, n.DNSBaseDomain, n.DNS)
	}
	var spec map[string]any
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if spec["control_host"] != "control.example-owner.net" || spec["dns_base_domain"] != "home.example-owner.net" {
		t.Fatalf("server deployment config = %v", spec)
	}
	// The address updater may now change only the new record.
	policy := h.iam.policies["covee-home-dns/covee-dns-updater"]
	if !strings.Contains(policy, `"control.example-owner.net"`) || !strings.Contains(policy, "hostedzone/ZEXAMPLE") || strings.Contains(policy, "coveetest.io") {
		t.Fatalf("updater policy = %s", policy)
	}
	var config map[string]any
	_ = json.Unmarshal([]byte(h.file(t, updaterConfig)), &config)
	if config["hostname"] != "control.example-owner.net" || config["zone_id"] != "ZEXAMPLE" {
		t.Fatalf("updater config = %v", config)
	}
	for _, want := range []string{"now answers at https://control.example-owner.net", "change the coordinator address to https://control.example-owner.net",
		"sudo tailscale down && sudo tailscale up --login-server=https://control.example-owner.net", "https://console.home.example-owner.net", "1 account(s) moved"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}

	// Again with the same names: nothing to do.
	obtained := h.ca.obtained
	if err := Rename(ctx, h.env, "home", "control.example-owner.net", "home.example-owner.net"); err != nil || h.ca.obtained != obtained {
		t.Fatalf("second run: %v (certificates %d)", err, h.ca.obtained-obtained)
	}
}

func TestRenameRefusesBeforeChangingAnything(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpForRename(t, h)
	h.env.HTTP = providerPages(0, 0)
	h.env.Ask = h.answers(map[string]string{"rename": "yes"})
	before, _ := h.env.Records.Load("home")
	cases := []struct{ host, mesh, want string }{
		{"control.home.example-owner.net", "home.example-owner.net", "would be inside it"},
		{"control.example-owner.net", "control.example-owner.net", "different name"},
		{"Control.example-owner.net", "home.example-owner.net", "lowercase"},
		{"control.elsewhere.org", "home.elsewhere.org", "no public Route 53 hosted zone"},
		{"control.example-owner.net", "home.otherzone.net", "outside the DNS zone example-owner.net"},
	}
	for _, c := range cases {
		if err := Rename(ctx, h.env, "home", c.host, c.mesh); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s/%s: expected %q, got %v", c.host, c.mesh, c.want, err)
		}
	}
	// Older Covee files on the server: update first.
	h.env.Archive = func() ([]byte, string, error) { return []byte("newer"), "fedcba9876543210fedcba9876543210", nil }
	if err := Rename(ctx, h.env, "home", "control.example-owner.net", "home.example-owner.net"); err == nil || !strings.Contains(err.Error(), "covee update home") {
		t.Fatalf("expected the update advice, got %v", err)
	}
	h.env.Archive = updaterArchive("# updater\n")
	// Covee accounts use passkeys tied to the current name.
	n, _ := h.env.Records.Load("home")
	n.SignIn.Local = &record.Local{}
	_ = h.env.Records.Save(n)
	if err := Rename(ctx, h.env, "home", "control.example-owner.net", "home.example-owner.net"); err == nil || !strings.Contains(err.Error(), "passkeys") {
		t.Fatalf("expected the passkey refusal, got %v", err)
	}
	n.SignIn.Local = nil
	_ = h.env.Records.Save(n)
	// Declined.
	h.env.Ask = h.answers(map[string]string{"rename": "no"})
	if err := Rename(ctx, h.env, "home", "control.example-owner.net", "home.example-owner.net"); err == nil {
		t.Fatal("declining must stop")
	}
	after, _ := h.env.Records.Load("home")
	if after.Hostname != before.Hostname || len(h.appChanges) != 0 || h.r53.a["control.example-owner.net."] != "" {
		t.Fatalf("something changed: %s, app changes %v, records %v", after.Hostname, h.appChanges, h.r53.a)
	}
	if _, err := os.Stat(filepath.Join(h.state, "rename-command")); err == nil {
		t.Fatal("the server was asked to rename")
	}
}

func TestRenameStopsWhileAProviderLacksTheNewAddress(t *testing.T) {
	h := newHarness(t)
	setUpForRename(t, h)
	h.env.HTTP = providerPages(1<<30, 0)
	h.env.Ask = h.answers(map[string]string{"rename": "yes", "google_redirect_done": "yes"})
	obtained := h.ca.obtained
	err := Rename(context.Background(), h.env, "home", "control.example-owner.net", "home.example-owner.net")
	if err == nil || !strings.Contains(err.Error(), "Google still does not accept the new address") || !strings.Contains(err.Error(), "nothing has changed on the network") {
		t.Fatalf("expected the Google wait to fail, got %v", err)
	}
	if h.ca.obtained != obtained {
		t.Fatal("a certificate was requested before sign-in was ready")
	}
	if _, err := os.Stat(filepath.Join(h.state, "rename-command")); err == nil {
		t.Fatal("the server was asked to rename")
	}
}

func TestAFailedSwitchKeepsTheOldNames(t *testing.T) {
	h := newHarness(t)
	setUpForRename(t, h)
	h.env.HTTP = providerPages(0, 0)
	_ = os.WriteFile(filepath.Join(h.state, "fail-rename"), nil, 0o600)
	h.env.Ask = h.answers(map[string]string{"rename": "yes"})
	err := Rename(context.Background(), h.env, "home", "control.example-owner.net", "home.example-owner.net")
	if err == nil || !strings.Contains(err.Error(), "the network kept control.coveetest.io") {
		t.Fatalf("expected the kept-old-names error, got %v", err)
	}
	n, _ := h.env.Records.Load("home")
	if n.Hostname != "control.coveetest.io" || n.DNSBaseDomain != "mesh.coveetest.io" || n.DNS.ZoneID != "ZTEST" {
		t.Fatalf("record changed: %s %s %+v", n.Hostname, n.DNSBaseDomain, n.DNS)
	}
	if removed, _ := os.ReadFile(filepath.Join(h.state, "removed")); !strings.Contains(string(removed), "next-fullchain.pem") {
		t.Fatal("the unused new certificate was left on the server")
	}
	if _, ok := h.r53.a["control.coveetest.io."]; !ok {
		t.Fatal("the old record was deleted although the network still uses it")
	}
	if !strings.Contains(h.iam.policies["covee-home-dns/covee-dns-updater"], "control.coveetest.io") {
		t.Fatal("the address updater was moved although the network kept its name")
	}
}

func TestRenameFinishesWhenOnlyTheAddressUpdaterLags(t *testing.T) {
	h := newHarness(t)
	setUpForRename(t, h)
	defer func(d time.Duration) { updaterRetryDelay = d }(updaterRetryDelay)
	updaterRetryDelay = time.Millisecond
	h.env.HTTP = providerPages(0, 0)
	// AWS has not yet applied the updater's new policy.
	_ = os.WriteFile(filepath.Join(h.state, "fail-dns-check"), nil, 0o600)
	h.env.Ask = h.answers(map[string]string{"rename": "yes", "remove_old_record": "yes"})
	err := Rename(context.Background(), h.env, "home", "control.example-owner.net", "home.example-owner.net")
	if err == nil || !strings.Contains(err.Error(), "run `covee dns auto home`") {
		t.Fatalf("expected the updater advice, got %v", err)
	}
	n, _ := h.env.Records.Load("home")
	if n.Hostname != "control.example-owner.net" {
		t.Fatalf("the record lost the switch: %s", n.Hostname)
	}
	if _, ok := h.r53.a["control.coveetest.io."]; ok {
		t.Fatal("the old record was kept")
	}
	if !strings.Contains(h.out.String(), "change the coordinator address to https://control.example-owner.net") {
		t.Fatalf("no device instructions:\n%s", h.out)
	}
	// Once AWS has caught up, `covee dns auto` finishes the job.
	os.Remove(filepath.Join(h.state, "fail-dns-check"))
	if err := DNSAuto(context.Background(), h.env, "home"); err != nil {
		t.Fatalf("dns auto: %v", err)
	}
	var config map[string]any
	_ = json.Unmarshal([]byte(h.file(t, updaterConfig)), &config)
	if config["hostname"] != "control.example-owner.net" || config["zone_id"] != "ZEXAMPLE" {
		t.Fatalf("updater config = %v", config)
	}
}
