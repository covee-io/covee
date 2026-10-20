package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"covee.io/cli/internal/cert"
	"covee.io/cli/internal/dns"
)

// cfAPI is a minimal Cloudflare zone for setup: it keeps records and counts changes.
type cfAPI struct {
	mu      sync.Mutex
	records map[string]map[string]any // id -> record
	next    int
	writes  []string
	tokens  []string
}

func (c *cfAPI) serve(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.tokens = append(c.tokens, r.Header.Get("Authorization"))
		reply := func(v any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": v})
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if r.Method != "GET" {
			c.writes = append(c.writes, r.Method+" "+r.URL.Path)
		}
		zone := map[string]any{"id": "zone-office", "name": "example-office.net", "name_servers": []string{"ana.ns.cloudflare.com"}}
		switch {
		case r.Method == "GET" && len(parts) == 1:
			if r.URL.Query().Get("name") == "example-office.net" {
				reply([]any{zone})
			} else {
				reply([]any{})
			}
		case r.Method == "GET" && len(parts) == 2:
			reply(zone)
		case r.Method == "GET" && len(parts) == 3:
			out := []any{}
			for _, rec := range c.records {
				if rec["type"] == r.URL.Query().Get("type") && rec["name"] == r.URL.Query().Get("name") {
					out = append(out, rec)
				}
			}
			reply(out)
		case r.Method == "POST" && len(parts) == 3:
			var rec map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rec)
			c.next++
			rec["id"] = fmt.Sprintf("rec-%d", c.next)
			c.records[rec["id"].(string)] = rec
			reply(rec)
		case r.Method == "DELETE" && len(parts) == 4:
			delete(c.records, parts[3])
			reply(map[string]any{"id": parts[3]})
		default:
			t.Errorf("unexpected Cloudflare call %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
}

func (c *cfAPI) txt(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, rec := range c.records {
		if rec["type"] == "TXT" && rec["name"] == name {
			out = append(out, strings.Trim(rec["content"].(string), `"`))
		}
	}
	return out
}

// txtCA proves each name with a TXT record through the network's DNS provider.
type txtCA struct {
	fakeCA
	proved []string
}

func (f *txtCA) Obtain(ctx context.Context, hosts []string, account []byte, provider dns.Provider, say func(string, ...any)) (*cert.Result, []byte, error) {
	for _, h := range hosts {
		name := "_acme-challenge." + h
		if err := provider.SetTXT(ctx, name, "proof-"+h); err != nil {
			return nil, nil, err
		}
		f.proved = append(f.proved, name)
		if err := provider.RemoveTXT(ctx, name, "proof-"+h); err != nil {
			return nil, nil, err
		}
	}
	return f.fakeCA.Obtain(ctx, hosts, account, provider, say)
}

// An Azure VM managed over the private network, with its public name kept in
// Cloudflare by OpenTofu: setup leaves that record alone, proves both names
// through Cloudflare and keeps the token as a secret of record.
func TestSetupWithCloudflareDNSOnACloudServer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	facts := `{"os":"ubuntu","codename":"noble","pretty":"Ubuntu 24.04.3 LTS","architecture":"amd64","hostname":"vm-covee",` +
		`"interface":"eth0","ipv4_cidr":"10.60.8.4/28","dhcp":true,"ssh_client":"10.60.6.5","virtualization":"microsoft",` +
		`"public_ipv4":"203.0.113.30","service_user":false,"prepared":false,"docker":false,"passwordless_sudo":true}`
	if err := os.WriteFile(filepath.Join(h.state, "facts.json"), []byte(facts+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.state, "issuer.json"), []byte(`{"issuer":"https://covee.example-office.net/identity"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.env.HTTP = &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"issuer":"https://covee.example-office.net/identity"}`))}, nil
	})}
	api := &cfAPI{records: map[string]map[string]any{
		"tofu": {"id": "tofu", "type": "A", "name": "covee.example-office.net", "content": "203.0.113.30", "ttl": 300, "proxied": false, "comment": "infra-repo"},
	}}
	srv := api.serve(t)
	defer srv.Close()
	h.env.CloudflareBase = srv.URL
	h.env.CloudflareLookup = func(_ context.Context, server, name string) ([]string, error) { return api.txt(name), nil }
	ca := &txtCA{}
	h.env.CA = func(bool) CertAuthority { return ca }
	// The token was put in Parameter Store beforehand, never typed.
	h.ssm.values["/covee/office/cloudflare-dns-token"] = "cf-token-0123456789abcdefghij"

	h.env.Ask = h.answers(map[string]string{
		"organization": "Example Co", "network": "office", "hostname": "covee.example-office.net",
		"dns_host": labelCloudflare, "cloudflare_token": "/covee/office/cloudflare-dns-token",
		"server_address": "10.60.8.4", "server_user": "azureuser", "ssh_sources": "10.60.6.0/28",
	})
	if err := Run(ctx, h.env, Options{Network: "office"}); err != nil {
		t.Fatalf("setup failed: %v\n%s", err, h.out)
	}
	n, err := h.env.Records.Load("office")
	if err != nil {
		t.Fatal(err)
	}
	if n.DNS.Host != "cloudflare" || n.DNS.ZoneID != "zone-office" || n.DNS.Zone != "example-office.net" || n.DNS.Token != "/covee/office/cloudflare-dns-token" {
		t.Fatalf("DNS record = %+v", n.DNS)
	}
	if n.PublicAddress != "203.0.113.30" || n.DNSBaseDomain != "mesh.example-office.net" || strings.Join(n.Server.SSHSources, ",") != "10.60.6.0/28" {
		t.Fatalf("record does not match the answers: %+v", n)
	}
	for _, w := range api.writes {
		if strings.Contains(w, "/tofu") || (strings.HasPrefix(w, "POST") && len(api.records) > 1) {
			t.Fatalf("the record kept by OpenTofu must stay untouched and no TXT record may be left: %v", api.writes)
		}
	}
	if len(api.records) != 1 || api.records["tofu"]["content"] != "203.0.113.30" {
		t.Fatalf("records afterwards = %v", api.records)
	}
	want := []string{"_acme-challenge.covee.example-office.net", "_acme-challenge.console.mesh.example-office.net"}
	if strings.Join(ca.proved, ",") != strings.Join(want, ",") {
		t.Fatalf("proved %v, want %v", ca.proved, want)
	}
	for _, tok := range api.tokens {
		if tok != "Bearer cf-token-0123456789abcdefghij" {
			t.Fatalf("Cloudflare got the wrong token: %q", tok)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(h.env.Home, "networks", "office.json"))
	if strings.Contains(string(raw), "cf-token-") {
		t.Fatal("the record contains the token")
	}
	if b, err := os.ReadFile(filepath.Join(h.env.Home, "secrets", "office", "cloudflare-dns-token")); err != nil || string(b) != "cf-token-0123456789abcdefghij" {
		t.Fatalf("local copy of the token: %q %v", b, err)
	}
	if n.SignIn.Entra == nil || n.SignIn.Entra.GroupName != "Covee office users" || !strings.Contains(h.out.String(), `"Covee office users" group`) {
		t.Fatalf("Microsoft sign-in must use the network's own group: %+v\n%s", n.SignIn.Entra, h.out)
	}

	// A later command, in a new process on another computer, reads the token
	// from Parameter Store.
	if err := os.RemoveAll(filepath.Join(h.env.Home, "secrets", "office")); err != nil {
		t.Fatal(err)
	}
	later := &session{env: h.env, n: n}
	if err := later.ensureAWS(ctx); err != nil {
		t.Fatal(err)
	}
	if err := later.dnsProvider().SetTXT(ctx, "_acme-challenge.covee.example-office.net", "renewal"); err != nil {
		t.Fatalf("a later renewal could not use the stored token: %v", err)
	}
	if got := api.txt("_acme-challenge.covee.example-office.net"); len(got) != 1 || got[0] != "renewal" {
		t.Fatalf("TXT values = %v", got)
	}
}
