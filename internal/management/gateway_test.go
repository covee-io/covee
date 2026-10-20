package management

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tailscale/hujson"
)

func TestGatewaySettingsAreCheckedAndCleaned(t *testing.T) {
	good, err := cleanSettings(GatewaySettings{
		Entries: []GatewayEntry{{Label: " Azure ", Destinations: []string{"10.20.0.0/16", "DB.Example.com.", "10.20.0.0/16", "203.0.113.7"}, Users: []string{"b@x.io", "a@x.io", "a@x.io"}}},
		DNS:     []GatewayDNS{{Domain: "Vault.Azure.Net.", Resolvers: []string{"168.63.129.16"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := good.Entries[0]
	if e.Label != "Azure" || strings.Join(e.Destinations, ",") != "10.20.0.0/16,db.example.com,203.0.113.7/32" || strings.Join(e.Users, ",") != "a@x.io,b@x.io" || e.ID == "" {
		t.Fatalf("cleaned entry = %+v", e)
	}
	if good.DNS[0].Domain != "vault.azure.net" {
		t.Fatalf("cleaned DNS = %+v", good.DNS)
	}
	for name, bad := range map[string]GatewaySettings{
		"no label":           {Entries: []GatewayEntry{{Destinations: []string{"10.0.0.0/8"}}}},
		"no destinations":    {Entries: []GatewayEntry{{Label: "x"}}},
		"internet":           {Entries: []GatewayEntry{{Label: "x", Destinations: []string{"0.0.0.0/0"}}}},
		"not canonical":      {Entries: []GatewayEntry{{Label: "x", Destinations: []string{"10.1.2.3/8"}}}},
		"network's own":      {Entries: []GatewayEntry{{Label: "x", Destinations: []string{"100.64.0.0/16"}}}},
		"wildcard":           {Entries: []GatewayEntry{{Label: "x", Destinations: []string{"*.example.com"}}}},
		"single label":       {Entries: []GatewayEntry{{Label: "x", Destinations: []string{"intranet"}}}},
		"user with a space":  {Entries: []GatewayEntry{{Label: "x", Destinations: []string{"10.0.0.0/8"}, Users: []string{"a b"}}}},
		"loopback resolver":  {DNS: []GatewayDNS{{Domain: "vault.azure.net", Resolvers: []string{"127.0.0.1"}}}},
		"no resolver":        {DNS: []GatewayDNS{{Domain: "vault.azure.net"}}},
		"domain twice":       {DNS: []GatewayDNS{{Domain: "a.io", Resolvers: []string{"10.0.0.2"}}, {Domain: "a.io", Resolvers: []string{"10.0.0.3"}}}},
		"single-label zone":  {DNS: []GatewayDNS{{Domain: "local", Resolvers: []string{"10.0.0.2"}}}},
		"tailnet resolver":   {DNS: []GatewayDNS{{Domain: "a.io", Resolvers: []string{"100.100.100.100"}}}},
		"unnamed with a pad": {Entries: []GatewayEntry{{Label: "   ", Destinations: []string{"10.0.0.0/8"}}}},
	} {
		if _, err := cleanSettings(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestGatewayGrantEditsTouchOnlyItsOwnRules(t *testing.T) {
	policy := `{
  // Printers.
  "grants": [
    {"src": ["autogroup:member"], "dst": ["tag:printer"], "ip": ["tcp:631"]}, // printing
    {"src": ["autogroup:member"], "dst": ["10.1.0.0/16"], "ip": ["*"]},
  ],
}`
	old := []grant{{Src: []string{"autogroup:member"}, Dst: []string{"10.1.0.0/16"}, IP: []string{"*"}}}
	current := []grant{{Src: []string{"a@x.io"}, Dst: []string{"10.2.0.0/16"}, IP: []string{"*"}}}
	text, changed, err := withGrantsReplaced(policy, old, current)
	if err != nil || !changed {
		t.Fatalf("edit: %v %v", changed, err)
	}
	if !strings.Contains(text, "// Printers.") || !strings.Contains(text, "// printing") || !strings.Contains(text, "tcp:631") {
		t.Fatalf("lost other rules or comments:\n%s", text)
	}
	if strings.Contains(text, "10.1.0.0/16") || !strings.Contains(text, "10.2.0.0/16") {
		t.Fatalf("rules not replaced:\n%s", text)
	}
	if again, changed, err := withGrantsReplaced(text, current, current); err != nil || changed || again != text {
		t.Fatalf("an unchanged set edited the policy: %v %v", changed, err)
	}
	// A rule someone else wrote that matches only in part stays.
	other := `{"grants": [{"src": ["autogroup:member"], "dst": ["10.1.0.0/16"], "ip": ["tcp:22"]}]}`
	if _, changed, _ := withGrantsReplaced(other, old, nil); changed {
		t.Fatal("removed a rule this service did not write")
	}
}

// fakeGatewayHeadscale is a coordinator with one gateway device.
type fakeGatewayHeadscale struct {
	mu       sync.Mutex
	policy   string
	offered  []string
	approved []string
	writes   int
}

func (f *fakeGatewayHeadscale) handle(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		node := func() map[string]any {
			return map[string]any{"id": "12", "given_name": "gateway", "tags": []string{"tag:covee-gateway"}, "online": true,
				"available_routes": f.offered, "approved_routes": f.approved}
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/policy":
			json.NewEncoder(w).Encode(map[string]string{"policy": f.policy})
		case "POST /api/v1/policy/check":
			io.WriteString(w, `{}`)
		case "PUT /api/v1/policy":
			f.policy = in["policy"].(string)
			f.writes++
			json.NewEncoder(w).Encode(map[string]string{"policy": f.policy})
		case "GET /api/v1/node":
			json.NewEncoder(w).Encode(map[string]any{"nodes": []any{map[string]any{"id": "3", "given_name": "laptop"}, node()}})
		case "POST /api/v1/node/12/approve_routes":
			f.approved = nil
			for _, route := range in["routes"].([]any) {
				f.approved = append(f.approved, route.(string))
			}
			json.NewEncoder(w).Encode(map[string]any{"node": node()})
		case "GET /api/v1/user":
			io.WriteString(w, `{"users":[{"id":"1","name":"alice@example.com"},{"id":"2","name":"bob","email":"bob@example.com"}]}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
}

func newGatewayServer(t *testing.T, f *fakeGatewayHeadscale) (*Server, string) {
	t.Helper()
	up := httptest.NewServer(f.handle(t))
	t.Cleanup(up.Close)
	dir := filepath.Join(t.TempDir(), "gateway")
	s, err := New(Config{Listen: "127.0.0.1:8088", PublicURL: "http://127.0.0.1:8088", AdminToken: testToken, HeadscaleURL: up.URL,
		HeadscaleAPIKey: testAPIKey, DataDir: t.TempDir(), GatewayTag: "tag:covee-gateway", GatewayDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.gateway.mu.Lock()
	s.gateway.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "cluster0-shard-00-00.abc.mongodb.net":
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		case "kv-example.vault.azure.net":
			return []netip.Addr{netip.MustParseAddr("10.60.7.4"), netip.MustParseAddr("::ffff:10.60.7.4")}, nil
		}
		return nil, errors.New("no such host")
	}
	s.gateway.mu.Unlock()
	return s, dir
}

func gatewayState(t *testing.T, s *Server) (revision string, body string) {
	t.Helper()
	w := request(s, "GET", "/api/gateway", "", bearer(), nil)
	assertStatus(t, w, 200)
	var out struct {
		Revision string `json:"revision"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out.Revision, w.Body.String()
}

// wantGrants checks the policy's grants are exactly want, in order.
func wantGrants(t *testing.T, policy string, want ...grant) {
	t.Helper()
	doc, err := hujson.Parse([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	doc.Standardize()
	var view struct{ Grants []grant }
	if err := json.Unmarshal(doc.Pack(), &view); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.Grants, want) {
		t.Fatalf("grants = %+v\nwant %+v", view.Grants, want)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func TestTheGatewayPageKeepsRoutesAccessAndDNSInStep(t *testing.T) {
	f := &fakeGatewayHeadscale{policy: "{\n  // Office printers.\n  \"grants\": [{\"src\": [\"autogroup:member\"], \"dst\": [\"tag:printer\"], \"ip\": [\"tcp:631\"]}]\n}"}
	s, dir := newGatewayServer(t, f)
	rev, _ := gatewayState(t, s)

	settings := `{"revision":"` + rev + `","entries":[
	  {"label":"Azure private networks","destinations":["10.60.0.0/16","10.20.0.0/16","kv-example.vault.azure.net"],"users":[]},
	  {"label":"MongoDB Atlas","destinations":["cluster0-shard-00-00.abc.mongodb.net"],"users":["bob@example.com","alice@example.com"]}],
	 "dns":[{"domain":"vault.azure.net","resolvers":["168.63.129.16"]}]}`
	w := request(s, "PUT", "/api/gateway", settings, bearer(), nil)
	assertStatus(t, w, 200)

	var routes struct{ Routes []string }
	readJSON(t, filepath.Join(dir, "routes.json"), &routes)
	if got := strings.Join(routes.Routes, ","); got != "10.20.0.0/16,10.60.0.0/16,10.60.7.4/32,168.63.129.16/32,203.0.113.7/32" {
		t.Fatalf("routes.json = %s", got)
	}
	var dns struct{ Split map[string][]string }
	readJSON(t, filepath.Join(dir, "dns.json"), &dns)
	if strings.Join(dns.Split["vault.azure.net"], ",") != "168.63.129.16" {
		t.Fatalf("dns.json = %v", dns)
	}
	f.mu.Lock()
	policy := f.policy
	f.mu.Unlock()
	if !strings.Contains(policy, "// Office printers.") {
		t.Fatalf("policy lost its comment:\n%s", policy)
	}
	wantGrants(t, policy,
		grant{Src: []string{"autogroup:member"}, Dst: []string{"tag:printer"}, IP: []string{"tcp:631"}},
		grant{Src: []string{"autogroup:member"}, Dst: []string{"10.20.0.0/16", "10.60.0.0/16", "10.60.7.4/32"}, IP: []string{"*"}},
		grant{Src: []string{"alice@example.com", "bob@example.com"}, Dst: []string{"203.0.113.7/32"}, IP: []string{"*"}},
		grant{Src: []string{"autogroup:member"}, Dst: []string{"168.63.129.16/32"}, IP: []string{"udp:53", "tcp:53"}})

	// The device offers some of the routes: exactly those get approved.
	f.mu.Lock()
	f.offered = []string{"10.20.0.0/16", "203.0.113.7/32", "192.168.9.0/24"}
	f.mu.Unlock()
	if err := s.reconcileGateway(context.Background(), systemActor, false); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	approved := strings.Join(f.approved, ",")
	f.mu.Unlock()
	if approved != "10.20.0.0/16,203.0.113.7/32" {
		t.Fatalf("approved %s", approved)
	}
	_, view := gatewayState(t, s)
	for _, want := range []string{`"route":"203.0.113.7/32"`, `"approved":true`, `"name":"cluster0-shard-00-00.abc.mongodb.net","addresses":["203.0.113.7"]`, `"given_name"`} {
		if want == `"given_name"` {
			if strings.Contains(view, want) {
				t.Fatalf("the view leaks the coordinator's raw fields: %s", view)
			}
			continue
		}
		if !strings.Contains(view, want) {
			t.Fatalf("view lacks %s: %s", want, view)
		}
	}

	// Taking an entry out removes its rule and route, and nothing else.
	rev, _ = gatewayState(t, s)
	w = request(s, "PUT", "/api/gateway", `{"revision":"`+rev+`","entries":[{"label":"Azure private networks","destinations":["10.20.0.0/16"],"users":[]}],"dns":[]}`, bearer(), nil)
	assertStatus(t, w, 200)
	f.mu.Lock()
	policy = f.policy
	f.mu.Unlock()
	wantGrants(t, policy,
		grant{Src: []string{"autogroup:member"}, Dst: []string{"tag:printer"}, IP: []string{"tcp:631"}},
		grant{Src: []string{"autogroup:member"}, Dst: []string{"10.20.0.0/16"}, IP: []string{"*"}})
	readJSON(t, filepath.Join(dir, "routes.json"), &routes)
	if strings.Join(routes.Routes, ",") != "10.20.0.0/16" {
		t.Fatalf("routes after removal = %v", routes.Routes)
	}
}

func TestGatewaySettingsRefuseStaleAndUnknownPeople(t *testing.T) {
	f := &fakeGatewayHeadscale{policy: `{}`}
	s, _ := newGatewayServer(t, f)
	assertStatus(t, request(s, "PUT", "/api/gateway", `{"revision":"stale","entries":[],"dns":[]}`, bearer(), nil), 409)
	rev, _ := gatewayState(t, s)
	w := request(s, "PUT", "/api/gateway", `{"revision":"`+rev+`","entries":[{"label":"x","destinations":["10.0.0.0/8"],"users":["mallory@evil.io"]}],"dns":[]}`, bearer(), nil)
	assertStatus(t, w, 400)
	if !strings.Contains(w.Body.String(), "mallory@evil.io is not a user") {
		t.Fatalf("reply: %s", w.Body.String())
	}
	assertStatus(t, request(s, "PUT", "/api/gateway", `{"revision":"`+rev+`","entries":[{"label":"x","destinations":["0.0.0.0/0"]}],"dns":[]}`, bearer(), nil), 400)
}

func TestAHostThatStopsResolvingKeepsItsAddresses(t *testing.T) {
	f := &fakeGatewayHeadscale{policy: `{}`}
	s, dir := newGatewayServer(t, f)
	rev, _ := gatewayState(t, s)
	assertStatus(t, request(s, "PUT", "/api/gateway", `{"revision":"`+rev+`","entries":[{"label":"db","destinations":["cluster0-shard-00-00.abc.mongodb.net"]}],"dns":[]}`, bearer(), nil), 200)
	s.gateway.mu.Lock()
	s.gateway.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("timeout") }
	s.gateway.mu.Unlock()
	if err := s.reconcileGateway(context.Background(), systemActor, true); err != nil {
		t.Fatal(err)
	}
	var routes struct{ Routes []string }
	readJSON(t, filepath.Join(dir, "routes.json"), &routes)
	if strings.Join(routes.Routes, ",") != "203.0.113.7/32" {
		t.Fatalf("a failed lookup removed the route: %v", routes.Routes)
	}
	if _, view := gatewayState(t, s); !strings.Contains(view, `"problem":"could not be looked up"`) {
		t.Fatalf("view does not show the lookup problem: %s", view)
	}
}

func TestWithoutAGatewayThePageSaysSo(t *testing.T) {
	s := newTestServer(t, (&fakeHeadscale{}).handle(t))
	w := request(s, "GET", "/api/gateway", "", bearer(), nil)
	assertStatus(t, w, 200)
	if strings.TrimSpace(w.Body.String()) != `{"enabled":false}` {
		t.Fatalf("reply: %s", w.Body.String())
	}
	assertStatus(t, request(s, "PUT", "/api/gateway", `{"revision":"","entries":[],"dns":[]}`, bearer(), nil), 404)
}
