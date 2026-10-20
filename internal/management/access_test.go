package management

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPolicyEditsAddOnlyWhatIsMissingAndKeepComments(t *testing.T) {
	policy := `{
  // Our printers.
  "tagOwners": {"tag:printer": []},
  "grants": [
    {"src": ["autogroup:member"], "dst": ["tag:printer"], "ip": ["tcp:631"]}, // printing
  ],
}`
	server := grant{Src: []string{"autogroup:member"}, Dst: []string{"tag:server"}, IP: []string{"*"}}
	text, changed, err := withAccess(policy, []string{"tag:server"}, []grant{server})
	if err != nil || !changed {
		t.Fatalf("withAccess: %v %v", changed, err)
	}
	for _, want := range []string{"// Our printers.", "// printing", `"tag:printer"`, `"tag:server"`, "tcp:631"} {
		if !strings.Contains(text, want) {
			t.Fatalf("policy lost %q:\n%s", want, text)
		}
	}
	if again, changed, err := withAccess(text, []string{"tag:server"}, []grant{server}); err != nil || changed || again != text {
		t.Fatalf("a second edit changed the policy: %v %v", changed, err)
	}
	// A policy without tagOwners or grants gets both sections.
	text, changed, err = withAccess(`{"ssh": []}`, []string{"tag:server"}, []grant{server})
	if err != nil || !changed || !strings.Contains(text, `"tagOwners"`) || !strings.Contains(text, `"grants"`) {
		t.Fatalf("empty policy edit: %v %v\n%s", changed, err, text)
	}
	if _, _, err := withAccess(`{"grants": {}}`, nil, []grant{server}); err == nil {
		t.Fatal("a malformed grants section was accepted")
	}
}

// fakeHeadscale records policy writes, key requests and route approvals.
type fakeHeadscale struct {
	policy   string
	keyBody  map[string]any
	approved []string
	checks   int
}

func (f *fakeHeadscale) handle(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/policy":
			json.NewEncoder(w).Encode(map[string]string{"policy": f.policy})
		case "POST /api/v1/policy/check":
			f.checks++
			io.WriteString(w, `{}`)
		case "PUT /api/v1/policy":
			f.policy = in["policy"].(string)
			json.NewEncoder(w).Encode(map[string]string{"policy": f.policy})
		case "POST /api/v1/preauthkey":
			f.keyBody = in
			io.WriteString(w, `{"preAuthKey":{"id":"9","key":"server-join-secret","aclTags":["tag:server"]}}`)
		case "GET /api/v1/preauthkey":
			io.WriteString(w, `{"pre_auth_keys":[{"id":"5","key":"x","acl_tags":["tag:server"]},{"id":"6","user":{"id":"2"},"key":"y"}]}`)
		case "POST /api/v1/preauthkey/expire":
			io.WriteString(w, `{}`)
		case "GET /api/v1/node/4":
			io.WriteString(w, `{"node":{"id":"4","given_name":"homeserver","available_routes":["0.0.0.0/0","::/0","192.168.1.0/24"]}}`)
		case "POST /api/v1/node/4/approve_routes":
			for _, route := range in["routes"].([]any) {
				f.approved = append(f.approved, route.(string))
			}
			io.WriteString(w, `{"node":{"id":"4","given_name":"homeserver","available_routes":["0.0.0.0/0","::/0","192.168.1.0/24"],"approved_routes":["0.0.0.0/0","::/0","192.168.1.0/24"]}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}
}

func TestServerKeysAreTagOwnedAndCanOpenAccess(t *testing.T) {
	f := &fakeHeadscale{policy: `{"grants": [], "ssh": []}`}
	s := newTestServer(t, f.handle(t))
	s.config.ControlURL = "https://control.example.test"
	w := request(s, "POST", "/api/keys", `{"tags":["tag:server"],"expiryHours":24,"reusable":true,"allowMembers":true}`, bearer(), nil)
	assertStatus(t, w, 201)
	var out struct {
		Secret     string `json:"secret"`
		ControlURL string `json:"controlURL"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Secret != "server-join-secret" || out.ControlURL != "https://control.example.test" {
		t.Fatalf("create reply: %s", w.Body.String())
	}
	if _, hasUser := f.keyBody["user"]; hasUser || f.keyBody["reusable"] != true {
		t.Fatalf("a server key must have no user: %v", f.keyBody)
	}
	if f.checks != 1 || !strings.Contains(f.policy, `"tag:server": []`) || !strings.Contains(f.policy, `"dst": ["tag:server"]`) {
		t.Fatalf("policy after server key:\n%s", f.policy)
	}
	// Without the access rule, the tag still gets its owner entry.
	f.policy = `{"grants": []}`
	assertStatus(t, request(s, "POST", "/api/keys", `{"tags":["tag:backup"],"expiryHours":1}`, bearer(), nil), 201)
	if !strings.Contains(f.policy, `"tag:backup": []`) || strings.Contains(f.policy, `"dst": ["tag:backup"]`) {
		t.Fatalf("policy after a key without the rule:\n%s", f.policy)
	}
	// Without a user, a key needs a tag; allowMembers needs tags too.
	assertStatus(t, request(s, "POST", "/api/keys", `{"expiryHours":24}`, bearer(), nil), 400)
	assertStatus(t, request(s, "POST", "/api/keys", `{"userId":"2","allowMembers":true}`, bearer(), nil), 400)

	w = request(s, "GET", "/api/keys?owner=tags", "", bearer(), nil)
	assertStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"id":"5"`) || strings.Contains(w.Body.String(), `"id":"6"`) || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("tag-owned key list: %s", w.Body.String())
	}
	assertStatus(t, request(s, "POST", "/api/keys/5/expire", `{"tagged":true}`, bearer(), nil), 200)
	assertStatus(t, request(s, "POST", "/api/keys/6/expire", `{"tagged":true}`, bearer(), nil), 404)
}

func TestRouteApprovalAllowsOnlyOfferedRoutesAndCanGrantThem(t *testing.T) {
	f := &fakeHeadscale{policy: `{"grants": [], "ssh": []}`}
	s := newTestServer(t, f.handle(t))
	assertStatus(t, request(s, "POST", "/api/devices/4/routes", `{"routes":["10.0.0.0/8"]}`, bearer(), nil), 400)
	assertStatus(t, request(s, "POST", "/api/devices/4/routes", `{"routes":["192.168.1.7/24"]}`, bearer(), nil), 400)
	if f.approved != nil || f.checks != 0 {
		t.Fatal("refused routes reached Headscale")
	}
	w := request(s, "POST", "/api/devices/4/routes", `{"routes":["0.0.0.0/0","::/0","192.168.1.0/24"],"allowMembers":true}`, bearer(), nil)
	assertStatus(t, w, 200)
	if strings.Join(f.approved, ",") != "0.0.0.0/0,::/0,192.168.1.0/24" {
		t.Fatalf("approved %v", f.approved)
	}
	for _, want := range []string{`"dst": ["autogroup:internet"]`, `"dst": ["192.168.1.0/24"]`} {
		if !strings.Contains(f.policy, want) {
			t.Fatalf("policy lacks %s:\n%s", want, f.policy)
		}
	}
	if !strings.Contains(w.Body.String(), `"approvedRoutes":["0.0.0.0/0","::/0","192.168.1.0/24"]`) {
		t.Fatalf("reply: %s", w.Body.String())
	}
}

func TestControlURLComesFromSettingOrBrokeredIssuer(t *testing.T) {
	if got := (Config{ControlURL: "https://control.example.test"}).controlURL(); got != "https://control.example.test" {
		t.Fatal(got)
	}
	if got := (Config{OIDCIssuer: "https://control.example.test/identity"}).controlURL(); got != "https://control.example.test" {
		t.Fatal(got)
	}
	if got := (Config{OIDCIssuer: "https://login.microsoftonline.com/tenant/v2.0"}).controlURL(); got != "" {
		t.Fatalf("a non-brokered issuer gave %q", got)
	}
}
