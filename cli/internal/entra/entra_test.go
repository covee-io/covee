package entra

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type call struct {
	Method, Path string
	Body         map[string]any
}

// fakeGraph is a tiny in-memory tenant.
type fakeGraph struct {
	mu          sync.Mutex
	calls       []call
	apps        []map[string]any
	groups      []map[string]any // id, displayName
	sp          map[string]any
	assignments []map[string]any
	spMisses    int // POST /servicePrincipals fails this many times first (replication)
}

func (f *fakeGraph) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("missing token on %s", r.URL)
		}
		var body map[string]any
		data, _ := io.ReadAll(r.Body)
		if len(data) > 0 {
			_ = json.Unmarshal(data, &body)
		}
		path := r.URL.Path
		f.calls = append(f.calls, call{r.Method, path, body})
		reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.Method == "GET" && path == "/me":
			reply(map[string]any{"id": "user-1", "userPrincipalName": "alice@example.com"})
		case r.Method == "GET" && path == "/organization":
			reply(map[string]any{"value": []any{map[string]any{"displayName": "Example Co"}}})
		case r.Method == "GET" && path == "/applications":
			reply(map[string]any{"value": named(f.apps, r)})
		case r.Method == "POST" && path == "/applications":
			app := map[string]any{"id": "app-obj", "appId": "app-id", "displayName": body["displayName"], "appRoles": body["appRoles"], "web": body["web"], "groupMembershipClaims": body["groupMembershipClaims"]}
			f.apps = append(f.apps, app)
			reply(app)
		case r.Method == "GET" && strings.HasPrefix(path, "/applications/"):
			reply(f.apps[0])
		case r.Method == "PATCH" && strings.HasPrefix(path, "/applications/"):
			for k, v := range body {
				f.apps[0][k] = v
			}
			w.WriteHeader(204)
		case r.Method == "GET" && path == "/servicePrincipals":
			if f.sp == nil {
				reply(map[string]any{"value": []any{}})
			} else {
				reply(map[string]any{"value": []any{f.sp}})
			}
		case r.Method == "POST" && path == "/servicePrincipals":
			if f.spMisses > 0 {
				f.spMisses--
				w.WriteHeader(400)
				reply(map[string]any{"error": map[string]any{"code": "Request_BadRequest", "message": "The appId 'app-id' of the service principal does not reference a valid application object."}})
				return
			}
			f.sp = map[string]any{"id": "sp-1", "appRoleAssignmentRequired": body["appRoleAssignmentRequired"]}
			reply(f.sp)
		case r.Method == "PATCH" && strings.HasPrefix(path, "/servicePrincipals/"):
			f.sp["appRoleAssignmentRequired"] = body["appRoleAssignmentRequired"]
			w.WriteHeader(204)
		case r.Method == "GET" && path == "/groups":
			reply(map[string]any{"value": named(f.groups, r)})
		case r.Method == "POST" && path == "/groups":
			f.groups = append(f.groups, map[string]any{"id": "group-1", "displayName": body["displayName"], "mailNickname": body["mailNickname"]})
			reply(map[string]any{"id": "group-1"})
		case r.Method == "GET" && strings.HasSuffix(path, "/appRoleAssignedTo"):
			reply(map[string]any{"value": f.assignments})
		case r.Method == "POST" && strings.HasSuffix(path, "/appRoleAssignedTo"):
			f.assignments = append(f.assignments, body)
			reply(body)
		case r.Method == "POST" && strings.HasSuffix(path, "/addPassword"):
			reply(map[string]any{"keyId": "key-1", "secretText": "s3cr3t", "endDateTime": time.Now().AddDate(2, 0, 0).UTC().Format(time.RFC3339)})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	})
}

// named keeps the objects whose displayName the request's $filter asks for.
func named(objects []map[string]any, r *http.Request) []map[string]any {
	filter := r.URL.Query().Get("$filter")
	out := []map[string]any{}
	for _, o := range objects {
		if strings.Contains(filter, "displayName eq '"+o["displayName"].(string)+"'") {
			out = append(out, o)
		}
	}
	return out
}

func roleIDs(app map[string]any) map[string]string {
	out := map[string]string{}
	roles, _ := app["appRoles"].([]any)
	for _, r := range roles {
		m := r.(map[string]any)
		out[m["value"].(string)] = m["id"].(string)
	}
	return out
}

func TestNewTenantGetsAppRolesGroupAssignmentsAndSecret(t *testing.T) {
	fake := &fakeGraph{spMisses: 2}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	g := &Graph{Base: srv.URL, Token: "token", Settle: time.Minute, Sleep: func(time.Duration) {}}
	ctx := context.Background()
	plan, err := g.Prepare(ctx, "tenant-1", "home")
	if err != nil {
		t.Fatal(err)
	}
	if plan.App != nil || plan.GroupID != "" || plan.TenantName != "Example Co" || plan.Admin != "alice@example.com" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Describe(), "\n"), "create the app") {
		t.Fatal("plan should say it creates the app")
	}
	res, err := g.Apply(ctx, plan, "control.covee.io", "https://control.covee.io/identity/callback/entra")
	if err != nil {
		t.Fatal(err)
	}
	if res.ClientID != "app-id" || res.GroupID != "group-1" || res.GroupName != "Covee home users" || res.Secret != "s3cr3t" || res.SecretExpires.Before(time.Now().AddDate(1, 11, 0)) {
		t.Fatalf("unexpected result: %+v", res)
	}
	app := fake.apps[0]
	if app["displayName"] != "Covee home" || fake.groups[0]["displayName"] != "Covee home users" || fake.groups[0]["mailNickname"] != "covee-home-users" {
		t.Fatalf("the app and group must carry the network's name: %v %v", app["displayName"], fake.groups[0])
	}
	if app["groupMembershipClaims"] != "ApplicationGroup" {
		t.Fatal("group claims must be limited to groups assigned to the app")
	}
	ids := roleIDs(app)
	if len(ids) != 3 || ids[RoleAdmin] == "" || ids[RoleRead] == "" || ids[RoleUser] == "" {
		t.Fatalf("roles = %v", ids)
	}
	if fake.sp["appRoleAssignmentRequired"] != true {
		t.Fatal("assignment must be required")
	}
	var create map[string]any
	for _, c := range fake.calls {
		if c.Method == "POST" && c.Path == "/applications" {
			create = c.Body
		}
	}
	if create["signInAudience"] != "AzureADMyOrg" {
		t.Fatal("the app must accept only this tenant's accounts")
	}
	want := map[string]string{"user-1": ids[RoleAdmin], "group-1": ids[RoleUser]}
	if len(fake.assignments) != 2 {
		t.Fatalf("assignments = %v", fake.assignments)
	}
	for _, a := range fake.assignments {
		if want[a["principalId"].(string)] != a["appRoleId"] {
			t.Fatalf("wrong assignment %v", a)
		}
	}
}

func TestExistingAppIsReusedAndCompleted(t *testing.T) {
	claims := "SecurityGroup"
	fake := &fakeGraph{
		apps: []map[string]any{{"id": "app-obj", "appId": "app-id", "displayName": "Covee office", "groupMembershipClaims": claims,
			"web":      map[string]any{"redirectUris": []any{"https://old.covee.io/identity/callback/entra"}},
			"appRoles": []any{map[string]any{"value": RoleAdmin, "id": "r-admin", "allowedMemberTypes": []any{"User"}, "displayName": "Covee Admin", "description": "d", "isEnabled": true}}}},
		groups: []map[string]any{{"id": "group-9", "displayName": "Covee office users"}},
		sp:     map[string]any{"id": "sp-1", "appRoleAssignmentRequired": false},
	}
	fake.assignments = []map[string]any{{"principalId": "user-1", "appRoleId": "r-admin"}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	g := &Graph{Base: srv.URL, Token: "token", Settle: time.Minute, Sleep: func(time.Duration) {}}
	ctx := context.Background()
	plan, err := g.Prepare(ctx, "tenant-1", "office")
	if err != nil {
		t.Fatal(err)
	}
	if plan.App == nil || plan.GroupID != "group-9" {
		t.Fatalf("existing app and group not found: %+v", plan)
	}
	res, err := g.Apply(ctx, plan, "vpn.example.com", "https://vpn.example.com/identity/callback/entra")
	if err != nil {
		t.Fatal(err)
	}
	if res.GroupID != "group-9" || res.ClientID != "app-id" {
		t.Fatalf("unexpected result %+v", res)
	}
	app := fake.apps[0]
	uris := app["web"].(map[string]any)["redirectUris"].([]any)
	if len(uris) != 2 || uris[1] != "https://vpn.example.com/identity/callback/entra" {
		t.Fatalf("redirect URIs = %v", uris)
	}
	if app["groupMembershipClaims"] != "ApplicationGroup" {
		t.Fatal("group claims not corrected")
	}
	if ids := roleIDs(app); ids["Covee.Admin"] != "r-admin" || ids[RoleUser] == "" || ids[RoleRead] == "" {
		t.Fatalf("roles not completed while keeping existing IDs: %v", ids)
	}
	if fake.sp["appRoleAssignmentRequired"] != true {
		t.Fatal("assignment requirement not switched on")
	}
	// The admin was already assigned: only the group assignment is added.
	if len(fake.assignments) != 2 {
		t.Fatalf("assignments = %v", fake.assignments)
	}
	for _, c := range fake.calls {
		if c.Method == "POST" && (c.Path == "/applications" || c.Path == "/groups") {
			t.Fatalf("reuse must not create %s", c.Path)
		}
	}
}

func TestANetworkNeverReusesAnotherNetworksAppOrGroup(t *testing.T) {
	role := []any{map[string]any{"value": RoleAdmin, "id": "r-admin", "allowedMemberTypes": []any{"User"}, "displayName": "Covee Admin", "description": "d", "isEnabled": true}}
	// The tenant already has the shared app and group of a network set up before
	// networks had their own, and the app of another network.
	fake := &fakeGraph{
		apps: []map[string]any{{"id": "legacy-obj", "appId": "legacy-id", "displayName": "Covee", "appRoles": role},
			{"id": "home-obj", "appId": "home-id", "displayName": "Covee home", "appRoles": role}},
		groups: []map[string]any{{"id": "legacy-group", "displayName": "Covee users"}, {"id": "home-group", "displayName": "Covee home users"}},
	}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	g := &Graph{Base: srv.URL, Token: "token", Settle: time.Minute, Sleep: func(time.Duration) {}}
	plan, err := g.Prepare(context.Background(), "tenant-1", "office")
	if err != nil {
		t.Fatal(err)
	}
	if plan.App != nil || plan.GroupID != "" {
		t.Fatalf("a new network must get its own app and group: %+v", plan)
	}
	for _, line := range []string{`create the app "Covee office" for this network only`, `create the group "Covee office users"`} {
		if !strings.Contains(strings.Join(plan.Describe(), "\n"), line) {
			t.Fatalf("plan does not say %q: %v", line, plan.Describe())
		}
	}
}

func TestPrepareRefusesAmbiguousTenants(t *testing.T) {
	role := []any{map[string]any{"value": RoleAdmin, "id": "r"}}
	fake := &fakeGraph{apps: []map[string]any{{"id": "a", "appId": "1", "displayName": "Covee t", "appRoles": role}, {"id": "b", "appId": "2", "displayName": "Covee t", "appRoles": role}}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	g := &Graph{Base: srv.URL, Token: "token", Sleep: func(time.Duration) {}}
	if _, err := g.Prepare(context.Background(), "t", "t"); err == nil {
		t.Fatal("two apps for one network must stop setup")
	}
}

func TestIssuer(t *testing.T) {
	if got := Issuer("00000000-0000-4000-8000-000000000001"); got != "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/v2.0" {
		t.Fatal(got)
	}
	if id := uuid4(); len(id) != 36 || id[14] != '4' {
		t.Fatalf("not a version 4 UUID: %s", id)
	}
}
