// Package entra sets up Microsoft Entra ID (Office 365) sign-in for a network
// through Microsoft Graph, using the admin's own Azure CLI sign-in. Each
// network gets its own app ("Covee <network>"), roles, group ("Covee <network>
// users") and client secret, so access to one network never grants access to
// another in the same tenant. Networks set up before 18 October 2026 share the
// tenant's app "Covee" and group "Covee users"; their records keep those IDs.
package entra

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	RoleAdmin = "Covee.Admin"
	RoleRead  = "Covee.Reader"
	RoleUser  = "Covee.User"
)

// AppName is the name of a network's app in the tenant.
func AppName(network string) string { return "Covee " + network }

// GroupName is the name of the group whose members may add devices to a network.
func GroupName(network string) string { return "Covee " + network + " users" }

// Token is a Microsoft Graph access token and the tenant it belongs to.
type Token struct {
	AccessToken string
	TenantID    string
}

// TokenSource returns a Graph token for the signed-in admin.
type TokenSource func(ctx context.Context) (*Token, error)

// AzureCLI reads a token from the admin's Azure CLI sign-in.
func AzureCLI(ctx context.Context) (*Token, error) {
	if _, err := exec.LookPath("az"); err != nil {
		return nil, errors.New("Microsoft setup uses the Azure CLI: install it, then run `az login --allow-no-subscriptions` as a tenant administrator")
	}
	out, err := exec.CommandContext(ctx, "az", "account", "get-access-token", "--resource-type", "ms-graph", "--output", "json").Output()
	if err != nil {
		return nil, errors.New("the Azure CLI is not signed in: run `az login --allow-no-subscriptions` as a tenant administrator, then run setup again")
	}
	var t struct {
		AccessToken string `json:"accessToken"`
		Tenant      string `json:"tenant"`
	}
	if err := json.Unmarshal(out, &t); err != nil || t.AccessToken == "" || t.Tenant == "" {
		return nil, errors.New("could not read a Microsoft Graph token from the Azure CLI")
	}
	return &Token{AccessToken: t.AccessToken, TenantID: t.Tenant}, nil
}

// Graph is a minimal Microsoft Graph client.
type Graph struct {
	Base   string // https://graph.microsoft.com/v1.0
	Token  string
	HTTP   *http.Client
	Settle time.Duration // how long to retry while new objects replicate
	Sleep  func(time.Duration)
}

// GraphError is a non-success Graph response.
type GraphError struct {
	Status int
	Code   string
	Msg    string
}

func (e *GraphError) Error() string {
	return fmt.Sprintf("Microsoft Graph %d %s: %s", e.Status, e.Code, e.Msg)
}

func (g *Graph) do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(g.Settle)
	wait := time.Second
	for {
		req, err := http.NewRequestWithContext(ctx, method, g.Base+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+g.Token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		client := g.HTTP
		if client == nil {
			client = http.DefaultClient
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode < 300 {
			if out != nil && len(data) > 0 {
				return json.Unmarshal(data, out)
			}
			return nil
		}
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		gerr := &GraphError{Status: resp.StatusCode, Code: e.Error.Code, Msg: e.Error.Message}
		// New objects take a while to replicate; throttling asks us to wait.
		retry := resp.StatusCode == 429 || resp.StatusCode >= 500 || resp.StatusCode == 404 ||
			(resp.StatusCode == 400 && (strings.Contains(e.Error.Message, "does not reference a valid application") ||
				strings.Contains(e.Error.Message, "does not exist or one of its queried reference-property objects are not present")))
		if !retry || time.Now().After(deadline) {
			return gerr
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s < 60 {
			wait = time.Duration(s) * time.Second
		}
		sleep := g.Sleep
		if sleep == nil {
			sleep = time.Sleep
		}
		sleep(wait)
		if wait < 8*time.Second {
			wait *= 2
		}
	}
}

func q(v string) string { return strings.ReplaceAll(v, "'", "''") }

type appRole struct {
	AllowedMemberTypes []string `json:"allowedMemberTypes"`
	Description        string   `json:"description"`
	DisplayName        string   `json:"displayName"`
	ID                 string   `json:"id"`
	IsEnabled          bool     `json:"isEnabled"`
	Value              string   `json:"value"`
}

type application struct {
	ID       string    `json:"id"`
	AppID    string    `json:"appId"`
	AppRoles []appRole `json:"appRoles"`
	Web      struct {
		RedirectURIs []string `json:"redirectUris"`
	} `json:"web"`
	GroupMembershipClaims *string `json:"groupMembershipClaims"`
}

func uuid4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func wantedRoles() []appRole {
	return []appRole{
		{[]string{"User"}, "Can view and change Covee network settings in the private console.", "Covee Admin", "", true, RoleAdmin},
		{[]string{"User"}, "Can view Covee network settings in the private console but cannot change them.", "Covee Reader", "", true, RoleRead},
		{[]string{"User"}, "Can sign in to Covee. Grants no console access; adding devices depends on the network's users group.", "Covee User", "", true, RoleUser},
	}
}

// Plan describes what Setup will do, for the admin to confirm first.
type Plan struct {
	TenantID   string
	TenantName string
	Admin      string // signed-in user principal name
	Network    string
	AppName    string
	GroupName  string
	adminID    string
	App        *application // nil: a new app will be created
	GroupID    string       // empty: a new group will be created
}

// Describe returns the plan in plain words.
func (p *Plan) Describe() []string {
	var lines []string
	if p.App == nil {
		lines = append(lines, fmt.Sprintf("create the app %q for this network only (only %s accounts can use it, assignment required)", p.AppName, p.TenantName))
	} else {
		lines = append(lines, fmt.Sprintf("reuse this network's existing app %q (%s) and add its sign-in address", p.AppName, p.App.AppID))
	}
	if p.GroupID == "" {
		lines = append(lines, fmt.Sprintf("create the group %q with you in it; members may add devices to this network", p.GroupName))
	} else {
		lines = append(lines, fmt.Sprintf("use the existing group %q (%s)", p.GroupName, p.GroupID))
	}
	lines = append(lines, "give you the Covee Admin role", "create a client secret for this network, valid for 2 years")
	return lines
}

// Prepare reads the tenant and finds the network's app and group if an earlier
// attempt made them. It changes nothing.
func (g *Graph) Prepare(ctx context.Context, tenantID, network string) (*Plan, error) {
	var me struct{ ID, UserPrincipalName string }
	if err := g.do(ctx, "GET", "/me?$select=id,userPrincipalName", nil, &me); err != nil {
		return nil, fmt.Errorf("reading the signed-in Microsoft account: %w", err)
	}
	var orgs struct {
		Value []struct{ DisplayName string } `json:"value"`
	}
	if err := g.do(ctx, "GET", "/organization?$select=displayName", nil, &orgs); err != nil {
		return nil, fmt.Errorf("reading the Microsoft tenant: %w", err)
	}
	plan := &Plan{TenantID: tenantID, TenantName: tenantID, Admin: me.UserPrincipalName, Network: network,
		AppName: AppName(network), GroupName: GroupName(network), adminID: me.ID}
	if len(orgs.Value) == 1 {
		plan.TenantName = orgs.Value[0].DisplayName
	}
	var apps struct{ Value []application }
	if err := g.do(ctx, "GET", "/applications?$filter="+url.QueryEscape("displayName eq '"+q(plan.AppName)+"'")+"&$select=id,appId,appRoles,web,groupMembershipClaims", nil, &apps); err != nil {
		return nil, fmt.Errorf("looking for an existing %s app: %w", plan.AppName, err)
	}
	for i := range apps.Value {
		for _, r := range apps.Value[i].AppRoles {
			if r.Value == RoleAdmin {
				if plan.App != nil {
					return nil, fmt.Errorf("the tenant has more than one %q app with Covee roles; remove or rename the extra one first", plan.AppName)
				}
				plan.App = &apps.Value[i]
			}
		}
	}
	var groups struct {
		Value []struct{ ID string } `json:"value"`
	}
	if err := g.do(ctx, "GET", "/groups?$filter="+url.QueryEscape("displayName eq '"+q(plan.GroupName)+"' and securityEnabled eq true")+"&$select=id", nil, &groups); err != nil {
		return nil, fmt.Errorf("looking for the %s group: %w", plan.GroupName, err)
	}
	switch len(groups.Value) {
	case 0:
	case 1:
		plan.GroupID = groups.Value[0].ID
	default:
		return nil, fmt.Errorf("the tenant has more than one %q security group; keep one", plan.GroupName)
	}
	return plan, nil
}

// Result is the finished setup. Secret is private.
type Result struct {
	TenantID      string
	TenantName    string
	ClientID      string
	AppObjectID   string
	GroupID       string
	GroupName     string
	Secret        string
	SecretKeyID   string
	SecretExpires time.Time
}

// Apply carries out a confirmed plan with the network's redirect URI.
func (g *Graph) Apply(ctx context.Context, plan *Plan, host, redirectURI string) (*Result, error) {
	app := plan.App
	if app == nil {
		app = &application{}
		claims := "ApplicationGroup"
		roles := wantedRoles()
		for i := range roles {
			roles[i].ID = uuid4()
		}
		body := map[string]any{
			"displayName":           plan.AppName,
			"signInAudience":        "AzureADMyOrg",
			"web":                   map[string]any{"redirectUris": []string{redirectURI}},
			"appRoles":              roles,
			"groupMembershipClaims": claims,
		}
		if err := g.do(ctx, "POST", "/applications", body, app); err != nil {
			return nil, fmt.Errorf("creating the %s app: %w", plan.AppName, err)
		}
	} else {
		if err := g.completeApp(ctx, app, redirectURI); err != nil {
			return nil, err
		}
	}
	sp, err := g.servicePrincipal(ctx, app.AppID)
	if err != nil {
		return nil, err
	}
	groupID := plan.GroupID
	if groupID == "" {
		var created struct{ ID string }
		member := g.Base + "/directoryObjects/" + plan.adminID
		body := map[string]any{
			"displayName": plan.GroupName, "mailEnabled": false, "mailNickname": "covee-" + plan.Network + "-users", "securityEnabled": true,
			"description":        fmt.Sprintf("People allowed to add devices to the Covee network %s (%s) with Microsoft sign-in.", plan.Network, host),
			"owners@odata.bind":  []string{member},
			"members@odata.bind": []string{member},
		}
		if err := g.do(ctx, "POST", "/groups", body, &created); err != nil {
			return nil, fmt.Errorf("creating the %s group: %w", plan.GroupName, err)
		}
		groupID = created.ID
	}
	roles := map[string]string{}
	var current application
	if err := g.do(ctx, "GET", "/applications/"+app.ID+"?$select=appRoles", nil, &current); err != nil {
		return nil, fmt.Errorf("reading the Covee app roles: %w", err)
	}
	for _, r := range current.AppRoles {
		roles[r.Value] = r.ID
	}
	if err := g.assign(ctx, sp, plan.adminID, roles[RoleAdmin]); err != nil {
		return nil, fmt.Errorf("giving you the Covee Admin role: %w", err)
	}
	if err := g.assign(ctx, sp, groupID, roles[RoleUser]); err != nil {
		return nil, fmt.Errorf("adding the %s group to the app: %w", plan.GroupName, err)
	}
	expires := time.Now().UTC().AddDate(2, 0, 0).Truncate(time.Second)
	var secret struct {
		KeyID       string    `json:"keyId"`
		SecretText  string    `json:"secretText"`
		EndDateTime time.Time `json:"endDateTime"`
	}
	body := map[string]any{"passwordCredential": map[string]any{
		"displayName": fmt.Sprintf("Covee network %s (%s)", plan.Network, host), "endDateTime": expires.Format(time.RFC3339)}}
	if err := g.do(ctx, "POST", "/applications/"+app.ID+"/addPassword", body, &secret); err != nil {
		return nil, fmt.Errorf("creating the client secret: %w", err)
	}
	if secret.SecretText == "" {
		return nil, errors.New("Microsoft returned an empty client secret")
	}
	return &Result{TenantID: plan.TenantID, TenantName: plan.TenantName, ClientID: app.AppID, AppObjectID: app.ID, GroupID: groupID,
		GroupName: plan.GroupName, Secret: secret.SecretText, SecretKeyID: secret.KeyID, SecretExpires: secret.EndDateTime}, nil
}

// completeApp adds the redirect URI, any missing role and group claims to a reused app.
func (g *Graph) completeApp(ctx context.Context, app *application, redirectURI string) error {
	patch := map[string]any{}
	uris := app.Web.RedirectURIs
	found := false
	for _, u := range uris {
		found = found || u == redirectURI
	}
	if !found {
		patch["web"] = map[string]any{"redirectUris": append(append([]string{}, uris...), redirectURI)}
	}
	have := map[string]bool{}
	for _, r := range app.AppRoles {
		have[r.Value] = true
	}
	roles := append([]appRole{}, app.AppRoles...)
	for _, r := range wantedRoles() {
		if !have[r.Value] {
			r.ID = uuid4()
			roles = append(roles, r)
		}
	}
	if len(roles) != len(app.AppRoles) {
		patch["appRoles"] = roles
	}
	if app.GroupMembershipClaims == nil || *app.GroupMembershipClaims != "ApplicationGroup" {
		patch["groupMembershipClaims"] = "ApplicationGroup"
	}
	if len(patch) == 0 {
		return nil
	}
	if err := g.do(ctx, "PATCH", "/applications/"+app.ID, patch, nil); err != nil {
		return fmt.Errorf("updating the Covee app: %w", err)
	}
	return nil
}

// AddRedirectURI adds a sign-in return address to the app, keeping the ones it
// has. It reports whether the address was added (false: it was already there).
func (g *Graph) AddRedirectURI(ctx context.Context, appObjectID, redirectURI string) (bool, error) {
	var app application
	if err := g.do(ctx, "GET", "/applications/"+url.PathEscape(appObjectID)+"?$select=id,web", nil, &app); err != nil {
		return false, fmt.Errorf("reading the Covee app: %w", err)
	}
	for _, u := range app.Web.RedirectURIs {
		if u == redirectURI {
			return false, nil
		}
	}
	uris := append(append([]string{}, app.Web.RedirectURIs...), redirectURI)
	if err := g.do(ctx, "PATCH", "/applications/"+url.PathEscape(appObjectID), map[string]any{"web": map[string]any{"redirectUris": uris}}, nil); err != nil {
		return false, fmt.Errorf("adding %s to the Covee app: %w", redirectURI, err)
	}
	return true, nil
}

func (g *Graph) servicePrincipal(ctx context.Context, appID string) (string, error) {
	var found struct {
		Value []struct {
			ID                        string `json:"id"`
			AppRoleAssignmentRequired bool   `json:"appRoleAssignmentRequired"`
		} `json:"value"`
	}
	if err := g.do(ctx, "GET", "/servicePrincipals?$filter="+url.QueryEscape("appId eq '"+q(appID)+"'")+"&$select=id,appRoleAssignmentRequired", nil, &found); err != nil {
		return "", fmt.Errorf("looking for the Covee enterprise app: %w", err)
	}
	if len(found.Value) == 1 {
		if !found.Value[0].AppRoleAssignmentRequired {
			if err := g.do(ctx, "PATCH", "/servicePrincipals/"+found.Value[0].ID, map[string]any{"appRoleAssignmentRequired": true}, nil); err != nil {
				return "", fmt.Errorf("requiring assignment on the Covee enterprise app: %w", err)
			}
		}
		return found.Value[0].ID, nil
	}
	var created struct{ ID string }
	if err := g.do(ctx, "POST", "/servicePrincipals", map[string]any{"appId": appID, "appRoleAssignmentRequired": true}, &created); err != nil {
		return "", fmt.Errorf("creating the Covee enterprise app: %w", err)
	}
	return created.ID, nil
}

func (g *Graph) assign(ctx context.Context, sp, principal, role string) error {
	if role == "" {
		return errors.New("the Covee app is missing a required role")
	}
	var existing struct {
		Value []struct {
			PrincipalID string `json:"principalId"`
			AppRoleID   string `json:"appRoleId"`
		} `json:"value"`
	}
	if err := g.do(ctx, "GET", "/servicePrincipals/"+sp+"/appRoleAssignedTo?$top=999", nil, &existing); err != nil {
		return err
	}
	for _, a := range existing.Value {
		if strings.EqualFold(a.PrincipalID, principal) && strings.EqualFold(a.AppRoleID, role) {
			return nil
		}
	}
	return g.do(ctx, "POST", "/servicePrincipals/"+sp+"/appRoleAssignedTo", map[string]any{"principalId": principal, "resourceId": sp, "appRoleId": role}, nil)
}

// Issuer returns the tenant-specific sign-in issuer the broker requires.
func Issuer(tenantID string) string {
	return "https://login.microsoftonline.com/" + tenantID + "/v2.0"
}
