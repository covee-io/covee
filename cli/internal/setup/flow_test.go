package setup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"filippo.io/age"

	"covee.io/cli/internal/cert"
	"covee.io/cli/internal/dns"
	"covee.io/cli/internal/entra"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
	"covee.io/cli/internal/secrets"
)

// fakeSSH behaves like a fresh Ubuntu server: it answers each command setup
// sends, keeps uploaded files, and fails the covee login until the account exists.
const fakeSSH = `#!/bin/sh
for last; do :; done
user=""
prev=""
for a; do [ "$prev" = "-l" ] && user="$a"; prev="$a"; done
printf '%s\t%s\n' "$user" "$last" >> "$STATE/log"
case "$last" in
  *'mktemp -d'*) cat >/dev/null; echo /tmp/covee-test ;;
  *"host_prepare.py' facts"*) cat "$STATE/facts.json" ;;
  'rm -rf '*) ;;
  *'id -un && sudo -n true'*)
    [ "$user" = covee ] && [ -f "$STATE/account" ] || { echo "Permission denied" >&2; exit 255; }
    echo covee; echo ok ;;
  *"host_prepare.py' account"*) cat > "$STATE/account.json"; touch "$STATE/account"; echo '{"service_user":"covee","uid":10001}' ;;
  *'covee-payload-'*'mkdir'*) cat >/dev/null; echo /home/covee/covee-payload-0123456789ab ;;
  *"host_prepare.py' system"*) cat > "$STATE/system.json"; echo "Installing..."; echo '{"prepared":true,"changed":true}' ;;
  *'docker info'*) echo 28.5.0 ;;
  *'disable --now covee-dns.timer'*) printf '%s\n' "$last" >> "$STATE/dns-off" ;;
  *'disable --now covee-gateway-dns.path'*) mkdir -p "$STATE/units"; echo gateway-dns-removed >> "$STATE/units/actions" ;;
  *'src.new'*) cat >/dev/null; echo ok ;;
  *'cat > '*)
    f=$(printf '%s' "$last" | sed -n "s/.*cat > '\([^']*\)'.tmp.*/\1/p")
    mkdir -p "$STATE/files$(dirname "$f")"; cat > "$STATE/files$f" ;;
  *'scripts/deploy.py build'*) [ -f "$STATE/fail-build" ] && { echo "build broke" >&2; exit 1; }; echo built ;;
  *'scripts/deploy.py backup'*)
    out=$(printf '%s' "$last" | sed -n "s/.*--output '\([^']*\)'.*/\1/p"); rcpt=$(printf '%s' "$last" | sed -n "s/.*--recipient '\([^']*\)'.*/\1/p")
    host=control.coveetest.io; [ -f "$STATE/wrong-host" ] && host=other.coveetest.io
    d=$(mktemp -d); mkdir -p "$d/state/headscale"; printf '{"format": 1, "spec": {"control_host": "%s"}}' "$host" > "$d/deployment.json"; echo sqlite > "$d/state/headscale/db.sqlite"
    mkdir -p "$STATE/backups"; COPYFILE_DISABLE=1 tar -cf - -C "$d" deployment.json state/headscale/db.sqlite | age -r "$rcpt" > "$STATE/backups/$(basename "$out")"; rm -rf "$d"; echo "backup done" ;;
  'cat /srv/covee/backups/'*|"cat '/srv/covee/backups/"*) cat "$STATE/backups/$(basename "$(printf '%s' "$last" | sed "s/^cat //; s/'//g")")" ;;
  'sha256sum '*) f=$(printf '%s' "$last" | sed "s/^sha256sum //; s/'//g"); shasum -a 256 "$STATE/backups/$(basename "$f")" | sed "s|  .*|  $f|" ;;
  'mkdir -p -m 700 /srv/covee/backups'*|'ls -1t '*) ;;
  *"proxmox_host.py' facts"*) cat "$STATE/proxmox-facts.json" ;;
  *"proxmox_host.py' create"*) cat > "$STATE/vm-request.json"; touch "$STATE/account"; echo '{"vmid": 103, "name": "covee-home", "ipv4": "192.168.50.21", "image_reused": true}' ;;
  *'qm config '*) ;;
  *'test -f /var/lib/covee-bootstrap-complete'*) [ -f "$STATE/account" ] && echo ready ;;
  *'scripts/deploy.py restore '*|*'scripts/deploy.py renew-certificates '*|*'scripts/deploy.py up '*|*'scripts/deploy.py prepare '*|*'scripts/deploy.py validate '*)
    printf '%s\n' "$last" | sed -n 's/.*scripts\/deploy.py \([a-z-]*\).*/\1/p' >> "$STATE/deploy-calls"; echo deployed ;;
  *'sudo -n tee /etc/systemd/system/'*|*"sudo -n tee '/etc/systemd/system/"*) n=$(printf '%s' "$last" | sed "s/.*system\///; s/'.*//; s/ .*//"); mkdir -p "$STATE/units"; cat > "$STATE/units/$n" ;;
  *'systemctl daemon-reload'*) echo enabled >> "$STATE/units/actions" ;;
  *'dns_updater.py'*'--check'*) [ -f "$STATE/fail-dns-check" ] && { echo "AccessDenied" >&2; exit 1; }
    cat "$STATE/dns-check.json" 2>/dev/null || echo '{"action": "checked", "hostname": "control.coveetest.io", "public": "203.0.113.9", "record": ["203.0.113.9"], "serves": true}' ;;
  *'sudo -n systemctl start covee-dns.service'*) echo dns-started >> "$STATE/units/actions" ;;
  *'systemctl is-active covee-dns.timer;'*) echo active; echo success; echo "Mon 2026-10-12 23:55:00 UTC" ;;
  *'sudo -n systemctl start covee-api-key.service'*) [ -f "$STATE/fail-rotation" ] && { echo "Job failed" >&2; exit 1; }; echo started >> "$STATE/units/actions" ;;
  *'systemctl show -p Result'*) echo success; echo active ;;
  *'scripts/deploy.py local-accounts'*)
    printf '%s\n' "$last" >> "$STATE/local-calls"
    case "$last" in
      *'--action invite'*) [ -f "$STATE/account-exists" ] && { echo "ERROR: Local account change refused: an account with this email exists" >&2; exit 1; }
        echo '{"email": "x", "invite_token": "TOKEN123", "expires": "2026-10-15T20:00:00Z"}' ;;
      *'--action reset'*) echo '{"email": "x", "invite_token": "TOKEN456", "expires": "2026-10-15T20:00:00Z"}' ;;
      *'--action update'*) echo '{"email": "x", "role": "reader", "enroll": false}' ;;
      *'--action remove'*) echo '{"removed": "x"}' ;;
      *'--action list'*) echo '{"accounts": [{"email": "alice@example.org", "name": "Alice", "role": "admin", "enroll": true, "passkeys": 1, "password": false, "invite_pending": false, "locked": false}]}' ;;
    esac ;;
  *'scripts/deploy.py create-device-key'*) printf '%s\n' "$last" > "$STATE/device-key-command"; echo '{"key": "hskey-auth-0123456789abcdef0123456789abcdef", "expiration": {"seconds": 1791835261, "nanos": 1}, "tags": ["tag:server"]}' ;;
  *'scripts/deploy.py enable-console-network'*) printf '%s\n' "$last" > "$STATE/console-enable"; echo '{"console": "https://console.mesh.coveetest.io"}' ;;
  *'docker ps --filter name=console-node'*) echo "Up 2 minutes (healthy)" ;;
  *"docker ps --filter 'name=-gateway-'"*) [ -f "$STATE/gateway-on" ] && echo "Up 1 minute (healthy)" ;;
  *"host_prepare.py' firewall"*) cat > "$STATE/firewall.json"; echo '{"firewall": "applied", "changed": true}' ;;
  *'scripts/deploy.py enable-gateway'*) printf '%s\n' "$last" > "$STATE/gateway-command"; touch "$STATE/gateway-on"; echo '{"gateway": true, "changed": true}' ;;
  *'scripts/deploy.py disable-gateway'*) printf '%s\n' "$last" > "$STATE/gateway-command"; rm -f "$STATE/gateway-on"; echo '{"gateway": false, "changed": true}' ;;
  *'sudo -n systemctl start covee-gateway-dns.service'*) echo gateway-dns-started >> "$STATE/units/actions" ;;
  *'scripts/deploy.py update-identity-providers'*) [ -f "$STATE/fail-providers" ] && { echo "broker unhealthy" >&2; exit 1; }; echo deployed ;;
  *'scripts/deploy.py rename '*)
    printf '%s\n' "$last" > "$STATE/rename-command"; [ -f "$STATE/fail-rename" ] && { echo "ERROR: Renaming failed; the previous names were restored" >&2; exit 1; }
    h=$(printf '%s' "$last" | sed -n "s/.*--control-host '\([^']*\)'.*/\1/p"); printf '{"issuer":"https://%s/identity"}' "$h" > "$STATE/issuer.json"
    echo "{\"control\": \"https://$h\", \"accounts_moved\": 1}" ;;
  'rm -f '*) printf '%s\n' "$last" >> "$STATE/removed" ;;
  'mv -f '*) printf '%s\n' "$last" >> "$STATE/moved" ;;
  *'scripts/deploy.py'*) echo deployed ;;
  *'while [ -e /srv/covee/runtime-'*) echo /srv/covee/runtime-1 ;;
  *'curl -fsS'*) cat "$STATE/issuer.json" 2>/dev/null || echo '{"issuer":"https://control.coveetest.io/identity"}' ;;
  *"python3 -c"*) cat "$STATE/grants.json" 2>/dev/null || echo '[]' ;;
  *) echo "unexpected command: $last" >&2; exit 99 ;;
esac
`

type memSSM struct {
	mu     sync.Mutex
	values map[string]string
}

func (m *memSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[aws.ToString(in.Name)] = aws.ToString(in.Value)
	return &ssm.PutParameterOutput{}, nil
}

func (m *memSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[aws.ToString(in.Name)]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(v)}}, nil
}

type memR53 struct {
	mu sync.Mutex
	a  map[string]string
	// zones adds hosted zones (name → ID) beside coveetest.io.
	zones map[string]string
	// listA makes the A records readable, as Route 53 does.
	listA bool
}

func (m *memR53) ListHostedZonesByName(_ context.Context, in *route53.ListHostedZonesByNameInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
	zones := []types.HostedZone{{Id: aws.String("/hostedzone/ZTEST"), Name: aws.String("coveetest.io.")}}
	for name, id := range m.zones {
		zones = append(zones, types.HostedZone{Id: aws.String("/hostedzone/" + id), Name: aws.String(name + ".")})
	}
	return &route53.ListHostedZonesByNameOutput{HostedZones: zones}, nil
}

func (m *memR53) ChangeResourceRecordSets(_ context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range in.ChangeBatch.Changes {
		if c.ResourceRecordSet.Type == types.RRTypeA {
			name := aws.ToString(c.ResourceRecordSet.Name)
			if c.Action == types.ChangeActionDelete {
				if m.a[name] != aws.ToString(c.ResourceRecordSet.ResourceRecords[0].Value) || aws.ToInt64(c.ResourceRecordSet.TTL) != 300 {
					return nil, fmt.Errorf("Tried to delete resource record set [name='%s', type='A'] but the values provided do not match the current values", name)
				}
				delete(m.a, name)
				continue
			}
			m.a[name] = aws.ToString(c.ResourceRecordSet.ResourceRecords[0].Value)
		}
	}
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("c")}}, nil
}

func (m *memR53) GetChange(context.Context, *route53.GetChangeInput, ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
	return &route53.GetChangeOutput{ChangeInfo: &types.ChangeInfo{Status: types.ChangeStatusInsync}}, nil
}

func (m *memR53) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := aws.ToString(in.StartRecordName)
	if v, ok := m.a[name]; ok && m.listA && in.StartRecordType == types.RRTypeA {
		return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{{
			Name: aws.String(name), Type: types.RRTypeA, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String(v)}}}}}, nil
	}
	return &route53.ListResourceRecordSetsOutput{}, nil
}

type fakeCA struct {
	obtained int
	names    []string
}

func (f *fakeCA) Terms(context.Context) (string, error) {
	return "https://letsencrypt.example/terms", nil
}

func (f *fakeCA) Obtain(_ context.Context, hosts []string, account []byte, _ dns.Provider, _ func(string, ...any)) (*cert.Result, []byte, error) {
	f.obtained++
	f.names = hosts
	host := hosts[0]
	if account == nil {
		account = []byte("ACCOUNT KEY")
	}
	return &cert.Result{FullChainPEM: []byte("CHAIN for " + host), KeyPEM: []byte("CERT KEY"), NotAfter: time.Now().AddDate(0, 3, 0), Issuer: "Test CA"}, account, nil
}

// graph is a minimal empty tenant for the Microsoft step. Changes to the app are
// sent to patched.
func graph(t *testing.T, patched func(map[string]any)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.URL.Path == "/me":
			reply(map[string]any{"id": "user-1", "userPrincipalName": "alice@example.com"})
		case r.URL.Path == "/organization":
			reply(map[string]any{"value": []any{map[string]any{"displayName": "Example Co"}}})
		case r.Method == "GET" && (r.URL.Path == "/applications" || r.URL.Path == "/groups" || r.URL.Path == "/servicePrincipals"):
			reply(map[string]any{"value": []any{}})
		case r.Method == "POST" && r.URL.Path == "/applications":
			reply(map[string]any{"id": "app-obj", "appId": "11111111-2222-4333-8444-555555555555"})
		case r.Method == "GET" && r.URL.Path == "/applications/app-obj":
			reply(map[string]any{"id": "app-obj", "web": map[string]any{"redirectUris": []string{"https://control.coveetest.io/identity/callback/entra"}}, "appRoles": []any{
				map[string]any{"value": entra.RoleAdmin, "id": "r-admin"}, map[string]any{"value": entra.RoleRead, "id": "r-read"}, map[string]any{"value": entra.RoleUser, "id": "r-user"}}})
		case r.Method == "PATCH" && r.URL.Path == "/applications/app-obj":
			patched(body)
			w.WriteHeader(204)
		case r.Method == "POST" && r.URL.Path == "/servicePrincipals":
			reply(map[string]any{"id": "sp-1"})
		case r.Method == "POST" && r.URL.Path == "/groups":
			reply(map[string]any{"id": "00000000-0000-4000-8000-000000000003"})
		case strings.HasSuffix(r.URL.Path, "/appRoleAssignedTo"):
			reply(map[string]any{"value": []any{}})
		case strings.HasSuffix(r.URL.Path, "/addPassword"):
			reply(map[string]any{"keyId": "k", "secretText": "entra-secret-value", "endDateTime": time.Now().AddDate(2, 0, 0).UTC().Format(time.RFC3339)})
		default:
			t.Errorf("unexpected Graph call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type harness struct {
	env   *Env
	state string
	ssm   *memSSM
	r53   *memR53
	iam   *memIAM
	ca    *fakeCA
	out   *bytes.Buffer
	// appChanges are the changes made to the Microsoft app after setup.
	appChanges []map[string]any
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	state := filepath.Join(dir, "server")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATE", state)
	facts := `{"os":"ubuntu","codename":"noble","pretty":"Ubuntu 24.04.3 LTS","architecture":"amd64","hostname":"covee-test",
"interface":"eth0","ipv4_cidr":"192.168.50.20/24","dhcp":false,"ssh_client":"192.168.50.30","virtualization":"kvm",
"public_ipv4":"203.0.113.9","service_user":false,"prepared":false,"docker":false,"passwordless_sudo":true}`
	// host_prepare.py prints its JSON on one line.
	if err := os.WriteFile(filepath.Join(state, "facts.json"), []byte(strings.ReplaceAll(facts, "\n", "")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(fakeSSH), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	records, err := record.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{state: state, ssm: &memSSM{values: map[string]string{}}, r53: &memR53{a: map[string]string{}}, iam: newMemIAM(), ca: &fakeCA{}, out: &bytes.Buffer{}}
	var mu sync.Mutex
	g := graph(t, func(body map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		h.appChanges = append(h.appChanges, body)
	})
	t.Cleanup(g.Close)
	h.env = &Env{
		Out:        h.out,
		Home:       home,
		Records:    records,
		AWS:        func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		Caller:     func(context.Context, aws.Config) (string, error) { return "arn:aws:iam::123:user/test", nil },
		NewRoute53: func(aws.Config) dns.Route53API { return h.r53 },
		NewSSM:     func(aws.Config) secrets.SSMAPI { return h.ssm },
		NewIAM:     func(aws.Config) dns.IAMAPI { return h.iam },
		EntraToken: func(context.Context) (*entra.Token, error) {
			return &entra.Token{AccessToken: "token", TenantID: "00000000-0000-4000-8000-000000000001"}, nil
		},
		GraphBase: g.URL,
		Open:      func(string) {},
		SSH:       ssh,
		HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"issuer":"https://control.coveetest.io/identity"}`))}, nil
		})},
		Archive: func() ([]byte, string, error) { return []byte("payload"), "0123456789abcdef0123456789abcdef", nil },
		CA:      func(bool) CertAuthority { return h.ca },
	}
	return h
}

func (h *harness) answers(extra map[string]string) *prompt.Scripted {
	a := map[string]string{
		"organization": "Example Home", "network": "home", "hostname": "control.coveetest.io",
		"dns_host": labelR53, "server_address": "192.168.50.20", "server_user": "ubuntu", "dedicated": "yes",
		"sign_in": labelEntra, "secrets_store": labelSSM, "acme_terms": "yes", "dynamic_address": "no",
	}
	for k, v := range extra {
		a[k] = v
	}
	return &prompt.Scripted{Answers: a, Out: h.out}
}

func (h *harness) file(t *testing.T, path string) string {
	b, err := os.ReadFile(filepath.Join(h.state, "files", path))
	if err != nil {
		t.Fatalf("server file %s: %v", path, err)
	}
	return string(b)
}

func TestSetupBuildsANetworkAndResumesAfterAFailure(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.state, "fail-build"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.env.Ask = h.answers(nil)
	err := Run(ctx, h.env, Options{Network: "home"})
	if err == nil || !strings.Contains(err.Error(), "covee setup home") {
		t.Fatalf("expected the build failure with resume advice, got %v", err)
	}
	n, err := h.env.Records.Load("home")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"ssh-key", "sign-in-entra", "dns", "certificate", "account", "system", "source", "secrets"} {
		if !n.Done(step) {
			t.Fatalf("step %s not recorded as done: %v", step, n.Completed)
		}
	}
	if n.Done("build") {
		t.Fatal("failed build recorded as done")
	}

	// Second run, by a newer CLI: only the remaining steps run, and the newer
	// server files replace the ones the interrupted setup installed.
	os.Remove(filepath.Join(h.state, "fail-build"))
	before := h.ca.obtained
	h.env.Archive = func() ([]byte, string, error) { return []byte("payload v2"), "fedcba9876543210fedcba9876543210", nil }
	h.env.Ask = h.answers(nil)
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("resume failed: %v\n%s", err, h.out)
	}
	if h.ca.obtained != before {
		t.Fatal("resume issued the certificate again")
	}
	if log, _ := os.ReadFile(filepath.Join(h.state, "log")); strings.Count(string(log), "src.new") != 2 {
		t.Fatalf("the newer files were not installed again:\n%s", log)
	}
	n, _ = h.env.Records.Load("home")
	if !n.Done("verify") || n.Runtime != "/srv/covee/runtime-1" || n.Payload == "" {
		t.Fatalf("unexpected final record: %+v", n)
	}

	// Choices reached the record.
	if n.PublicAddress != "203.0.113.9" || n.DNSBaseDomain != "mesh.coveetest.io" || n.Server.IPv4CIDR != "192.168.50.20/24" ||
		strings.Join(n.Server.SSHSources, ",") != "192.168.50.0/24" || n.DNS.ZoneID != "ZTEST" {
		t.Fatalf("record does not match the answers: %+v", n)
	}
	if n.SignIn.Entra == nil || n.SignIn.Entra.GroupID != "00000000-0000-4000-8000-000000000003" || n.SignIn.Entra.SecretName != "/covee/home/entra-client-secret" {
		t.Fatalf("Microsoft not recorded: %+v", n.SignIn.Entra)
	}
	raw, _ := os.ReadFile(filepath.Join(h.env.Home, "networks", "home.json"))
	for _, secret := range []string{"entra-secret-value", "CERT KEY", "OPENSSH PRIVATE KEY"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the record contains a secret value (%s)", secret)
		}
	}

	// DNS and secrets of record.
	if h.r53.a["control.coveetest.io."] != "203.0.113.9" {
		t.Fatalf("A record = %v", h.r53.a)
	}
	for _, name := range []string{"ssh-private-key", "entra-client-secret", "tls-private-key", "acme-account-key"} {
		if _, ok := h.ssm.values["/covee/home/"+name]; !ok {
			t.Fatalf("Parameter Store is missing %s", name)
		}
	}

	// The server received the account key, hardening settings and files.
	var account, system map[string]any
	b, _ := os.ReadFile(filepath.Join(h.state, "account.json"))
	_ = json.Unmarshal(b, &account)
	b, _ = os.ReadFile(filepath.Join(h.state, "system.json"))
	_ = json.Unmarshal(b, &system)
	if !strings.HasPrefix(account["ssh_public_key"].(string), "ssh-ed25519 ") || system["ssh_public_key"] != account["ssh_public_key"] {
		t.Fatalf("account/system key mismatch: %v %v", account, system)
	}
	if system["network_interface"] != "eth0" || system["ipv4_cidr"] != "192.168.50.20/24" {
		t.Fatalf("system settings = %v", system)
	}
	if h.file(t, "/srv/covee/secrets/entra-client-secret") != "entra-secret-value" ||
		h.file(t, "/srv/covee/secrets/tls/privkey.pem") != "CERT KEY" ||
		h.file(t, "/srv/covee/secrets/tls/fullchain.pem") != "CHAIN for control.coveetest.io" {
		t.Fatal("secrets not copied to the server correctly")
	}
	var spec map[string]any
	if err := json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec); err != nil {
		t.Fatal(err)
	}
	providers := spec["identity"].(map[string]any)["providers"].([]any)
	p := providers[0].(map[string]any)
	if len(providers) != 1 || p["issuer"] != "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/v2.0" ||
		p["client_secret_file"] != "/srv/covee/secrets/entra-client-secret" || spec["dns_base_domain"] != "mesh.coveetest.io" {
		t.Fatalf("deployment config = %v", spec)
	}

	// Commands ran as the right account, and the admin login was only used before covee existed.
	log, _ := os.ReadFile(filepath.Join(h.state, "log"))
	var sawSystemAsCovee, adminAfterSystem, systemSeen bool
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		user, cmd, _ := strings.Cut(line, "\t")
		if strings.Contains(cmd, "host_prepare.py' system") {
			systemSeen, sawSystemAsCovee = true, user == "covee"
		}
		if systemSeen && user == "ubuntu" {
			adminAfterSystem = true
		}
	}
	if !sawSystemAsCovee || adminAfterSystem {
		t.Fatalf("hardening must run as covee and the admin login must not be used afterwards:\n%s", log)
	}

	// A third run reports the finished network.
	h.out.Reset()
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil || !strings.Contains(h.out.String(), "already set up") {
		t.Fatalf("finished network: %v %s", err, h.out)
	}
}

func TestSetupStopsBeforeChangingAnythingWhenDeclined(t *testing.T) {
	h := newHarness(t)
	h.env.Ask = h.answers(map[string]string{"start": "no"})
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err != prompt.ErrAborted {
		t.Fatalf("expected ErrAborted, got %v", err)
	}
	if _, err := h.env.Records.Load("home"); err == nil {
		t.Fatal("a declined setup must not leave a record")
	}
	if len(h.ssm.values) != 0 || len(h.r53.a) != 0 {
		t.Fatal("a declined setup changed AWS")
	}
	if _, err := os.Stat(filepath.Join(h.state, "account")); err == nil {
		t.Fatal("a declined setup changed the server")
	}
}

func TestSetupRefusesALockoutAndUnsupportedServers(t *testing.T) {
	h := newHarness(t)
	h.env.Ask = h.answers(map[string]string{"ssh_sources": "10.0.0.0/24"})
	err := Run(context.Background(), h.env, Options{Network: "home"})
	if err == nil || !strings.Contains(err.Error(), "locked out") {
		t.Fatalf("expected a lockout refusal, got %v", err)
	}
	facts := filepath.Join(h.state, "facts.json")
	b, _ := os.ReadFile(facts)
	_ = os.WriteFile(facts, bytes.Replace(b, []byte(`"amd64"`), []byte(`"arm64"`), 1), 0o600)
	h.env.Ask = h.answers(nil)
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err == nil || !strings.Contains(err.Error(), "amd64") {
		t.Fatalf("expected an unsupported-server error, got %v", err)
	}
}

func TestGrantMergesTheAccessList(t *testing.T) {
	h := newHarness(t)
	h.env.Ask = h.answers(map[string]string{"sign_in": labelGoogle,
		"google_client_id": "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com", "google_client_secret": "GOCSPX-abcdefghijklmnopqrstuvwx"})
	ctx := context.Background()
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	existing := `[{"provider":"google","subject":"111","role":"Covee.Admin","enroll":true}]`
	if err := os.WriteFile(filepath.Join(h.state, "grants.json"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Grant(ctx, h.env, "home", "google", "222", "reader", false); err != nil {
		t.Fatal(err)
	}
	var grants []map[string]any
	if err := json.Unmarshal([]byte(h.file(t, "/srv/covee/grants.json")), &grants); err != nil || len(grants) != 2 {
		t.Fatalf("grants = %v, %v", grants, err)
	}
	if grants[1]["subject"] != "222" || grants[1]["role"] != "Covee.Reader" || grants[1]["enroll"] != false {
		t.Fatalf("new grant = %v", grants[1])
	}
	if err := Grant(ctx, h.env, "home", "apple", "333", "admin", true); err == nil {
		t.Fatal("granted on a provider that is not enabled")
	}
	if err := Grant(ctx, h.env, "home", "google", "bad id!", "admin", true); err == nil {
		t.Fatal("accepted a malformed subject")
	}
}

func providerIDs(t *testing.T, h *harness) []string {
	var providers []map[string]any
	if err := json.Unmarshal([]byte(h.file(t, "/srv/covee/providers.json")), &providers); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range providers {
		ids = append(ids, p["id"].(string))
	}
	return ids
}

func TestAuthAddAndRemoveChangeARunningNetwork(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.env.Ask = h.answers(nil)
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	h.env.Ask = h.answers(map[string]string{
		"google_client_id": "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com", "google_client_secret": "GOCSPX-abcdefghijklmnopqrstuvwx"})
	if err := AuthAdd(ctx, h.env, "home", "google"); err != nil {
		t.Fatalf("auth add: %v\n%s", err, h.out)
	}
	if got := strings.Join(providerIDs(t, h), ","); got != "entra,google" {
		t.Fatalf("providers sent = %s", got)
	}
	if h.file(t, "/srv/covee/secrets/google-client-secret") != "GOCSPX-abcdefghijklmnopqrstuvwx" {
		t.Fatal("Google secret not copied to the server")
	}
	if _, ok := h.ssm.values["/covee/home/google-client-secret"]; !ok {
		t.Fatal("Google secret not stored in Parameter Store")
	}
	n, _ := h.env.Records.Load("home")
	if strings.Join(n.Providers, ",") != "entra,google" || n.SignIn.Google == nil {
		t.Fatalf("record = %v %+v", n.Providers, n.SignIn.Google)
	}
	var spec map[string]any
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	if len(spec["identity"].(map[string]any)["providers"].([]any)) != 2 {
		t.Fatal("the server's deployment config was not kept in sync")
	}
	if err := AuthAdd(ctx, h.env, "home", "google"); err == nil {
		t.Fatal("adding an enabled provider twice must fail")
	}

	// Removing Google: its approved accounts lose access only after confirmation.
	_ = os.WriteFile(filepath.Join(h.state, "grants.json"), []byte(`[{"provider":"google","subject":"111","role":"Covee.Admin","enroll":true}]`), 0o600)
	h.env.Ask = h.answers(map[string]string{"remove_grants": "no"})
	if err := AuthRemove(ctx, h.env, "home", "google"); err == nil {
		t.Fatal("declining must stop the removal")
	}
	if got := strings.Join(providerIDs(t, h), ","); got != "entra,google" {
		t.Fatalf("a declined removal changed the providers: %s", got)
	}
	h.env.Ask = h.answers(map[string]string{"remove_grants": "yes"})
	if err := AuthRemove(ctx, h.env, "home", "google"); err != nil {
		t.Fatalf("auth remove: %v\n%s", err, h.out)
	}
	if strings.TrimSpace(h.file(t, "/srv/covee/grants.json")) != "[]" {
		t.Fatalf("Google grants not removed: %s", h.file(t, "/srv/covee/grants.json"))
	}
	if got := strings.Join(providerIDs(t, h), ","); got != "entra" {
		t.Fatalf("providers after removal = %s", got)
	}
	if removed, _ := os.ReadFile(filepath.Join(h.state, "removed")); !strings.Contains(string(removed), "google-client-secret") {
		t.Fatal("the server copy of the Google secret was not removed")
	}
	if err := AuthRemove(ctx, h.env, "home", "microsoft"); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("removing the last method must fail: %v", err)
	}

	// A failed broker restart leaves the record as it was.
	_ = os.WriteFile(filepath.Join(h.state, "fail-providers"), nil, 0o600)
	h.env.Ask = h.answers(map[string]string{
		"google_client_id": "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com", "google_client_secret": "GOCSPX-abcdefghijklmnopqrstuvwx"})
	if err := AuthAdd(ctx, h.env, "home", "google"); err == nil || !strings.Contains(err.Error(), "kept its previous") {
		t.Fatalf("expected a kept-previous error, got %v", err)
	}
	n, _ = h.env.Records.Load("home")
	if strings.Join(n.Providers, ",") != "entra" || n.SignIn.Google != nil {
		t.Fatalf("record changed after a failed add: %v", n.Providers)
	}
}

func TestDeviceTokenCreatesATaggedKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.env.Ask = h.answers(nil)
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	h.out.Reset()
	if err := DeviceToken(ctx, h.env, "home", []string{"Office-NAS"}, "7d", true, false); err != nil {
		t.Fatal(err)
	}
	cmd, _ := os.ReadFile(filepath.Join(h.state, "device-key-command"))
	for _, want := range []string{"--tags 'tag:office-nas'", "--expiration '7d'", "--reusable", "--directory '/srv/covee/runtime-1'"} {
		if !strings.Contains(string(cmd), want) {
			t.Fatalf("command %q lacks %q", cmd, want)
		}
	}
	out := h.out.String()
	if !strings.Contains(out, "--login-server https://control.coveetest.io --auth-key hskey-auth-0123456789abcdef") || !strings.Contains(out, "denies all traffic by default") {
		t.Fatalf("instructions missing:\n%s", out)
	}
	if err := DeviceToken(ctx, h.env, "home", []string{"bad tag!"}, "24h", false, false); err == nil {
		t.Fatal("invalid tag accepted")
	}
}

func TestUpdateInstallsNewerFilesAndRestarts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.env.Ask = h.answers(nil)
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	h.out.Reset()
	if err := Update(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "already runs") {
		t.Fatalf("same files must be a no-op: %v %s", err, h.out)
	}
	logBefore, _ := os.ReadFile(filepath.Join(h.state, "log"))
	h.env.Archive = func() ([]byte, string, error) { return []byte("payload v3"), "aaaabbbbccccddddeeeeffff00001111", nil }
	if err := Update(ctx, h.env, "home"); err != nil {
		t.Fatalf("update: %v\n%s", err, h.out)
	}
	logAfter, _ := os.ReadFile(filepath.Join(h.state, "log"))
	added := string(logAfter[len(logBefore):])
	order := []string{"src.new", "deploy.py build", "deploy.py validate", "deploy.py up", "curl -fsS"}
	at := 0
	for _, want := range order {
		i := strings.Index(added[at:], want)
		if i < 0 {
			t.Fatalf("update did not run %q in order:\n%s", want, added)
		}
		at += i
	}
	n, _ := h.env.Records.Load("home")
	if n.Payload != "aaaabbbbccccddddeeeeffff00001111" {
		t.Fatalf("payload not recorded: %s", n.Payload)
	}
}

func TestBackupDownloadsAndVerifiesAnEncryptedSnapshot(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("the fake server needs the age command to encrypt its snapshot")
	}
	h := newHarness(t)
	ctx := context.Background()
	h.env.Ask = h.answers(nil)
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	h.env.Ask = h.answers(map[string]string{"backup": "yes"})
	if err := Backup(ctx, h.env, "home"); err != nil {
		t.Fatalf("backup: %v\n%s", err, h.out)
	}
	n, _ := h.env.Records.Load("home")
	if len(n.Backups) != 1 || n.Backups[0].Files != 2 || n.BackupRecipient == "" || !strings.HasPrefix(n.BackupRecipient, "age1") {
		t.Fatalf("backup not recorded: %+v %s", n.Backups, n.BackupRecipient)
	}
	if info, err := os.Stat(n.Backups[0].File); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("local backup missing or not private: %v", err)
	}
	identity, ok := h.ssm.values["/covee/home/backup-age-identity"]
	if !ok || !strings.HasPrefix(identity, "AGE-SECRET-KEY-") {
		t.Fatal("the backup key is not in Parameter Store")
	}
	raw, _ := os.ReadFile(filepath.Join(h.env.Home, "networks", "home.json"))
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("the record contains the backup key")
	}
	// A second backup reuses the same key; one from another network is refused.
	_ = os.WriteFile(filepath.Join(h.state, "wrong-host"), nil, 0o600)
	time.Sleep(1100 * time.Millisecond)
	if err := Backup(ctx, h.env, "home"); err == nil || !strings.Contains(err.Error(), "belongs to other.coveetest.io") {
		t.Fatalf("expected a wrong-network refusal, got %v", err)
	}
	n2, _ := h.env.Records.Load("home")
	if n2.BackupRecipient != n.BackupRecipient {
		t.Fatal("the backup key changed between backups")
	}
}

func TestSetupCreatesAProxmoxVM(t *testing.T) {
	h := newHarness(t)
	vmPoll = time.Millisecond
	facts := `{"node": "pve", "next_vmid": 103, "used_vmids": [100, 101, 102], "disk_storages": [{"id": "local-lvm", "free_gib": 1000}, {"id": "nvme", "free_gib": 500}],
"snippet_storages": [{"id": "snippets", "directory": "/var/lib/vz/snippets/snippets"}], "bridges": ["vmbr0"], "gateway": "192.168.50.1",
"host_cidr": "192.168.50.10/24", "ssh_client": "192.168.50.30", "cached_image": true, "version": "pve-manager/8.4.1/0123456789abcdef"}`
	_ = os.WriteFile(filepath.Join(h.state, "proxmox-facts.json"), []byte(strings.ReplaceAll(facts, "\n", "")+"\n"), 0o600)
	h.env.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		body := `{"issuer":"https://control.coveetest.io/identity"}`
		if r.URL.Host == "checkip.amazonaws.com" {
			body = "198.51.100.20\n"
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	h.env.Ask = h.answers(map[string]string{"server_kind": labelProxmox, "proxmox_host": "192.168.50.10", "vm_id": "102", "public_address": ""})
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("a used VM ID must be refused, got %v", err)
	}
	h.env.Ask = h.answers(map[string]string{"server_kind": labelProxmox, "proxmox_host": "192.168.50.10", "vm_storage": "nvme",
		"vm_address": "192.168.50.21/24", "vm_size": labelSizeSmall})
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	var req map[string]any
	b, _ := os.ReadFile(filepath.Join(h.state, "vm-request.json"))
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"node": "pve", "vmid": float64(103), "name": "covee-home", "disk_storage": "nvme", "snippet_storage": "snippets",
		"snippet_directory": "/var/lib/vz/snippets/snippets", "bridge": "vmbr0", "network_interface": "eth0", "ipv4_cidr": "192.168.50.21/24",
		"gateway_ipv4": "192.168.50.1", "cores": float64(2), "memory_mib": float64(4096), "disk_gib": float64(32), "control_host": "control.coveetest.io"}
	for k, v := range want {
		if req[k] != v {
			t.Errorf("VM request %s = %v, want %v", k, req[k], v)
		}
	}
	if sources := fmt.Sprint(req["ssh_source_cidrs"]); sources != "[192.168.50.0/24]" {
		t.Errorf("SSH sources = %s", sources)
	}
	if !strings.HasPrefix(fmt.Sprint(req["ssh_public_key"]), "ssh-ed25519 ") {
		t.Error("the VM did not get the covee key")
	}
	n, _ := h.env.Records.Load("home")
	if n.Server.Kind != "proxmox" || n.Server.Address != "192.168.50.21" || n.Server.Proxmox.VMID != 103 || n.PublicAddress != "198.51.100.20" || !n.Done("verify") {
		t.Fatalf("record = %+v %+v", n.Server, n.Server.Proxmox)
	}
	log, _ := os.ReadFile(filepath.Join(h.state, "log"))
	if strings.Contains(string(log), "host_prepare.py' account") || strings.Contains(string(log), "host_prepare.py' system") {
		t.Fatal("a Proxmox VM is prepared by cloud-init, not by the existing-server steps")
	}
}

// writeBackup makes an age-encrypted runtime snapshot like deploy_backup.py does.
func writeBackup(t *testing.T, path string, recipient age.Recipient, host string) {
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	add := func(name, body string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o400, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	meta := map[string]any{"format": 1, "lab": false, "spec": map[string]any{"control_host": host, "dns_base_domain": "mesh.coveetest.io",
		"identity": map[string]any{
			"providers": []any{
				map[string]any{"id": "entra", "kind": "entra", "issuer": "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/v2.0",
					"client_id": "00000000-0000-4000-8000-000000000002", "client_secret_file": "/run/identity-secrets/entra-client-secret",
					"allowed_group_ids": []any{"00000000-0000-4000-8000-000000000003"}},
				map[string]any{"id": "google", "kind": "google", "client_id": "1-x.apps.googleusercontent.com", "client_secret_file": "/run/identity-secrets/google-client-secret"}},
			"grants": []any{map[string]any{"provider": "google", "subject": "100000000000000000001", "role": "Covee.Admin", "enroll": true}}}}}
	data, _ := json.Marshal(meta)
	add("deployment.json", string(data))
	add("state/headscale/db.sqlite", "SQLite format 3")
	add("identity-secrets/entra-client-secret", "backed-up-entra-secret")
	add("identity-secrets/google-client-secret", "backed-up-google-secret")
	_ = tw.Close()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := age.Encrypt(f, recipient)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(plain.Bytes())
	_ = w.Close()
	_ = f.Close()
}

func TestSetupRestoresANetworkFromABackup(t *testing.T) {
	h := newHarness(t)
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	archive, keyFile := filepath.Join(dir, "home-20261012T200648Z.tar.age"), filepath.Join(dir, "backup.key")
	writeBackup(t, archive, id.Recipient(), "control.coveetest.io")
	_ = os.WriteFile(keyFile, []byte("# created: today\n"+id.String()+"\n"), 0o600)
	h.env.Ask = h.answers(map[string]string{"start_from": labelBackup, "backup_file": archive, "backup_key": keyFile, "hostname": "", "sign_in": ""})
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("restore: %v\n%s", err, h.out)
	}
	n, _ := h.env.Records.Load("home")
	if n.Hostname != "control.coveetest.io" || n.DNSBaseDomain != "mesh.coveetest.io" || strings.Join(n.Providers, ",") != "entra,google" {
		t.Fatalf("record not taken from the backup: %s %s %v", n.Hostname, n.DNSBaseDomain, n.Providers)
	}
	if n.SignIn.Entra.GroupID != "00000000-0000-4000-8000-000000000003" || n.SignIn.Google.ClientID != "1-x.apps.googleusercontent.com" || n.RestoredFrom.Grants != 1 {
		t.Fatalf("sign-in not taken from the backup: %+v %+v", n.SignIn, n.RestoredFrom)
	}
	if h.ssm.values["/covee/home/entra-client-secret"] != "backed-up-entra-secret" || h.ssm.values["/covee/home/google-client-secret"] != "backed-up-google-secret" {
		t.Fatal("the backup's sign-in secrets were not kept in the secrets store")
	}
	if strings.TrimSpace(h.ssm.values["/covee/home/backup-age-identity"]) != id.String() || n.BackupRecipient != id.Recipient().String() {
		t.Fatal("the backup key was not kept for later backups")
	}
	if h.file(t, "/srv/covee/secrets/google-client-secret") != "backed-up-google-secret" {
		t.Fatal("the restored secrets were not copied to the server")
	}
	archiveOnServer := h.file(t, "/srv/covee/backups/restore-"+n.RestoredFrom.SHA256[:12]+".tar.age")
	if raw, _ := os.ReadFile(archive); archiveOnServer != string(raw) {
		t.Fatal("the backup was not copied to the server unchanged")
	}
	removed, _ := os.ReadFile(filepath.Join(h.state, "removed"))
	if !strings.Contains(string(removed), "/srv/covee/.restore-identity") {
		t.Fatal("the backup key was left on the server")
	}
	calls, _ := os.ReadFile(filepath.Join(h.state, "deploy-calls"))
	if got := strings.Join(strings.Fields(string(calls)), ","); !strings.HasPrefix(got, "restore,renew-certificates,validate,up") || strings.Contains(got, "prepare") {
		t.Fatalf("deploy calls = %s", got)
	}
	// The hostname moves only after the restored network runs.
	log, _ := os.ReadFile(filepath.Join(h.state, "log"))
	if h.r53.a["control.coveetest.io."] != "203.0.113.9" || !strings.Contains(h.out.String(), "moves to the new server only at the end") {
		t.Fatal("DNS was not pointed at the new server, or the summary did not say when")
	}
	startAt := strings.Index(string(log), "scripts/deploy.py up")
	if startAt < 0 {
		t.Fatal("the restored network was not started")
	}
	order := []string{}
	for _, c := range n.Completed {
		order = append(order, c)
	}
	if strings.Join(order, ",") != "ssh-key,backup-key,import,certificate,account,system,source,secrets,build,start,dns,maintenance,verify" {
		t.Fatalf("step order = %v", order)
	}
}

func TestRestoreRefusesTheWrongKey(t *testing.T) {
	h := newHarness(t)
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	archive, keyFile := filepath.Join(dir, "b.tar.age"), filepath.Join(dir, "k")
	writeBackup(t, archive, id.Recipient(), "control.coveetest.io")
	_ = os.WriteFile(keyFile, []byte(other.String()+"\n"), 0o600)
	h.env.Ask = h.answers(map[string]string{"start_from": labelBackup, "backup_file": archive, "backup_key": keyFile})
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err == nil || !strings.Contains(err.Error(), "cannot decrypt") {
		t.Fatalf("expected a key refusal, got %v", err)
	}
}

func TestSetupWithCoveeAccountsInvitesTheFirstAdmin(t *testing.T) {
	h := newHarness(t)
	h.env.Ask = h.answers(map[string]string{"sign_in": labelLocalAccounts, "local_admin_email": "Alice@Example.org", "local_admin_name": "Alice"})
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	var spec map[string]any
	_ = json.Unmarshal([]byte(h.file(t, "/srv/covee/deployment.json")), &spec)
	providers := spec["identity"].(map[string]any)["providers"].([]any)
	if len(providers) != 1 || fmt.Sprint(providers[0]) != "map[id:local kind:local]" {
		t.Fatalf("providers = %v", providers)
	}
	calls, _ := os.ReadFile(filepath.Join(h.state, "local-calls"))
	if !strings.Contains(string(calls), "--action invite --email 'alice@example.org' --name 'Alice' --role admin --enroll true") {
		t.Fatalf("first admin not invited: %s", calls)
	}
	if !strings.Contains(h.out.String(), "https://control.coveetest.io/identity/local/invite#TOKEN123") {
		t.Fatalf("invite link not shown:\n%s", h.out)
	}
	n, _ := h.env.Records.Load("home")
	if n.SignIn.Local == nil || n.SignIn.Local.FirstAdmin != "alice@example.org" || !n.Done("local-admin") {
		t.Fatalf("record = %+v %v", n.SignIn.Local, n.Completed)
	}
	for id := range h.ssm.values {
		if strings.Contains(id, "local") {
			t.Fatalf("Covee accounts need no secret in the store: %s", id)
		}
	}
}

func TestUsersCommandsManageCoveeAccounts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.env.Ask = h.answers(nil)
	if err := Run(ctx, h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	if err := UsersInvite(ctx, h.env, "home", "bob@example.org", "Bob", "none", true, "72h"); err == nil || !strings.Contains(err.Error(), "auth add home accounts") {
		t.Fatalf("accounts are off: expected guidance, got %v", err)
	}
	if err := AuthAdd(ctx, h.env, "home", "accounts"); err != nil {
		t.Fatalf("auth add accounts: %v\n%s", err, h.out)
	}
	if got := strings.Join(providerIDs(t, h), ","); got != "entra,local" {
		t.Fatalf("providers = %s", got)
	}
	h.out.Reset()
	if err := UsersInvite(ctx, h.env, "home", "Bob@Example.org", "Bob", "reader", false, "48h"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "/identity/local/invite#TOKEN123") {
		t.Fatalf("no link: %s", h.out)
	}
	for _, bad := range []func() error{
		func() error { return UsersInvite(ctx, h.env, "home", "not-an-email", "Bob", "reader", true, "72h") },
		func() error { return UsersInvite(ctx, h.env, "home", "bob@example.org", "", "reader", true, "72h") },
		func() error { return UsersInvite(ctx, h.env, "home", "bob@example.org", "Bob", "owner", true, "72h") },
		func() error { return UsersInvite(ctx, h.env, "home", "bob@example.org", "Bob", "none", false, "72h") },
	} {
		if bad() == nil {
			t.Fatal("an invalid invite was accepted")
		}
	}
	_ = os.WriteFile(filepath.Join(h.state, "account-exists"), nil, 0o600)
	if err := UsersInvite(ctx, h.env, "home", "bob@example.org", "Bob", "reader", true, "72h"); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("the server's refusal must reach the admin, got %v", err)
	}
	enroll := false
	if err := UsersUpdate(ctx, h.env, "home", "bob@example.org", "reader", &enroll); err != nil {
		t.Fatal(err)
	}
	h.env.Ask = h.answers(map[string]string{"reset_account": "yes", "remove_account": "no"})
	h.out.Reset()
	if err := UsersReset(ctx, h.env, "home", "bob@example.org", "72h"); err != nil || !strings.Contains(h.out.String(), "#TOKEN456") {
		t.Fatalf("reset: %v %s", err, h.out)
	}
	if err := UsersRemove(ctx, h.env, "home", "bob@example.org"); err != prompt.ErrAborted {
		t.Fatalf("declined removal: %v", err)
	}
	h.out.Reset()
	if err := UsersList(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "alice@example.org") || !strings.Contains(h.out.String(), "1 passkey") || !strings.Contains(h.out.String(), "role admin") {
		t.Fatalf("list: %v %s", err, h.out)
	}
	if !strings.Contains(h.out.String(), `the "Covee home users" group for devices`) {
		t.Fatalf("list must name the network's own Microsoft group:\n%s", h.out)
	}
	calls, _ := os.ReadFile(filepath.Join(h.state, "local-calls"))
	for _, want := range []string{"--action invite --email 'bob@example.org' --name 'Bob' --role reader --enroll false --expires '48h'",
		"--action update --email 'bob@example.org' --role reader --enroll false", "--action reset --email 'bob@example.org'", "--action list"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("missing call %q in:\n%s", want, calls)
		}
	}
	if strings.Contains(string(calls), "--action remove") {
		t.Fatal("a declined removal reached the server")
	}
}

func TestSetupSchedulesTheConsoleKeyRotation(t *testing.T) {
	h := newHarness(t)
	h.env.Ask = h.answers(nil)
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	service, err := os.ReadFile(filepath.Join(h.state, "units", "covee-api-key.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=covee", "ExecStart=/usr/bin/python3 /opt/covee/src/scripts/deploy.py rotate-api-key --directory /srv/covee/runtime-1", "NoNewPrivileges=true"} {
		if !strings.Contains(string(service), want) {
			t.Errorf("service lacks %q", want)
		}
	}
	timer, _ := os.ReadFile(filepath.Join(h.state, "units", "covee-api-key.timer"))
	if !strings.Contains(string(timer), "OnUnitActiveSec=12h") || !strings.Contains(string(timer), "WantedBy=timers.target") {
		t.Fatalf("timer = %s", timer)
	}
	actions, _ := os.ReadFile(filepath.Join(h.state, "units", "actions"))
	if strings.Join(strings.Fields(string(actions)), ",") != "enabled,started" {
		t.Fatalf("the timer was not enabled and run once: %s", actions)
	}
	n, _ := h.env.Records.Load("home")
	if !n.Done("maintenance") {
		t.Fatal("maintenance step not recorded")
	}
}

func TestAFailedKeyRotationStopsSetup(t *testing.T) {
	h := newHarness(t)
	_ = os.WriteFile(filepath.Join(h.state, "fail-rotation"), nil, 0o600)
	h.env.Ask = h.answers(nil)
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err == nil || !strings.Contains(err.Error(), "first key rotation failed") {
		t.Fatalf("expected the rotation failure, got %v", err)
	}
}
