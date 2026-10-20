package setup

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"covee.io/cli/internal/record"
)

func TestCheckHostname(t *testing.T) {
	for _, ok := range []string{"control.covee.io", "vpn.example-office.net", "a.b.c.example-covee.net"} {
		if err := checkHostname(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"covee", "Control.covee.io", "vpn.example.com", "x.test", "1.2.3.4", "-a.covee.io", "a..covee.io"} {
		if err := checkHostname(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := defaultMeshDomain("control.covee.io"); got != "mesh.covee.io" {
		t.Fatal(got)
	}
	if got := defaultMeshDomain("covee.io"); got != "mesh.covee.io" {
		t.Fatal(got)
	}
}

func TestSSHSourcesMustIncludeTheClient(t *testing.T) {
	client := net.ParseIP("192.168.50.30")
	got, err := sshSources("192.168.50.0/24, 203.0.113.7", client)
	if err != nil || strings.Join(got, ",") != "192.168.50.0/24,203.0.113.7/32" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"10.0.0.0/24", "192.168.0.0/16", "192.168.50.5/24", "fe80::/64", ""} {
		if _, err := sshSources(bad, client); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDeploymentConfigMatchesTheSocialProfile(t *testing.T) {
	n := &record.Network{Hostname: "control.covee.io", DNSBaseDomain: "mesh.covee.io", SignIn: record.SignIn{
		Entra:  &record.Entra{TenantID: "00000000-0000-4000-8000-000000000001", ClientID: "00000000-0000-4000-8000-000000000002", GroupID: "00000000-0000-4000-8000-000000000003"},
		Google: &record.Google{ClientID: "1-x.apps.googleusercontent.com"},
		Apple:  &record.Apple{TeamID: "87LFD98HJU", ServicesID: "io.covee.signin", KeyID: "ABCDE12345"},
	}}
	data, err := deploymentConfig(n, nil)
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	identity := spec["identity"].(map[string]any)
	if grants := identity["grants"].([]any); len(grants) != 0 {
		t.Fatal("grants must be an explicit empty list")
	}
	providers := identity["providers"].([]any)
	want := []map[string]any{
		{"id": "entra", "kind": "entra", "issuer": "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/v2.0",
			"client_id": "00000000-0000-4000-8000-000000000002", "client_secret_file": "/srv/covee/secrets/entra-client-secret",
			"allowed_group_ids": []any{"00000000-0000-4000-8000-000000000003"}},
		{"id": "google", "kind": "google", "client_id": "1-x.apps.googleusercontent.com", "client_secret_file": "/srv/covee/secrets/google-client-secret"},
		{"id": "apple", "kind": "apple", "client_id": "io.covee.signin", "team_id": "87LFD98HJU", "key_id": "ABCDE12345",
			"private_key_file": "/srv/covee/secrets/apple-AuthKey_ABCDE12345.p8"},
	}
	got, _ := json.Marshal(providers)
	expected, _ := json.Marshal(want)
	if string(got) != string(expected) {
		t.Fatalf("providers:\n got %s\nwant %s", got, expected)
	}
	if spec["control_host"] != "control.covee.io" || spec["public_port"] != float64(443) || spec["stun_port"] != float64(3478) || spec["admin_host"] != "localhost" {
		t.Fatalf("spec = %v", spec)
	}
	if _, err := deploymentConfig(&record.Network{}, nil); err == nil {
		t.Fatal("a network without sign-in methods must be refused")
	}
}

func TestLastJSON(t *testing.T) {
	var v map[string]any
	if err := lastJSON([]byte("progress\nmore\n{\"ok\":true}\n"), &v); err != nil || v["ok"] != true {
		t.Fatalf("%v %v", v, err)
	}
	if err := lastJSON([]byte(`{"error":"nope"}`), &v); err == nil || err.Error() != "nope" {
		t.Fatalf("server error not surfaced: %v", err)
	}
	if err := lastJSON([]byte("garbage"), &v); err == nil {
		t.Fatal("garbage accepted")
	}
}
