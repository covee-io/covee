package record

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadListAndPermissions(t *testing.T) {
	home := filepath.Join(t.TempDir(), "covee")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	n := &Network{Organization: "Example Home", Name: "home", Hostname: "control.covee.io"}
	n.Mark("ssh-key")
	n.Mark("ssh-key")
	if err := store.Save(n); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&Network{Name: "office", Hostname: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load("home")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "control.covee.io" || !got.Done("ssh-key") || len(got.Completed) != 1 || got.Created.IsZero() {
		t.Fatalf("unexpected record: %+v", got)
	}
	all, err := store.List()
	if err != nil || len(all) != 2 || all[0].Name != "home" || all[1].Name != "office" {
		t.Fatalf("List = %v, %v", all, err)
	}
	info, _ := os.Stat(filepath.Join(store.Dir, "home.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v", info.Mode().Perm())
	}
	info, _ = os.Stat(home)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("home mode %v", info.Mode().Perm())
	}
	if _, err := store.Load("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"home", "office-2", "a1"} {
		if err := CheckName(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "h", "Home", "-home", "home-", "../x", "a b", "1home"} {
		if err := CheckName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHostsAreKept(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n := &Network{Name: "home", HostsEnabled: true, Hosts: []Host{
		{Name: "grafana", Device: "mac-mini", Port: 8080, Path: "/some/sub/service", Scheme: "http"},
		{Name: "nas", Device: "nas", Port: 5001, Scheme: "https", NoVerify: true},
	}}
	if err := s.Save(n); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "home.json"))
	for _, want := range []string{`"hosts_enabled": true`, `"no_verify": true`, `"path": "/some/sub/service"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("record lacks %s:\n%s", want, raw)
		}
	}
	got, err := s.Load("home")
	if err != nil || !got.HostsEnabled || len(got.Hosts) != 2 || got.Hosts[1] != n.Hosts[1] {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	if err := s.Save(&Network{Name: "work"}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(s.Dir, "work.json"))
	if strings.Contains(string(raw), "hosts") {
		t.Fatalf("a network without hosts mentions them:\n%s", raw)
	}
}
