package record

import (
	"errors"
	"os"
	"path/filepath"
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
