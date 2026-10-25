package remote

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSSH runs the command on this computer, as the server would. With
// $STATE/drop, the first session is cut a second in, the way a restart of the
// network's gateway cuts an admin's session; with $STATE/unreachable, every
// session after the first fails as if the server were out of reach.
const fakeSSH = `#!/bin/sh
for last; do :; done
n=$(cat "$STATE/calls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$STATE/calls"
[ -f "$STATE/down" ] && { echo "ssh: connect to host server port 22: Operation timed out" >&2; exit 255; }
[ "$n" -gt 1 ] && [ -f "$STATE/unreachable" ] && { echo "ssh: connect to host server port 22: Operation timed out" >&2; exit 255; }
if [ "$n" = 1 ] && [ -f "$STATE/drop" ]; then
  sh -c "$last" &
  pid=$!
  sleep 1
  kill "$pid"
  echo "Connection to server closed by remote host." >&2
  exit 255
fi
exec sh -c "$last"
`

func fakeHost(t *testing.T, flags ...string) (*Host, string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, flag := range flags {
		if err := os.WriteFile(filepath.Join(state, flag), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(fakeSSH), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATE", state)
	t.Setenv("HOME", filepath.Join(dir, "home"))
	every, within := reconnectEvery, reconnectFor
	reconnectEvery, reconnectFor = 50*time.Millisecond, 3*time.Second
	t.Cleanup(func() { reconnectEvery, reconnectFor = every, within })
	return &Host{Address: "server", User: "covee", KnownHosts: filepath.Join(dir, "known_hosts"), Binary: ssh}, state
}

func calls(t *testing.T, state string) string {
	t.Helper()
	n, _ := os.ReadFile(filepath.Join(state, "calls"))
	return strings.TrimSpace(string(n))
}

func TestApartReturnsTheOutputAndTheCommandsStatus(t *testing.T) {
	h, _ := fakeHost(t)
	var shown bytes.Buffer
	out, err := h.Apart(context.Background(), "echo one; echo two >&2", &shown)
	if err != nil || string(out) != "one\ntwo\n" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if shown.String() != "    one\n    two\n" {
		t.Fatalf("shown %q", shown.String())
	}
	out, err = h.Apart(context.Background(), "echo broke >&2; exit 3", nil)
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "broke") || string(out) != "broke\n" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	// A status of 255 would read as a dropped session, so it arrives as 254.
	if _, err = h.Apart(context.Background(), "exit 255", nil); err == nil || !strings.Contains(err.Error(), "exit status 254") {
		t.Fatalf("err=%v", err)
	}
	info, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".covee-runs"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the runs folder is not private: %v %v", info, err)
	}
}

func TestApartCarriesOnWhenTheSessionDrops(t *testing.T) {
	h, state := fakeHost(t, "drop")
	var shown bytes.Buffer
	out, err := h.Apart(context.Background(), "echo one; sleep 2; echo two", &shown)
	if err != nil {
		t.Fatalf("err=%v\n%s", err, shown.String())
	}
	if string(out) != "one\ntwo\n" {
		t.Fatalf("the output was lost or repeated: %q", out)
	}
	if !strings.Contains(shown.String(), "Connecting again") || !strings.HasSuffix(shown.String(), "    two\n") {
		t.Fatalf("shown %q", shown.String())
	}
	if n := calls(t, state); n == "1" {
		t.Fatal("the CLI did not connect again")
	}
}

func TestApartReportsTheStatusOfACommandThatEndedWhileDisconnected(t *testing.T) {
	h, _ := fakeHost(t, "drop")
	out, err := h.Apart(context.Background(), "echo one; sleep 2; echo failed >&2; exit 4", nil)
	if err == nil || !strings.Contains(err.Error(), "exit status 4") || string(out) != "one\nfailed\n" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestApartGivesUpOnAServerThatStaysOutOfReach(t *testing.T) {
	h, state := fakeHost(t, "drop", "unreachable")
	start := time.Now()
	_, err := h.Apart(context.Background(), "echo one; sleep 6", nil)
	if err == nil || !strings.Contains(err.Error(), "stayed out of reach") {
		t.Fatalf("err=%v", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatal("it kept trying long after the limit")
	}
	if n := calls(t, state); n == "1" || n == "2" {
		t.Fatalf("it connected only %s times", n)
	}
}

func TestApartDoesNotRetryACommandThatNeverStarted(t *testing.T) {
	h, state := fakeHost(t, "down")
	_, err := h.Apart(context.Background(), "echo one", nil)
	if err == nil || !strings.Contains(err.Error(), "Operation timed out") {
		t.Fatalf("err=%v", err)
	}
	if n := calls(t, state); n != "1" {
		t.Fatalf("it connected %s times", n)
	}
}

func TestFirstLineDropsOnlyTheRunsName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"0123abcd\nhello\n", "hello\n"},
		{"deployed\n", "deployed\n"},
		{"0123", "0123"},
		{"0123abcdX\n", "0123abcdX\n"},
		{"", ""},
	} {
		var out bytes.Buffer
		f := &firstLine{want: "0123abcd", next: &out}
		for i := 0; i < len(c.in); i++ { // one byte at a time, as a slow session delivers it
			if _, err := f.Write([]byte{c.in[i]}); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.flush(); err != nil {
			t.Fatal(err)
		}
		if out.String() != c.want || f.seen != strings.HasPrefix(c.in, "0123abcd\n") {
			t.Fatalf("%q: got %q seen=%v", c.in, out.String(), f.seen)
		}
	}
}
