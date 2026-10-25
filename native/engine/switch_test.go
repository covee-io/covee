package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// signInControl is a coordinator, with its own relay, that asks every new
// device to sign in.
func signInControl(t *testing.T, relay *tailcfg.DERPMap) (*testcontrol.Server, string) {
	t.Helper()
	ctl := &testcontrol.Server{RequireAuth: true, DERPMap: relay, Logf: logger.Discard}
	ctl.HTTPTestServer = httptest.NewUnstartedServer(ctl)
	ctl.HTTPTestServer.Start()
	t.Cleanup(ctl.HTTPTestServer.Close)
	return ctl, ctl.HTTPTestServer.URL
}

// savedState is the Keychain item the app keeps between connections.
type savedState struct {
	mu  sync.Mutex
	raw []byte
}

func (s *savedState) store(t *testing.T) *keychainStore {
	t.Helper()
	s.mu.Lock()
	raw := bytes.Clone(s.raw)
	s.mu.Unlock()
	if raw == nil {
		raw = []byte(`{}`)
	}
	store, err := newKeychainStore(raw, func(b []byte) error {
		s.mu.Lock()
		s.raw = bytes.Clone(b)
		s.mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func connect(t *testing.T, state *savedState, controlURL string) *engine {
	t.Helper()
	e := newEngine(engineConfig{ControlURL: controlURL, Hostname: "covee-switch-test"}, state.store(t))
	if err := e.start(); err != nil {
		e.stop()
		t.Fatal(err)
	}
	return e
}

func waitStatus(t *testing.T, e *engine, what string, ok func(*ipnstate.Status) bool) *ipnstate.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		st := e.backend.Status()
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: still %s (sign-in address %q)", what, st.BackendState, st.AuthURL)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func signIn(t *testing.T, e *engine, ctl *testcontrol.Server, controlURL string) {
	t.Helper()
	st := waitStatus(t, e, "asking to sign in at "+controlURL, func(st *ipnstate.Status) bool {
		return st.BackendState == "NeedsLogin" && strings.HasPrefix(st.AuthURL, controlURL+"/")
	})
	if !ctl.CompleteAuth(st.AuthURL) {
		t.Fatalf("%s does not know the sign-in address %s", controlURL, st.AuthURL)
	}
	waitStatus(t, e, "connected to "+controlURL, func(st *ipnstate.Status) bool { return st.BackendState == "Running" })
}

// Changing the app's coordinator address must ask to sign in to the new
// network, never present the old network's device there, and keep the old
// sign-in so that switching back needs none.
func TestSwitchingCoordinatorSignsInAgainAndKeepsTheOldSignIn(t *testing.T) {
	relay := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	home, homeURL := signInControl(t, relay)
	office, officeURL := signInControl(t, relay)
	state := &savedState{}

	e := connect(t, state, homeURL)
	signIn(t, e, home, homeURL)
	e.stop()

	e = connect(t, state, officeURL)
	signIn(t, e, office, officeURL)
	e.stop()
	if len(home.AllNodes()) != 1 || len(office.AllNodes()) != 1 {
		t.Fatalf("devices: home %d, office %d", len(home.AllNodes()), len(office.AllNodes()))
	}
	if home.AllNodes()[0].Key == office.AllNodes()[0].Key {
		t.Fatal("the office network was shown the home network's device key")
	}

	e = connect(t, state, homeURL)
	defer e.stop()
	waitStatus(t, e, "back on the home network without signing in", func(st *ipnstate.Status) bool {
		if st.BackendState == "NeedsLogin" {
			t.Fatalf("switching back asked to sign in again (%s)", st.AuthURL)
		}
		return st.BackendState == "Running"
	})
	if len(home.AllNodes()) != 1 {
		t.Fatalf("switching back added a device at home: %d", len(home.AllNodes()))
	}
	// The app offers both networks again without typing their addresses.
	offered := map[string]bool{}
	for _, n := range e.buildStatus(e.backend).Networks {
		offered[n.ControlURL] = true
	}
	if !offered[homeURL] || !offered[officeURL] || len(offered) != 2 {
		t.Fatalf("networks offered: %v", offered)
	}
}

// When the sign-in expires while connected, the engine offers a new sign-in
// address by itself, so the app can open it.
func TestExpiredSignInOffersANewSignIn(t *testing.T) {
	relay := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	ctl, controlURL := signInControl(t, relay)
	e := connect(t, &savedState{}, controlURL)
	defer e.stop()
	signIn(t, e, ctl, controlURL)

	nodes := ctl.AllNodes()
	if len(nodes) != 1 {
		t.Fatalf("devices: %d", len(nodes))
	}
	expired := nodes[0].Clone()
	expired.KeyExpiry = time.Now().Add(-time.Minute)
	ctl.UpdateNode(expired)
	st := waitStatus(t, e, "offering a new sign-in", func(st *ipnstate.Status) bool {
		return st.BackendState == "NeedsLogin" && strings.HasPrefix(st.AuthURL, controlURL+"/")
	})
	if !ctl.CompleteAuth(st.AuthURL) {
		t.Fatalf("the coordinator does not know the sign-in address %s", st.AuthURL)
	}
	// The test coordinator carries the old expiry over to the new key.
	for _, n := range ctl.AllNodes() {
		if !n.KeyExpiry.IsZero() {
			n.KeyExpiry = time.Time{}
			ctl.UpdateNode(n)
		}
	}
	waitStatus(t, e, "connected again", func(st *ipnstate.Status) bool { return st.BackendState == "Running" })
}

// A coordinator under a new address, whose old address is gone, is still the
// same network: the device keeps its key, its address and its sign-in, with
// or without a record from before (sign-ins saved by older versions).
func TestARenamedCoordinatorWhoseOldAddressIsGoneKeepsTheDevice(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "recorded", true: "saved by an older version"}[legacy], func(t *testing.T) {
			relay := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
			ctl := &testcontrol.Server{DERPMap: relay, Logf: logger.Discard}
			before := httptest.NewServer(ctl)
			after := httptest.NewServer(ctl)
			t.Cleanup(after.Close)
			state := &savedState{}

			e := connect(t, state, before.URL)
			first := waitStatus(t, e, "connected", func(st *ipnstate.Status) bool { return st.BackendState == "Running" && st.Self != nil })
			waitRecorded(t, state)
			e.stop()
			before.Close()
			if legacy {
				state.forget(t, coordinatorsState)
			}

			e = connect(t, state, after.URL)
			defer e.stop()
			again := waitStatus(t, e, "connected under the new address", func(st *ipnstate.Status) bool {
				if st.BackendState == "NeedsLogin" {
					t.Fatal("the renamed network asked to sign in again")
				}
				return st.BackendState == "Running" && st.Self != nil
			})
			if again.Self.PublicKey != first.Self.PublicKey || len(ctl.AllNodes()) != 1 {
				t.Fatalf("the device came back as another device (%d devices)", len(ctl.AllNodes()))
			}
		})
	}
}

// An address that does not answer cannot be told apart from the current
// network, so the engine stops with a clear error and changes nothing.
func TestAnUnreachableNewAddressChangesNothing(t *testing.T) {
	relay := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	home, homeURL := signInControl(t, relay)
	state := &savedState{}
	e := connect(t, state, homeURL)
	signIn(t, e, home, homeURL)
	e.stop()

	gone := httptest.NewServer(nil)
	gone.Close()
	e = newEngine(engineConfig{ControlURL: gone.URL, Hostname: "covee-switch-test"}, state.store(t))
	err := e.start()
	e.stop()
	if err == nil || !strings.Contains(err.Error(), "could not reach "+gone.URL) {
		t.Fatalf("start = %v", err)
	}

	e = connect(t, state, homeURL)
	defer e.stop()
	waitStatus(t, e, "back home without signing in", func(st *ipnstate.Status) bool {
		if st.BackendState == "NeedsLogin" {
			t.Fatal("the failed attempt cost the home sign-in")
		}
		return st.BackendState == "Running"
	})
}

func waitRecorded(t *testing.T, state *savedState) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if store := state.store(t); store != nil {
			if _, err := store.ReadState(coordinatorsState); err == nil {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the coordinator was never recorded")
}

func (s *savedState) forget(t *testing.T, key ipn.StateKey) {
	t.Helper()
	if err := s.store(t).WriteState(key, nil); err != nil {
		t.Fatal(err)
	}
}
