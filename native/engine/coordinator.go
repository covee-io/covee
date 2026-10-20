package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
)

// coordinatorsState records which coordinator each saved sign-in belongs to,
// by the coordinator's Noise public key. A network can move to a new address
// (`covee rename`) and keep its key; another network always has another key.
const coordinatorsState ipn.StateKey = "_covee-coordinators"

// useProfileFor makes the backend use the right saved sign-in for the
// configured coordinator before Start:
//   - the same coordinator under a new address keeps this device and its
//     sign-in, as after `covee rename`;
//   - another coordinator gets its own saved sign-in, or a new one that asks
//     to sign in, and is never shown the device key used elsewhere. Switching
//     back needs no new sign-in.
//
// A new profile contacts no coordinator until Start gives it the address.
func (e *engine) useProfileFor(lb *ipnlocal.LocalBackend) error {
	address := e.cfg.ControlURL
	current := lb.CurrentProfile()
	if current.ID() == "" || sameControl(current.ControlURL(), address) {
		return nil
	}
	profiles := lb.ListProfiles()
	want, err := e.fetchControlKey(address)
	if err != nil {
		for _, p := range profiles {
			if sameControl(p.ControlURL(), address) {
				return lb.SwitchProfile(p.ID())
			}
		}
		// Which network this is decides which device identity to use, so
		// do not guess; nothing could connect right now anyway.
		return fmt.Errorf("could not reach %s to tell which network it is: %w", address, err)
	}
	known := e.coordinators()
	for _, p := range profiles {
		if known[p.ID()] == want {
			return lb.SwitchProfile(p.ID())
		}
	}
	// Sign-ins saved before coordinators were recorded.
	for _, p := range profiles {
		if known[p.ID()] == "" && sameControl(p.ControlURL(), address) {
			return lb.SwitchProfile(p.ID())
		}
	}
	if known[current.ID()] == "" {
		old, err := e.fetchControlKey(current.ControlURL())
		if err != nil || old == want {
			// The same coordinator, or one whose old address is gone, as
			// after `covee rename`.
			return nil
		}
		known[current.ID()] = old
		if err := e.saveCoordinators(known); err != nil {
			return err
		}
	}
	return lb.NewProfile()
}

// rememberCoordinator records, once connected, which coordinator the current
// sign-in belongs to. It runs on the status ticker.
func (e *engine) rememberCoordinator(lb *ipnlocal.LocalBackend) {
	if e.remembered.Load() || lb.State() != ipn.Running {
		return
	}
	id := lb.CurrentProfile().ID()
	if id == "" {
		return
	}
	key, err := e.fetchControlKey(e.cfg.ControlURL)
	if err != nil {
		return // try again on the next tick
	}
	known := e.coordinators()
	if known[id] != key {
		// Keep only sign-ins that still exist.
		live := map[ipn.ProfileID]string{}
		for _, p := range lb.ListProfiles() {
			if v, ok := known[p.ID()]; ok {
				live[p.ID()] = v
			}
		}
		live[id] = key
		if err := e.saveCoordinators(live); err != nil {
			e.recordError(err)
			return
		}
	}
	e.remembered.Store(true)
}

func (e *engine) coordinators() map[ipn.ProfileID]string {
	known := map[ipn.ProfileID]string{}
	if raw, err := e.store.ReadState(coordinatorsState); err == nil {
		if json.Unmarshal(raw, &known) != nil {
			return map[ipn.ProfileID]string{}
		}
	}
	return known
}

func (e *engine) saveCoordinators(known map[ipn.ProfileID]string) error {
	raw, err := json.Marshal(known)
	if err != nil {
		return err
	}
	return e.store.WriteState(coordinatorsState, raw)
}

// fetchControlKey reads a coordinator's Noise public key, as the control
// client does before it connects. Keys for this engine's own address are
// cached.
func (e *engine) fetchControlKey(address string) (string, error) {
	own := sameControl(address, e.cfg.ControlURL)
	if own {
		if k := e.controlKey.Load(); k != nil {
			return *k, nil
		}
	}
	if address == "" {
		return "", errors.New("no address")
	}
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	target := strings.TrimSuffix(address, "/") + "/key?v=" + strconv.Itoa(int(tailcfg.CurrentCapabilityVersion))
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext:     e.dialer.SystemDial,
		TLSClientConfig: &tls.Config{RootCAs: e.roots, MinVersion: tls.VersionTLS12},
	}}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the coordinator answered %s", resp.Status)
	}
	var keys tailcfg.OverTLSPublicKeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&keys); err != nil || keys.PublicKey.IsZero() {
		return "", errors.New("the coordinator sent no key")
	}
	k := keys.PublicKey.String()
	if own {
		e.controlKey.Store(&k)
	}
	return k, nil
}

func sameControl(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/"))
}
