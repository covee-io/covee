package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sync"

	"tailscale.com/ipn"
)

const maxStateBytes = 8 << 20

// keychainStore makes the platform's durable write part of WriteState itself.
// A failed Keychain write neither reports success nor advances in-memory state.
type keychainStore struct {
	mu      sync.Mutex
	state   map[string][]byte
	persist func([]byte) error
	// Installed before backend construction. Invoke only after releasing mu:
	// upstream callers can hold LocalBackend/profile-manager locks here.
	onFailure func()
	failed    bool
}

func newKeychainStore(raw []byte, persist func([]byte) error) (*keychainStore, error) {
	if persist == nil {
		return nil, errors.New("durable state persistence callback is required")
	}
	if len(raw) == 0 || len(raw) > maxStateBytes {
		return nil, errors.New("state must be a JSON object of at most 8 MiB")
	}
	state := make(map[string][]byte)
	if err := json.Unmarshal(raw, &state); err != nil || state == nil || bytes.TrimSpace(raw)[0] != '{' {
		return nil, errors.New("state must map names to base64-encoded byte strings")
	}
	for key, value := range state {
		if len(key) > 1024 || value == nil {
			return nil, errors.New("state contains an invalid entry")
		}
	}
	return &keychainStore{state: state, persist: persist}, nil
}

func (s *keychainStore) ReadState(id ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.state[string(id)]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return slices.Clone(value), nil
}

func (s *keychainStore) WriteState(id ipn.StateKey, value []byte) (err error) {
	s.mu.Lock()
	defer func() {
		if err != nil && s.onFailure != nil {
			s.failed = true
		}
		s.mu.Unlock()
		if err != nil && s.onFailure != nil {
			s.onFailure()
		}
	}()
	if s.failed {
		return errors.New("durable state persistence failed")
	}
	if len(id) > 1024 {
		return errors.New("state name is too long")
	}
	next := maps.Clone(s.state)
	if value == nil {
		delete(next, string(id))
	} else {
		next[string(id)] = slices.Clone(value)
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > maxStateBytes {
		return errors.New("state exceeds 8 MiB")
	}
	if err := s.persist(raw); err != nil {
		return errors.New("durable state persistence failed")
	}
	s.state = next
	return nil
}
