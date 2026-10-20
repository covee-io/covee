package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxUpstreamResponse = 4 << 20

type upstream struct {
	base, key string
	client    *http.Client
}
type upstreamError struct {
	status    int
	uncertain bool
}

func (e *upstreamError) Error() string { return "Headscale request failed" }

func (u *upstream) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	r, err := http.NewRequestWithContext(ctx, method, u.base+path, body)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+u.key)
	r.Header.Set("Accept", "application/json")
	if in != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := u.client.Do(r)
	if err != nil {
		return &upstreamError{uncertain: method != "GET"}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &upstreamError{status: resp.StatusCode, uncertain: method != "GET" && resp.StatusCode >= 500}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse+1))
	if err != nil || len(data) > maxUpstreamResponse {
		return &upstreamError{uncertain: method != "GET"}
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return &upstreamError{uncertain: method != "GET"}
	}
	return nil
}

// ProtoJSON uses string IDs; accept numeric IDs too, without rounding uint64s.
type id string

func (i *id) UnmarshalJSON(b []byte) error {
	var s string
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
	} else {
		s = string(b)
	}
	if s == "" {
		*i = ""
		return nil
	}
	if _, err := strconv.ParseUint(s, 10, 64); err != nil {
		return errors.New("invalid upstream id")
	}
	*i = id(s)
	return nil
}

// Raw maps accept grpc-gateway's lowerCamelCase and its snake_case variant.
type wire map[string]json.RawMessage

func (w *wire) UnmarshalJSON(b []byte) error {
	type rawWire map[string]json.RawMessage
	var parsed rawWire
	if err := json.Unmarshal(b, &parsed); err != nil {
		return err
	}
	if parsed == nil {
		return errors.New("invalid upstream object")
	}
	for key, value := range parsed {
		var target any
		switch key {
		case "id":
			target = new(id)
		case "name", "email", "displayName", "display_name", "createdAt", "created_at", "givenName", "given_name", "lastSeen", "last_seen", "expiry", "expiration", "updatedAt", "updated_at", "key", "policy":
			target = new(string)
		case "online", "reusable", "ephemeral", "used", "databaseConnectivity", "database_connectivity":
			target = new(bool)
		case "tags", "aclTags", "acl_tags", "ipAddresses", "ip_addresses", "availableRoutes", "available_routes", "approvedRoutes", "approved_routes":
			target = new([]string)
		case "user", "node", "preAuthKey", "pre_auth_key":
			if string(value) != "null" {
				target = new(wire)
			}
		case "users", "nodes", "preAuthKeys", "pre_auth_keys":
			target = new([]wire)
		}
		if target != nil {
			if err := json.Unmarshal(value, target); err != nil {
				return errors.New("invalid upstream field type")
			}
		}
	}
	*w = wire(parsed)
	return nil
}

func (w wire) get(names ...string) json.RawMessage {
	for _, n := range names {
		if v, ok := w[n]; ok {
			return v
		}
	}
	return nil
}
func (w wire) str(names ...string) string {
	var v string
	_ = json.Unmarshal(w.get(names...), &v)
	return v
}
func (w wire) identifier(names ...string) string {
	var v id
	_ = json.Unmarshal(w.get(names...), &v)
	return string(v)
}
func (w wire) boolean(names ...string) bool {
	var v bool
	_ = json.Unmarshal(w.get(names...), &v)
	return v
}
func (w wire) strings(names ...string) []string {
	v := []string{}
	_ = json.Unmarshal(w.get(names...), &v)
	if v == nil {
		v = []string{}
	}
	return v
}
func (w wire) object(names ...string) wire {
	var v wire
	_ = json.Unmarshal(w.get(names...), &v)
	return v
}
func (w wire) list(names ...string) []wire {
	var v []wire
	_ = json.Unmarshal(w.get(names...), &v)
	return v
}

type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	CreatedAt   string `json:"createdAt"`
}

func userDTO(w wire) User {
	return User{w.identifier("id"), w.str("name"), w.str("email"), w.str("displayName", "display_name"), w.str("createdAt", "created_at")}
}

type Device struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname"`
	UserID          string   `json:"userId"`
	UserName        string   `json:"userName"`
	IPs             []string `json:"ips"`
	Online          bool     `json:"online"`
	Expired         bool     `json:"expired"`
	LastSeen        string   `json:"lastSeen"`
	ExpiresAt       string   `json:"expiresAt"`
	Tags            []string `json:"tags"`
	AvailableRoutes []string `json:"availableRoutes"`
	ApprovedRoutes  []string `json:"approvedRoutes"`
}

func deviceDTO(w wire) Device {
	user := w.object("user")
	expiry := w.str("expiry")
	t, err := time.Parse(time.RFC3339Nano, expiry)
	return Device{w.identifier("id"), w.str("givenName", "given_name"), w.str("name"), user.identifier("id"), user.str("name"), w.strings("ipAddresses", "ip_addresses"), w.boolean("online"), err == nil && !t.IsZero() && t.Before(time.Now()), w.str("lastSeen", "last_seen"), expiry, w.strings("tags"), w.strings("availableRoutes", "available_routes"), w.strings("approvedRoutes", "approved_routes")}
}

type Key struct {
	ID        string   `json:"id"`
	UserID    string   `json:"userId"`
	Reusable  bool     `json:"reusable"`
	Ephemeral bool     `json:"ephemeral"`
	Used      bool     `json:"used"`
	ExpiresAt string   `json:"expiresAt"`
	CreatedAt string   `json:"createdAt"`
	Tags      []string `json:"tags"`
}

func keyDTO(w wire) Key {
	return Key{w.identifier("id"), w.object("user").identifier("id"), w.boolean("reusable"), w.boolean("ephemeral"), w.boolean("used"), w.str("expiration"), w.str("createdAt", "created_at"), w.strings("aclTags", "acl_tags")}
}

func validID(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func upstreamCode(err error) (int, string, string) {
	var e *upstreamError
	if !errors.As(err, &e) {
		return 502, "upstream_failed", "Headscale request failed"
	}
	if e.uncertain {
		return 502, "upstream_uncertain", "Headscale request failed; the operation may have completed. Inspect current state before retrying."
	}
	switch e.status {
	case 400, 422:
		return 400, "upstream_rejected", "Headscale rejected the request. Check names, ownership, and policy syntax/tests."
	case 404:
		return 404, "not_found", "Requested resource was not found in Headscale"
	case 409:
		return 409, "upstream_conflict", "Headscale rejected the operation because the resource is in use or conflicts with current state"
	default:
		return 502, "upstream_failed", "Headscale request failed"
	}
}

func (u *upstream) listKeys(ctx context.Context) ([]wire, error) {
	var out wire
	err := u.call(ctx, "GET", "/api/v1/preauthkey", nil, &out)
	keys := out.list("preAuthKeys", "pre_auth_keys")
	if err == nil {
		for _, key := range keys {
			if !validID(key.identifier("id")) {
				return nil, &upstreamError{}
			}
		}
	}
	return keys, err
}
func (u *upstream) policy(ctx context.Context) (wire, error) {
	var out wire
	err := u.call(ctx, "GET", "/api/v1/policy", nil, &out)
	return out, err
}
func newUpstream(c Config) (*upstream, error) {
	client, err := c.client()
	if err != nil {
		return nil, err
	}
	return &upstream{strings.TrimSuffix(c.HeadscaleURL, "/"), c.HeadscaleAPIKey, client}, nil
}
func requiredObject(out wire, field ...string) (wire, error) {
	w := out.object(field...)
	if !validID(w.identifier("id")) {
		return nil, &upstreamError{uncertain: true}
	}
	return w, nil
}
