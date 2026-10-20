package management

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	parts := strings.Split(path, "/")
	switch {
	case path == "session" && r.Method == "GET":
		respond(w, 200, sessionResponse(requestSession(r)))
	case path == "logout" && r.Method == "POST":
		if c, err := r.Cookie(s.cookieName()); err == nil {
			s.sessionMu.Lock()
			delete(s.sessions, c.Value)
			s.sessionMu.Unlock()
		}
		s.cookie(w, "", time.Unix(1, 0), -1)
		respond(w, 200, map[string]bool{"authenticated": false})
	case path == "readyz" && r.Method == "GET":
		var out wire
		if err := s.upstream.call(r.Context(), "GET", "/api/v1/health", nil, &out); err != nil {
			upstreamFail(w, err)
			return
		}
		if !out.boolean("databaseConnectivity", "database_connectivity") {
			fail(w, 503, "upstream_not_ready", "Headscale database is not ready")
			return
		}
		respond(w, 200, map[string]string{"status": "ready"})
	case path == "audit" && r.Method == "GET":
		respond(w, 200, map[string]any{"events": s.audit.latest()})
	case path == "users" && r.Method == "GET":
		s.users(w, r)
	case path == "users" && r.Method == "POST":
		s.createUser(w, r)
	case len(parts) == 2 && parts[0] == "users" && validID(parts[1]) && r.Method == "DELETE":
		s.mutate(w, r, "user.delete", parts[1], func() (any, error) {
			return map[string]bool{"deleted": true}, s.upstream.call(r.Context(), "DELETE", "/api/v1/user/"+parts[1], nil, nil)
		}, 200)
	case path == "devices" && r.Method == "GET":
		s.devices(w, r)
	case len(parts) == 2 && parts[0] == "devices" && validID(parts[1]) && r.Method == "PATCH":
		s.renameDevice(w, r, parts[1])
	case len(parts) == 2 && parts[0] == "devices" && validID(parts[1]) && r.Method == "DELETE":
		s.mutate(w, r, "device.delete", parts[1], func() (any, error) {
			return map[string]bool{"deleted": true}, s.upstream.call(r.Context(), "DELETE", "/api/v1/node/"+parts[1], nil, nil)
		}, 200)
	case len(parts) == 3 && parts[0] == "devices" && validID(parts[1]) && parts[2] == "expire" && r.Method == "POST":
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		s.mutate(w, r, "device.expire", parts[1], func() (any, error) {
			var out wire
			err := s.upstream.call(r.Context(), "POST", "/api/v1/node/"+parts[1]+"/expire", nil, &out)
			if err != nil {
				return nil, err
			}
			node, err := requiredObject(out, "node")
			return map[string]any{"device": deviceDTO(node)}, err
		}, 200)
	case path == "network" && r.Method == "GET":
		s.network(w)
	case len(parts) == 3 && parts[0] == "devices" && validID(parts[1]) && parts[2] == "routes" && r.Method == "POST":
		s.approveRoutes(w, r, parts[1])
	case path == "keys" && r.Method == "GET":
		s.keys(w, r)
	case path == "keys" && r.Method == "POST":
		s.createKey(w, r)
	case len(parts) == 3 && parts[0] == "keys" && validID(parts[1]) && parts[2] == "expire" && r.Method == "POST":
		s.expireKey(w, r, parts[1])
	case path == "policy" && r.Method == "GET":
		out, err := s.upstream.policy(r.Context())
		if err != nil {
			upstreamFail(w, err)
			return
		}
		respond(w, 200, policyDTO(out))
	case path == "policy" && r.Method == "PUT":
		s.setPolicy(w, r)
	case path == "gateway" && r.Method == "GET":
		s.getGateway(w, r)
	case path == "gateway" && r.Method == "PUT":
		s.setGateway(w, r)
	default:
		fail(w, 404, "not_found", "API resource or method was not found")
	}
}
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	var out wire
	if err := s.upstream.call(r.Context(), "GET", "/api/v1/user", nil, &out); err != nil {
		upstreamFail(w, err)
		return
	}
	users := []User{}
	for _, u := range out.list("users") {
		if !validID(u.identifier("id")) {
			upstreamFail(w, &upstreamError{})
			return
		}
		users = append(users, userDTO(u))
	}
	respond(w, 200, map[string]any{"users": users})
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !validText(in.Name, 1, 100) || !validText(in.Email, 0, 320) || !validText(in.DisplayName, 0, 200) {
		fail(w, 400, "invalid_input", "A name of 1–100 characters is required; email and display name must fit their limits")
		return
	}
	s.mutate(w, r, "user.create", "new", func() (any, error) {
		var out wire
		err := s.upstream.call(r.Context(), "POST", "/api/v1/user", map[string]any{"name": in.Name, "email": in.Email, "displayName": in.DisplayName}, &out)
		if err != nil {
			return nil, err
		}
		u, err := requiredObject(out, "user")
		return map[string]any{"user": userDTO(u)}, err
	}, 201)
}
func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	var out wire
	if err := s.upstream.call(r.Context(), "GET", "/api/v1/node", nil, &out); err != nil {
		upstreamFail(w, err)
		return
	}
	nodes := []Device{}
	for _, n := range out.list("nodes") {
		if !validID(n.identifier("id")) {
			upstreamFail(w, &upstreamError{})
			return
		}
		nodes = append(nodes, deviceDTO(n))
	}
	respond(w, 200, map[string]any{"devices": nodes})
}
func (s *Server) renameDevice(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !validText(in.Name, 1, 100) || strings.ContainsAny(in.Name, "/\\?#%") {
		fail(w, 400, "invalid_input", "Device name must contain 1–100 characters without URL separators")
		return
	}
	s.mutate(w, r, "device.rename", id, func() (any, error) {
		var out wire
		err := s.upstream.call(r.Context(), "POST", "/api/v1/node/"+id+"/rename/"+url.PathEscape(in.Name), nil, &out)
		if err != nil {
			return nil, err
		}
		node, err := requiredObject(out, "node")
		return map[string]any{"device": deviceDTO(node)}, err
	}, 200)
}
func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userId")
	// owner=tags lists the keys of tag-owned devices, such as servers, which have no user.
	tagged := r.URL.Query().Get("owner") == "tags"
	if !tagged && !validID(userID) {
		fail(w, 400, "invalid_input", "A valid userId is required")
		return
	}
	keys, err := s.upstream.listKeys(r.Context())
	if err != nil {
		upstreamFail(w, err)
		return
	}
	out := []Key{}
	for _, key := range keys {
		dto := keyDTO(key)
		if (tagged && dto.UserID == "" && len(dto.Tags) > 0) || (!tagged && dto.UserID == userID) {
			out = append(out, dto)
		}
	}
	respond(w, 200, map[string]any{"keys": out})
}
func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID      string   `json:"userId"`
		ExpiryHours int      `json:"expiryHours"`
		Reusable    bool     `json:"reusable"`
		Ephemeral   bool     `json:"ephemeral"`
		Tags        []string `json:"tags"`
		// AllowMembers adds the policy rule letting every member reach these tags.
		AllowMembers bool `json:"allowMembers"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.ExpiryHours == 0 {
		in.ExpiryHours = 24
	}
	// A key without a user makes tag-owned devices (servers), which never expire.
	tagOwned := in.UserID == ""
	if (!tagOwned && !validID(in.UserID)) || (tagOwned && len(in.Tags) == 0) || in.ExpiryHours < 1 || in.ExpiryHours > 2160 || !validTags(in.Tags) || (in.AllowMembers && len(in.Tags) == 0) {
		fail(w, 400, "invalid_input", "userId or at least one tag, expiryHours (1–2160), or tags are invalid")
		return
	}
	target := in.UserID
	if tagOwned {
		target = strings.Join(in.Tags, ",")
	}
	body := map[string]any{"reusable": in.Reusable, "ephemeral": in.Ephemeral, "expiration": time.Now().UTC().Add(time.Duration(in.ExpiryHours) * time.Hour).Format(time.RFC3339Nano), "aclTags": in.Tags}
	if !tagOwned {
		body["user"] = in.UserID
	}
	s.mutate(w, r, "key.create", target, func() (any, error) {
		// A tag must have an owner entry before a device can join with it.
		if len(in.Tags) > 0 {
			var grants []grant
			if in.AllowMembers {
				grants = []grant{{Src: []string{"autogroup:member"}, Dst: in.Tags, IP: []string{"*"}}}
			}
			if err := s.ensureAccess(r, in.Tags, grants); err != nil {
				return nil, err
			}
		}
		var out wire
		err := s.upstream.call(r.Context(), "POST", "/api/v1/preauthkey", body, &out)
		if err != nil {
			return nil, err
		}
		key, err := requiredObject(out, "preAuthKey", "pre_auth_key")
		if err != nil {
			return nil, err
		}
		if key.str("key") == "" {
			return nil, &upstreamError{uncertain: true}
		}
		return map[string]any{"key": keyDTO(key), "secret": key.str("key"), "controlURL": s.config.controlURL()}, nil
	}, 201)
}
func (s *Server) expireKey(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		UserID string `json:"userId"`
		Tagged bool   `json:"tagged"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !in.Tagged && !validID(in.UserID) {
		fail(w, 400, "invalid_input", "A valid userId, or tagged, is required")
		return
	}
	keys, err := s.upstream.listKeys(r.Context())
	if err != nil {
		upstreamFail(w, err)
		return
	}
	found := false
	for _, key := range keys {
		dto := keyDTO(key)
		if dto.ID == id && ((in.Tagged && dto.UserID == "") || (!in.Tagged && dto.UserID == in.UserID)) {
			found = true
			break
		}
	}
	if !found {
		fail(w, 404, "not_found", "Enrollment key was not found for that user")
		return
	}
	s.mutate(w, r, "key.expire", id, func() (any, error) {
		return map[string]bool{"expired": true}, s.upstream.call(r.Context(), "POST", "/api/v1/preauthkey/expire", map[string]string{"id": id}, nil)
	}, 200)
}
func policyDTO(out wire) map[string]any {
	p := out.str("policy")
	return map[string]any{"policy": p, "revision": revision(p), "updatedAt": out.str("updatedAt", "updated_at")}
}
func (s *Server) setPolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Policy   string `json:"policy"`
		Revision string `json:"revision"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Policy) == 0 || len(in.Policy) > 768<<10 || len(in.Revision) != 64 {
		fail(w, 400, "invalid_input", "Policy and its current revision are required")
		return
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	current, err := s.upstream.policy(r.Context())
	if err != nil {
		upstreamFail(w, err)
		return
	}
	if !sameSecret(in.Revision, revision(current.str("policy"))) {
		fail(w, 409, "revision_conflict", "Policy changed since it was loaded. Reload before saving.")
		return
	}
	// The sandbox validates HuJSON and tests without touching the live manager.
	if err := s.upstream.call(r.Context(), "POST", "/api/v1/policy/check", map[string]string{"policy": in.Policy}, nil); err != nil {
		upstreamFail(w, err)
		return
	}
	s.mutate(w, r, "policy.update", "policy", func() (any, error) {
		var out wire
		err := s.upstream.call(r.Context(), "PUT", "/api/v1/policy", map[string]string{"policy": in.Policy}, &out)
		if err == nil && out.str("policy") != in.Policy {
			err = &upstreamError{uncertain: true}
		}
		return policyDTO(out), err
	}, 200)
}
func validText(s string, min, max int) bool {
	return len(s) >= min && len(s) <= max && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func validTags(tags []string) bool {
	if len(tags) > 32 {
		return false
	}
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") || !validText(tag, 5, 100) {
			return false
		}
		for _, c := range tag[4:] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
