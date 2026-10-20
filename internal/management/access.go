package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/tailscale/hujson"
)

// Adding servers, exit nodes and local networks. The console prepares keys
// and commands for machines that run the standard Tailscale client, approves
// the routes those machines offer, and can add the matching access rules to
// the policy. Edits keep the policy's comments; the layout is normalized.

// grant is one entry of the policy's grants list.
type grant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
}

// Exit traffic is granted to the internet, not to the exit node itself.
const internetDestination = "autogroup:internet"

// controlURL is the coordinator's public origin for join commands: the
// configured value, or the origin of the network's own sign-in issuer.
func (c Config) controlURL() string {
	if c.ControlURL != "" {
		return c.ControlURL
	}
	u, err := url.Parse(c.OIDCIssuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "/identity" {
		return ""
	}
	return "https://" + u.Host
}

func (s *Server) network(w http.ResponseWriter) {
	respond(w, 200, map[string]any{"controlURL": s.config.controlURL()})
}

// isExitRoute reports whether prefix is one of the two default routes an exit node offers.
func isExitRoute(prefix netip.Prefix) bool {
	return prefix.Bits() == 0
}

// ensureAccess adds tag owners and grants that are missing from the policy,
// checks the result with Headscale and saves it. It records its own audit
// entries. Nothing is written when everything is already present.
func (s *Server) ensureAccess(r *http.Request, tags []string, grants []grant) error {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	ctx := r.Context()
	current, err := s.upstream.policy(ctx)
	if err != nil {
		return err
	}
	text, changed, err := withAccess(current.str("policy"), tags, grants)
	if err != nil || !changed {
		return err
	}
	if err := s.upstream.call(ctx, "POST", "/api/v1/policy/check", map[string]string{"policy": text}, nil); err != nil {
		return err
	}
	return s.auditedPolicyWrite(ctx, r, text)
}

// auditedPolicyWrite saves the policy between an intent and an outcome audit entry.
func (s *Server) auditedPolicyWrite(ctx context.Context, r *http.Request, text string) error {
	id := randomToken()
	actor := requestSession(r).actor
	if err := s.audit.append("policy.update", "policy", "intent", id, actor); err != nil {
		return err
	}
	var out wire
	err := s.upstream.call(ctx, "PUT", "/api/v1/policy", map[string]string{"policy": text}, &out)
	if err == nil && out.str("policy") != text {
		err = &upstreamError{uncertain: true}
	}
	outcome := "success"
	if err != nil {
		outcome = "failed"
	}
	if auditErr := s.audit.append("policy.update", "policy", outcome, id, actor); auditErr != nil && err == nil {
		err = auditErr
	}
	return err
}

// withAccess returns policy with the given tag owners and grants added where
// missing. It edits the HuJSON document in place, so comments survive.
func withAccess(policy string, tags []string, grants []grant) (string, bool, error) {
	if strings.TrimSpace(policy) == "" {
		policy = "{}"
	}
	doc, err := hujson.Parse([]byte(policy))
	if err != nil {
		return "", false, errors.New("the current policy could not be read")
	}
	plain := doc.Clone()
	plain.Standardize()
	var view struct {
		TagOwners map[string]json.RawMessage `json:"tagOwners"`
		Grants    []grant                    `json:"grants"`
	}
	if err := json.Unmarshal(plain.Pack(), &view); err != nil {
		return "", false, errors.New("the current policy has unexpected tagOwners or grants")
	}
	var ops []map[string]any
	if view.TagOwners == nil && len(tags) > 0 {
		ops = append(ops, map[string]any{"op": "add", "path": "/tagOwners", "value": map[string]any{}})
	}
	for _, tag := range tags {
		if _, ok := view.TagOwners[tag]; !ok {
			ops = append(ops, map[string]any{"op": "add", "path": "/tagOwners/" + pointerEscape(tag), "value": []string{}})
		}
	}
	if view.Grants == nil && len(grants) > 0 {
		ops = append(ops, map[string]any{"op": "add", "path": "/grants", "value": []any{}})
	}
	for _, g := range grants {
		if !slices.ContainsFunc(view.Grants, func(have grant) bool { return sameGrant(have, g) }) {
			ops = append(ops, map[string]any{"op": "add", "path": "/grants/-", "value": g})
		}
	}
	if len(ops) == 0 {
		return policy, false, nil
	}
	patch, err := json.Marshal(ops)
	if err != nil {
		return "", false, err
	}
	if err := doc.Patch(patch); err != nil {
		return "", false, errors.New("the policy could not be updated")
	}
	doc.Format()
	return doc.String(), true, nil
}

func sameGrant(a, b grant) bool {
	return slices.Equal(a.Src, b.Src) && slices.Equal(a.Dst, b.Dst) && slices.Equal(a.IP, b.IP)
}

// pointerEscape escapes a JSON Pointer reference token.
func pointerEscape(s string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(s)
}

// approveRoutes sets the routes a device may serve, which must all be ones it
// offers, and optionally lets every member use them.
func (s *Server) approveRoutes(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		Routes       []string `json:"routes"`
		AllowMembers bool     `json:"allowMembers"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Routes) > 64 {
		fail(w, 400, "invalid_input", "At most 64 routes can be approved")
		return
	}
	var node wire
	if err := s.upstream.call(r.Context(), "GET", "/api/v1/node/"+id, nil, &node); err != nil {
		upstreamFail(w, err)
		return
	}
	device, err := requiredObject(node, "node")
	if err != nil {
		upstreamFail(w, err)
		return
	}
	offered := map[netip.Prefix]bool{}
	for _, route := range device.strings("availableRoutes", "available_routes") {
		if prefix, err := netip.ParsePrefix(route); err == nil {
			offered[prefix.Masked()] = true
		}
	}
	routes := []string{}
	exit, subnets := false, []string{}
	for _, route := range in.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || prefix != prefix.Masked() || !offered[prefix] {
			fail(w, 400, "invalid_input", "Only routes the device offers can be approved: "+route)
			return
		}
		routes = append(routes, prefix.String())
		if isExitRoute(prefix) {
			exit = true
		} else if !slices.Contains(subnets, prefix.String()) {
			subnets = append(subnets, prefix.String())
		}
	}
	s.mutate(w, r, "device.routes", id, func() (any, error) {
		if in.AllowMembers {
			var grants []grant
			if exit {
				grants = append(grants, grant{Src: []string{"autogroup:member"}, Dst: []string{internetDestination}, IP: []string{"*"}})
			}
			if len(subnets) > 0 {
				grants = append(grants, grant{Src: []string{"autogroup:member"}, Dst: subnets, IP: []string{"*"}})
			}
			if err := s.ensureAccess(r, nil, grants); err != nil {
				return nil, err
			}
		}
		var out wire
		if err := s.upstream.call(r.Context(), "POST", "/api/v1/node/"+id+"/approve_routes", map[string]any{"routes": routes}, &out); err != nil {
			return nil, err
		}
		approved, err := requiredObject(out, "node")
		return map[string]any{"device": deviceDTO(approved)}, err
	}, 200)
}
