package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/hujson"
)

// The gateway: members reach places only the server can, through the
// network's gateway device on the server.
//
// On the console's Gateway page an admin lists what goes through it, as
// entries of address ranges or host names (which this service looks up from
// the server, so private names get their private addresses), each for every
// member or for chosen people, and which DNS names the network asks a
// private resolver about. This service keeps those settings and everything
// that follows from them in step:
//   - routes.json, the routes the gateway device offers;
//   - the device's approved routes;
//   - one access rule (grant) per entry, and one for the private resolvers;
//   - dns.json, which the server applies to the coordinator's DNS settings
//     (deploy.py apply-gateway-dns), reporting back in dns-status.json.
//
// Only access rules this service wrote are ever taken out of the policy.

const (
	maxGatewayEntries      = 64
	maxGatewayDestinations = 64
	maxGatewayUsers        = 64
	maxGatewayDNS          = 32
	maxGatewayAddresses    = 16 // per host name
	gatewayLookupEvery     = 5 * time.Minute
	gatewayCheckEvery      = 15 * time.Second
)

// GatewayEntry is one line on the Gateway page.
type GatewayEntry struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Destinations []string `json:"destinations"` // address ranges or host names
	Users        []string `json:"users"`        // empty: every member
}

// GatewayDNS sends one domain's names to private resolvers.
type GatewayDNS struct {
	Domain    string   `json:"domain"`
	Resolvers []string `json:"resolvers"`
}

type GatewaySettings struct {
	Entries   []GatewayEntry `json:"entries"`
	DNS       []GatewayDNS   `json:"dns"`
	UpdatedAt string         `json:"updatedAt,omitempty"`
}

// gatewayFile is settings.json: the settings, and the access rules this
// service last added, so that it can take exactly those out again.
type gatewayFile struct {
	Settings GatewaySettings `json:"settings"`
	Applied  []grant         `json:"applied"`
}

type gatewayService struct {
	dir, tag string
	lookup   func(ctx context.Context, host string) ([]netip.Addr, error)
	now      func() time.Time

	mu         sync.Mutex
	file       gatewayFile
	addresses  map[string][]netip.Addr // host name -> addresses
	lookupErrs map[string]string
	lookedUp   time.Time
	problem    string
	cancel     context.CancelFunc
	done       chan struct{}
}

var systemActor = Actor{Type: "service", Subject: "gateway", Name: "Gateway settings", Role: roleAdmin}

func newGateway(c Config) (*gatewayService, error) {
	if c.GatewayTag == "" {
		return nil, nil
	}
	if err := os.MkdirAll(c.GatewayDir, 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(c.GatewayDir); err != nil || !info.IsDir() {
		return nil, errors.New("the gateway settings path must be a real directory")
	}
	g := &gatewayService{dir: c.GatewayDir, tag: c.GatewayTag, now: time.Now, addresses: map[string][]netip.Addr{}, lookupErrs: map[string]string{},
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}}
	raw, err := readPrivate(filepath.Join(g.dir, "settings.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		g.file = gatewayFile{Settings: GatewaySettings{Entries: []GatewayEntry{}, DNS: []GatewayDNS{}}, Applied: []grant{}}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &g.file); err != nil {
			return nil, errors.New("the gateway settings file is damaged; repair or remove settings.json")
		}
	}
	return g, nil
}

// start runs the background check: approvals and access every 15 seconds,
// host names every 5 minutes.
func (g *gatewayService) start(s *Server) {
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel, g.done = cancel, make(chan struct{})
	go func() {
		defer close(g.done)
		for {
			check, done := context.WithTimeout(ctx, time.Minute)
			_ = s.reconcileGateway(check, systemActor, false)
			done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(gatewayCheckEvery):
			}
		}
	}()
}

func (g *gatewayService) stop() {
	if g != nil && g.cancel != nil {
		g.cancel()
		<-g.done
	}
}

// --- validation -------------------------------------------------------------

var tailnetRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

func validDestinationPrefix(p netip.Prefix) error {
	if p.Bits() == 0 {
		return errors.New("would send all internet traffic through the gateway; use an exit node for that")
	}
	for _, own := range tailnetRanges {
		if own.Overlaps(p) {
			return errors.New("overlaps the network's own addresses")
		}
	}
	return nil
}

func validHostName(name string) bool {
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	_, err := netip.ParseAddr(name)
	return err != nil
}

func validResolver(text string) bool {
	a, err := netip.ParseAddr(text)
	return err == nil && a.String() == text && !a.IsLoopback() && !a.IsUnspecified() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && !tailnetRanges[0].Contains(a) && !tailnetRanges[1].Contains(a)
}

// cleanSettings checks the settings an admin sent and returns them in their
// stored form: trimmed, lower-case host names, canonical ranges, sorted
// people, and an ID for each new entry.
func cleanSettings(in GatewaySettings) (GatewaySettings, error) {
	out := GatewaySettings{Entries: []GatewayEntry{}, DNS: []GatewayDNS{}}
	if len(in.Entries) > maxGatewayEntries {
		return out, fmt.Errorf("at most %d entries", maxGatewayEntries)
	}
	ids := map[string]bool{}
	for i, e := range in.Entries {
		e.Label = strings.TrimSpace(e.Label)
		if !validText(e.Label, 1, 64) {
			return out, fmt.Errorf("entry %d needs a name of 1 to 64 characters", i+1)
		}
		if len(e.Destinations) == 0 || len(e.Destinations) > maxGatewayDestinations {
			return out, fmt.Errorf("%s: list 1 to %d destinations", e.Label, maxGatewayDestinations)
		}
		seen := map[string]bool{}
		dests := []string{}
		for _, d := range e.Destinations {
			d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			if strings.Contains(d, "/") {
				p, err := netip.ParsePrefix(d)
				if err != nil {
					return out, fmt.Errorf("%s: %q is not an address range such as 10.0.0.0/8", e.Label, d)
				}
				if p != p.Masked() {
					return out, fmt.Errorf("%s: %q should be written %s", e.Label, d, p.Masked())
				}
				if err := validDestinationPrefix(p); err != nil {
					return out, fmt.Errorf("%s: %s %v", e.Label, d, err)
				}
				d = p.String()
			} else if a, err := netip.ParseAddr(d); err == nil {
				p := netip.PrefixFrom(a, a.BitLen())
				if err := validDestinationPrefix(p); err != nil {
					return out, fmt.Errorf("%s: %s %v", e.Label, d, err)
				}
				d = p.String()
			} else if !validHostName(d) {
				return out, fmt.Errorf("%s: %q is neither an address range nor a host name such as db.example.com", e.Label, d)
			}
			if !seen[d] {
				seen[d] = true
				dests = append(dests, d)
			}
		}
		if len(e.Users) > maxGatewayUsers {
			return out, fmt.Errorf("%s: at most %d people", e.Label, maxGatewayUsers)
		}
		users := []string{}
		for _, u := range e.Users {
			u = strings.TrimSpace(u)
			if !validText(u, 1, 200) || strings.ContainsAny(u, " ,\"") {
				return out, fmt.Errorf("%s: %q is not a user name", e.Label, u)
			}
			if !slices.Contains(users, u) {
				users = append(users, u)
			}
		}
		sort.Strings(users)
		if e.ID == "" || ids[e.ID] {
			e.ID = randomToken()[:12]
		} else if !validText(e.ID, 1, 64) {
			return out, errors.New("an entry has an invalid ID")
		}
		ids[e.ID] = true
		out.Entries = append(out.Entries, GatewayEntry{ID: e.ID, Label: e.Label, Destinations: dests, Users: users})
	}
	if len(in.DNS) > maxGatewayDNS {
		return out, fmt.Errorf("at most %d DNS domains", maxGatewayDNS)
	}
	domains := map[string]bool{}
	for _, d := range in.DNS {
		d.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Domain), "."))
		if !validHostName(d.Domain) {
			return out, fmt.Errorf("%q is not a domain such as vault.azure.net", d.Domain)
		}
		if domains[d.Domain] {
			return out, fmt.Errorf("%s is listed twice", d.Domain)
		}
		domains[d.Domain] = true
		if len(d.Resolvers) == 0 || len(d.Resolvers) > 8 {
			return out, fmt.Errorf("%s: list 1 to 8 resolvers", d.Domain)
		}
		resolvers := []string{}
		for _, r := range d.Resolvers {
			r = strings.TrimSpace(r)
			if !validResolver(r) {
				return out, fmt.Errorf("%s: %q is not a resolver address such as 168.63.129.16", d.Domain, r)
			}
			if !slices.Contains(resolvers, r) {
				resolvers = append(resolvers, r)
			}
		}
		out.DNS = append(out.DNS, GatewayDNS{Domain: d.Domain, Resolvers: resolvers})
	}
	sort.Slice(out.DNS, func(i, j int) bool { return out.DNS[i].Domain < out.DNS[j].Domain })
	return out, nil
}

// --- what the settings mean ---------------------------------------------------

type gatewayPlan struct {
	routes []netip.Prefix            // everything the device offers
	byID   map[string][]netip.Prefix // each entry's routes
	grants []grant
	dns    map[string][]string
}

func userToken(name string) string {
	if strings.Contains(name, "@") {
		return name
	}
	return name + "@"
}

func (g *gatewayService) plan() gatewayPlan {
	p := gatewayPlan{byID: map[string][]netip.Prefix{}, dns: map[string][]string{}}
	all := map[netip.Prefix]bool{}
	for _, e := range g.file.Settings.Entries {
		var routes []netip.Prefix
		for _, d := range e.Destinations {
			if prefix, err := netip.ParsePrefix(d); err == nil {
				routes = append(routes, prefix)
				continue
			}
			for _, a := range g.addresses[d] {
				routes = append(routes, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		routes = sortedPrefixes(routes)
		p.byID[e.ID] = routes
		for _, r := range routes {
			all[r] = true
		}
		if len(routes) == 0 {
			continue
		}
		src := []string{"autogroup:member"}
		if len(e.Users) > 0 {
			src = nil
			for _, u := range e.Users {
				src = append(src, userToken(u))
			}
		}
		p.grants = append(p.grants, grant{Src: src, Dst: prefixStrings(routes), IP: []string{"*"}})
	}
	var resolvers []netip.Prefix
	for _, d := range g.file.Settings.DNS {
		p.dns[d.Domain] = d.Resolvers
		for _, r := range d.Resolvers {
			a := netip.MustParseAddr(r)
			resolvers = append(resolvers, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	if len(resolvers) > 0 {
		resolvers = sortedPrefixes(resolvers)
		for _, r := range resolvers {
			all[r] = true
		}
		// Members' devices ask the private resolvers through the gateway.
		p.grants = append(p.grants, grant{Src: []string{"autogroup:member"}, Dst: prefixStrings(resolvers), IP: []string{"udp:53", "tcp:53"}})
	}
	for r := range all {
		p.routes = append(p.routes, r)
	}
	p.routes = sortedPrefixes(p.routes)
	return p
}

func sortedPrefixes(in []netip.Prefix) []netip.Prefix {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(out)
}

func prefixStrings(in []netip.Prefix) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

// lookUp refreshes the host names' addresses. A name that cannot be looked
// up keeps its previous addresses, so a passing DNS failure removes nothing.
func (g *gatewayService) lookUp(ctx context.Context) {
	names := map[string]bool{}
	for _, e := range g.file.Settings.Entries {
		for _, d := range e.Destinations {
			if !strings.Contains(d, "/") {
				names[d] = true
			}
		}
	}
	for name := range g.addresses {
		if !names[name] {
			delete(g.addresses, name)
			delete(g.lookupErrs, name)
		}
	}
	for name := range names {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		addrs, err := g.lookup(lctx, name)
		cancel()
		var keep []netip.Addr
		for _, a := range addrs {
			a = a.Unmap()
			if a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() &&
				!tailnetRanges[0].Contains(a) && !tailnetRanges[1].Contains(a) && !slices.Contains(keep, a) {
				keep = append(keep, a)
			}
		}
		slices.SortFunc(keep, func(a, b netip.Addr) int { return a.Compare(b) })
		if len(keep) > maxGatewayAddresses {
			keep = keep[:maxGatewayAddresses]
		}
		switch {
		case err != nil:
			g.lookupErrs[name] = "could not be looked up"
		case len(keep) == 0:
			g.lookupErrs[name] = "has no usable address"
		default:
			delete(g.lookupErrs, name)
			g.addresses[name] = keep
		}
	}
	g.lookedUp = g.now()
}

// --- keeping everything in step -------------------------------------------------

// reconcileGateway brings the device's routes, their approval, the access
// rules and the DNS file in line with the settings. force also looks up host
// names again.
func (s *Server) reconcileGateway(ctx context.Context, actor Actor, force bool) error {
	g := s.gateway
	g.mu.Lock()
	defer g.mu.Unlock()
	if force || g.now().Sub(g.lookedUp) >= gatewayLookupEvery {
		g.lookUp(ctx)
	}
	p := g.plan()
	err := g.writeFiles(p)
	if err == nil && !sameGrants(p.grants, g.file.Applied) {
		if err = s.replaceGatewayGrants(ctx, actor, g.file.Applied, p.grants); err == nil {
			g.file.Applied = p.grants
			if p.grants == nil {
				g.file.Applied = []grant{}
			}
			err = g.save()
		}
	}
	if err == nil {
		err = s.approveGatewayRoutes(ctx, p.routes)
	}
	g.problem = ""
	if err != nil {
		g.problem = gatewayProblem(err)
	}
	return err
}

func gatewayProblem(err error) string {
	var ue *upstreamError
	if errors.As(err, &ue) {
		_, _, message := upstreamCode(err)
		return message
	}
	return err.Error()
}

func sameGrants(a, b []grant) bool {
	return reflect.DeepEqual(normalGrants(a), normalGrants(b))
}

func normalGrants(in []grant) []grant {
	if len(in) == 0 {
		return nil
	}
	return in
}

func (g *gatewayService) writeFiles(p gatewayPlan) error {
	routes, _ := json.MarshalIndent(map[string][]string{"routes": prefixStrings(p.routes)}, "", "  ")
	if err := writePrivateIfChanged(filepath.Join(g.dir, "routes.json"), append(routes, '\n')); err != nil {
		return fmt.Errorf("writing the gateway's routes: %w", err)
	}
	dns, _ := json.MarshalIndent(map[string]map[string][]string{"split": p.dns}, "", "  ")
	if err := writePrivateIfChanged(filepath.Join(g.dir, "dns.json"), append(dns, '\n')); err != nil {
		return fmt.Errorf("writing the DNS settings: %w", err)
	}
	return nil
}

func (g *gatewayService) save() error {
	raw, err := json.MarshalIndent(g.file, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateIfChanged(filepath.Join(g.dir, "settings.json"), append(raw, '\n'))
}

// replaceGatewayGrants takes the access rules this service added last time
// out of the policy and adds the current ones, keeping everything else and
// its comments. The coordinator checks the result before it is saved.
func (s *Server) replaceGatewayGrants(ctx context.Context, actor Actor, old, current []grant) error {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	policy, err := s.upstream.policy(ctx)
	if err != nil {
		return err
	}
	text, changed, err := withGrantsReplaced(policy.str("policy"), old, current)
	if err != nil || !changed {
		return err
	}
	if err := s.upstream.call(ctx, "POST", "/api/v1/policy/check", map[string]string{"policy": text}, nil); err != nil {
		return err
	}
	id := randomToken()
	if err := s.audit.append("policy.update", "gateway", "intent", id, actor); err != nil {
		return err
	}
	var out wire
	err = s.upstream.call(ctx, "PUT", "/api/v1/policy", map[string]string{"policy": text}, &out)
	if err == nil && out.str("policy") != text {
		err = &upstreamError{uncertain: true}
	}
	outcome := "success"
	if err != nil {
		outcome = "failed"
	}
	if auditErr := s.audit.append("policy.update", "gateway", outcome, id, actor); auditErr != nil && err == nil {
		err = auditErr
	}
	return err
}

// withGrantsReplaced removes each grant in old that the policy contains
// exactly, and adds each grant in current it lacks.
func withGrantsReplaced(policy string, old, current []grant) (string, bool, error) {
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
		Grants []json.RawMessage `json:"grants"`
	}
	if err := json.Unmarshal(plain.Pack(), &view); err != nil {
		return "", false, errors.New("the current policy has unexpected grants")
	}
	same := func(raw json.RawMessage, g grant) bool {
		var have, want any
		mine, _ := json.Marshal(g)
		return json.Unmarshal(raw, &have) == nil && json.Unmarshal(mine, &want) == nil && reflect.DeepEqual(have, want)
	}
	var ops []map[string]any
	kept := make([]bool, len(view.Grants))
	for i := range kept {
		kept[i] = true
	}
	for i := len(view.Grants) - 1; i >= 0; i-- {
		if slices.ContainsFunc(old, func(g grant) bool { return same(view.Grants[i], g) }) &&
			!slices.ContainsFunc(current, func(g grant) bool { return same(view.Grants[i], g) }) {
			ops = append(ops, map[string]any{"op": "remove", "path": fmt.Sprintf("/grants/%d", i)})
			kept[i] = false
		}
	}
	if view.Grants == nil && len(current) > 0 {
		ops = append(ops, map[string]any{"op": "add", "path": "/grants", "value": []any{}})
	}
	for _, g := range current {
		present := false
		for i, raw := range view.Grants {
			if kept[i] && same(raw, g) {
				present = true
			}
		}
		if !present {
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

// gatewayDevice finds the network's gateway device by its tag.
func (s *Server) gatewayDevice(ctx context.Context) (wire, error) {
	var out wire
	if err := s.upstream.call(ctx, "GET", "/api/v1/node", nil, &out); err != nil {
		return nil, err
	}
	for _, node := range out.list("nodes") {
		if slices.Contains(node.strings("tags"), s.gateway.tag) && validID(node.identifier("id")) {
			return node, nil
		}
	}
	return nil, nil
}

// approveGatewayRoutes approves, of the routes the device offers, exactly
// the ones the settings ask for.
func (s *Server) approveGatewayRoutes(ctx context.Context, wanted []netip.Prefix) error {
	node, err := s.gatewayDevice(ctx)
	if err != nil || node == nil {
		return err
	}
	offered := map[netip.Prefix]bool{}
	for _, r := range node.strings("availableRoutes", "available_routes") {
		if p, err := netip.ParsePrefix(r); err == nil {
			offered[p.Masked()] = true
		}
	}
	approve := []string{}
	for _, p := range wanted {
		if offered[p] {
			approve = append(approve, p.String())
		}
	}
	var have []netip.Prefix
	for _, r := range node.strings("approvedRoutes", "approved_routes") {
		if p, err := netip.ParsePrefix(r); err == nil {
			have = append(have, p.Masked())
		}
	}
	if slices.Equal(prefixStrings(sortedPrefixes(have)), approve) {
		return nil
	}
	return s.upstream.call(ctx, "POST", "/api/v1/node/"+node.identifier("id")+"/approve_routes", map[string]any{"routes": approve}, nil)
}

// --- the console's view -------------------------------------------------------------

type gatewayRoute struct {
	Route    string   `json:"route"`
	Entries  []string `json:"entries"`
	Offered  bool     `json:"offered"`
	Approved bool     `json:"approved"`
}

type gatewayHost struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Problem   string   `json:"problem,omitempty"`
}

type gatewayDNSStatus struct {
	Applied   bool   `json:"applied"`
	AppliedAt string `json:"appliedAt,omitempty"`
	Problem   string `json:"problem,omitempty"`
}

func (s *Server) gatewayView(ctx context.Context) map[string]any {
	g := s.gateway
	node, nodeErr := s.gatewayDevice(ctx)
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.plan()
	offered, approved := map[string]bool{}, map[string]bool{}
	var device *Device
	if node != nil {
		d := deviceDTO(node)
		device = &d
		for _, r := range d.AvailableRoutes {
			offered[r] = true
		}
		for _, r := range d.ApprovedRoutes {
			approved[r] = true
		}
	}
	routes := []gatewayRoute{}
	for _, r := range p.routes {
		entries := []string{}
		for _, e := range g.file.Settings.Entries {
			if slices.Contains(p.byID[e.ID], r) {
				entries = append(entries, e.ID)
			}
		}
		routes = append(routes, gatewayRoute{Route: r.String(), Entries: entries, Offered: offered[r.String()], Approved: approved[r.String()]})
	}
	hosts := []gatewayHost{}
	for _, e := range g.file.Settings.Entries {
		for _, d := range e.Destinations {
			if strings.Contains(d, "/") || slices.ContainsFunc(hosts, func(h gatewayHost) bool { return h.Name == d }) {
				continue
			}
			addrs := []string{}
			for _, a := range g.addresses[d] {
				addrs = append(addrs, a.String())
			}
			hosts = append(hosts, gatewayHost{Name: d, Addresses: addrs, Problem: g.lookupErrs[d]})
		}
	}
	problem := g.problem
	if nodeErr != nil && problem == "" {
		problem = gatewayProblem(nodeErr)
	}
	settings, _ := json.Marshal(g.file.Settings)
	sum := sha256.Sum256(settings)
	return map[string]any{
		"enabled":  true,
		"settings": g.file.Settings,
		"revision": hex.EncodeToString(sum[:]),
		"status": map[string]any{
			"device": device, "routes": routes, "hosts": hosts, "dns": g.dnsStatus(p.dns), "problem": problem,
		},
	}
}

// dnsStatus reads what the server last did with dns.json.
func (g *gatewayService) dnsStatus(want map[string][]string) gatewayDNSStatus {
	raw, err := readPrivate(filepath.Join(g.dir, "dns-status.json"))
	var status struct {
		Split     map[string][]string `json:"split"`
		AppliedAt string              `json:"appliedAt"`
		Error     string              `json:"error"`
	}
	if err != nil || json.Unmarshal(raw, &status) != nil {
		return gatewayDNSStatus{Applied: len(want) == 0}
	}
	same := reflect.DeepEqual(status.Split, want) || (len(status.Split) == 0 && len(want) == 0)
	return gatewayDNSStatus{Applied: same && status.Error == "", AppliedAt: status.AppliedAt, Problem: status.Error}
}

func (s *Server) getGateway(w http.ResponseWriter, r *http.Request) {
	if s.gateway == nil {
		respond(w, 200, map[string]any{"enabled": false})
		return
	}
	respond(w, 200, s.gatewayView(r.Context()))
}

func (s *Server) setGateway(w http.ResponseWriter, r *http.Request) {
	if s.gateway == nil {
		fail(w, 404, "not_found", "This network has no gateway; turn it on with `covee gateway <network>`")
		return
	}
	var in struct {
		Entries  []GatewayEntry `json:"entries"`
		DNS      []GatewayDNS   `json:"dns"`
		Revision string         `json:"revision"`
	}
	if !decode(w, r, &in) {
		return
	}
	settings, err := cleanSettings(GatewaySettings{Entries: in.Entries, DNS: in.DNS})
	if err != nil {
		fail(w, 400, "invalid_input", err.Error())
		return
	}
	if unknown, err := s.unknownUsers(r.Context(), settings); err != nil {
		upstreamFail(w, err)
		return
	} else if unknown != "" {
		fail(w, 400, "invalid_input", unknown+" is not a user of this network")
		return
	}
	g := s.gateway
	g.mu.Lock()
	current, _ := json.Marshal(g.file.Settings)
	sum := sha256.Sum256(current)
	if hex.EncodeToString(sum[:]) != in.Revision {
		g.mu.Unlock()
		fail(w, 409, "revision_conflict", "The gateway settings changed since they were loaded; reload and try again")
		return
	}
	previous := g.file.Settings
	settings.UpdatedAt = g.now().UTC().Format(time.RFC3339)
	g.file.Settings = settings
	if err := g.save(); err != nil {
		g.file.Settings = previous
		g.mu.Unlock()
		fail(w, 503, "storage_failed", "The gateway settings could not be saved")
		return
	}
	g.mu.Unlock()
	actor := requestSession(r).actor
	s.mutate(w, r, "gateway.update", "gateway", func() (any, error) {
		err := s.reconcileGateway(r.Context(), actor, true)
		return s.gatewayView(r.Context()), err
	}, 200)
}

// unknownUsers names the first person in the settings who is not a user of
// the network, so that a mistyped name never reaches the policy.
func (s *Server) unknownUsers(ctx context.Context, settings GatewaySettings) (string, error) {
	var want []string
	for _, e := range settings.Entries {
		want = append(want, e.Users...)
	}
	if len(want) == 0 {
		return "", nil
	}
	var out wire
	if err := s.upstream.call(ctx, "GET", "/api/v1/user", nil, &out); err != nil {
		return "", err
	}
	known := map[string]bool{}
	for _, u := range out.list("users") {
		known[u.str("name")] = true
		if e := u.str("email"); e != "" {
			known[e] = true
		}
	}
	for _, u := range want {
		if !known[u] {
			return u, nil
		}
	}
	return "", nil
}

// --- small file helpers -------------------------------------------------------------

func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New(filepath.Base(path) + " must be a small regular file")
	}
	return os.ReadFile(path)
}

// writePrivateIfChanged replaces path atomically, readable only by this
// account, when its content differs.
func writePrivateIfChanged(path string, data []byte) error {
	if old, err := readPrivate(path); err == nil && string(old) == string(data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
