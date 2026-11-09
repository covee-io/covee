package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Hosts: addresses such as https://grafana.<mesh domain> that devices in the
// network open, each passed on to a device and port by the hosts device on
// the server.
//
// The console's Hosts page lists them and changes them, but this service
// changes nothing itself. deploy.py set-hosts is the one place that checks a
// list of hosts, resolves its devices and puts the access rules, the hosts
// device's list and the DNS names in step, undoing everything if a step fails.
// So this service writes the wanted list to request.json; on the server a path
// unit runs deploy.py apply-console-hosts, which answers in status.json.
//
// A request carries the revision of the list it was made from, checked on the
// server under the runtime's operation lock, and an expiry, so one that waited
// (the path unit was off, say) can never apply later as a surprise.

const (
	maxHosts    = 256
	maxHostPath = 1024
	// Below the console's 30-second write timeout and the gateway's 30-second
	// wait for a response, so a slow server gets an answer that says so.
	hostsApplyWait   = 25 * time.Second
	hostsRequestLife = 2 * time.Minute
	hostsPollEvery   = 150 * time.Millisecond
	// The path unit does not watch while its service runs, so a request written
	// just as the service ends could go unnoticed. Writing it again is harmless:
	// the server answers each id once.
	hostsNudgeEvery = 3 * time.Second
	hostsTag        = "tag:covee-hosts"
	coveeTagPrefix  = "tag:covee-"
)

var hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// HostInput is one host as the console sends it, and as set-hosts takes it.
type HostInput struct {
	Name   string `json:"name"`
	Device string `json:"device"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	Scheme string `json:"scheme"`
	Verify bool   `json:"verify"`
}

// hostEntry is one line of hosts.json, as deploy.py writes it.
type hostEntry struct {
	Name   string `json:"name"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	Scheme string `json:"scheme"`
	Verify *bool  `json:"verify"`
	Device string `json:"device"`
	NodeID string `json:"node_id"`
}

// HostRow is one line on the Hosts page.
type HostRow struct {
	HostInput
	URL string `json:"url"`
	// Status is online, offline, renamed or missing, or empty when the
	// coordinator could not be asked.
	Status string `json:"status"`
}

// HostDevice is a device the page offers as a target.
type HostDevice struct {
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

type hostsService struct {
	dir  string        // where request.json and status.json are
	file string        // hosts.json, read only
	turn chan struct{} // holds one change at a time
	now  func() time.Time
	wait time.Duration
}

// hostsList is what the server holds: the hosts, the digest of their file
// (the revision a change is made from), and the ending of device names.
type hostsList struct {
	entries  []hostEntry
	revision string
	domain   string
}

func newHosts(c Config) (*hostsService, error) {
	if c.HostsDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(c.HostsDir, 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(c.HostsDir); err != nil || !info.IsDir() {
		return nil, errors.New("the hosts request path must be a real directory")
	}
	return &hostsService{dir: c.HostsDir, file: c.HostsFile, turn: make(chan struct{}, 1), now: time.Now, wait: hostsApplyWait}, nil
}

// read returns what the hosts device serves now, with domain.json, which the
// server writes beside hosts.json. The revision is the digest of hosts.json,
// which the server compares when it applies a change.
func (h *hostsService) read() (hostsList, error) {
	raw, err := readPrivate(h.file)
	if errors.Is(err, os.ErrNotExist) {
		raw, err = nil, nil
	}
	if err != nil {
		return hostsList{}, err
	}
	sum := sha256.Sum256(raw)
	file := struct {
		Hosts []hostEntry `json:"hosts"`
	}{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &file); err != nil {
			return hostsList{}, errors.New("the list of hosts on the server is unreadable")
		}
	}
	rawDomain, err := readPrivate(filepath.Join(filepath.Dir(h.file), "domain.json"))
	if err != nil {
		return hostsList{}, err
	}
	var settings struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(rawDomain, &settings); err != nil || settings.Domain == "" {
		return hostsList{}, errors.New("the network's device ending on the server is unreadable")
	}
	return hostsList{file.Hosts, hex.EncodeToString(sum[:]), settings.Domain}, nil
}

// label is the host's name without the network's ending.
func (l hostsList) label(full string) string {
	return strings.TrimSuffix(full, "."+l.domain)
}

func (e hostEntry) input(label string) HostInput {
	scheme := e.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return HostInput{Name: label, Device: e.Device, Port: e.Port, Path: e.Path, Scheme: scheme, Verify: e.Verify == nil || *e.Verify}
}

// cleanHosts refuses what can never be a list of hosts. The server's checks
// decide the rest, such as reserved names and whether the devices exist.
func cleanHosts(in []HostInput) ([]HostInput, error) {
	if len(in) > maxHosts {
		return nil, fmt.Errorf("a network can have at most %d hosts", maxHosts)
	}
	out, seen := []HostInput{}, map[string]bool{}
	for _, host := range in {
		if !hostLabelRE.MatchString(host.Name) {
			return nil, fmt.Errorf("%q cannot be a host's name; use lowercase letters, digits and dashes, such as grafana", host.Name)
		}
		if seen[host.Name] {
			return nil, fmt.Errorf("there are two hosts named %s", host.Name)
		}
		seen[host.Name] = true
		if !hostLabelRE.MatchString(host.Device) {
			return nil, fmt.Errorf("choose the device for %s", host.Name)
		}
		if host.Port < 1 || host.Port > 65535 {
			return nil, fmt.Errorf("the port of %s must be a number from 1 to 65535", host.Name)
		}
		if len(host.Path) > maxHostPath {
			return nil, fmt.Errorf("the path of %s is longer than %d characters", host.Name, maxHostPath)
		}
		if host.Scheme != "http" && host.Scheme != "https" {
			return nil, fmt.Errorf("the service of %s must use http or https", host.Name)
		}
		if host.Scheme == "http" && !host.Verify {
			host.Verify = true
		}
		out = append(out, host)
	}
	return out, nil
}

// changedHosts names what a change touches, for the activity log.
func changedHosts(old, wanted []HostInput) string {
	before := map[string]HostInput{}
	for _, host := range old {
		before[host.Name] = host
	}
	changed := []string{}
	for _, host := range wanted {
		if previous, ok := before[host.Name]; !ok || previous != host {
			changed = append(changed, host.Name)
		}
		delete(before, host.Name)
	}
	for name := range before {
		changed = append(changed, name)
	}
	slices.Sort(changed)
	if len(changed) == 0 || len(changed) > 8 {
		return "hosts"
	}
	return "hosts:" + strings.Join(changed, ",")
}

type hostsRequest struct {
	ID       string      `json:"id"`
	Revision string      `json:"revision"`
	Expires  int64       `json:"expires"`
	Hosts    []HostInput `json:"hosts"`
}

type hostsStatus struct {
	ID       string   `json:"id"`
	OK       bool     `json:"ok"`
	Conflict bool     `json:"conflict"`
	Message  string   `json:"message"`
	Warnings []string `json:"warnings"`
}

var errHostsConflict = &requestError{status: 409, code: "revision_conflict", message: "The hosts changed since this page loaded. Refresh and try again."}

// apply asks the server for the list and waits for its answer. The answer's
// warnings are for the person who made the change. The whole wait is bounded,
// and nothing is written for someone who has already stopped waiting.
func (h *hostsService) apply(ctx context.Context, hosts []HostInput, revision string) ([]string, error) {
	wait, cancel := context.WithTimeout(ctx, h.wait)
	defer cancel()
	select {
	case h.turn <- struct{}{}:
		defer func() { <-h.turn }()
	case <-wait.Done():
		return nil, &requestError{status: 503, code: "hosts_busy", message: "Another change to the hosts is still going on, so this one was not made. Try again in a moment."}
	}
	if err := wait.Err(); err != nil {
		return nil, &requestError{status: 503, code: "hosts_busy", message: "Another change to the hosts is still going on, so this one was not made. Try again in a moment."}
	}
	if list, err := h.read(); err != nil {
		return nil, &requestError{status: 503, code: "hosts_unreadable", message: "The list of hosts on the server could not be read."}
	} else if list.revision != revision {
		return nil, errHostsConflict
	}
	id := randomToken()
	data, err := json.Marshal(hostsRequest{ID: id, Revision: revision, Expires: h.now().Add(hostsRequestLife).Unix(), Hosts: hosts})
	if err != nil {
		return nil, err
	}
	path := filepath.Join(h.dir, "request.json")
	if err := writePrivate(path, data); err != nil {
		return nil, &requestError{status: 503, code: "storage_failed", message: "The change could not be passed to the server."}
	}
	nudge := time.NewTicker(hostsNudgeEvery)
	defer nudge.Stop()
	for {
		raw, err := readPrivate(filepath.Join(h.dir, "status.json"))
		var status hostsStatus
		if err == nil && json.Unmarshal(raw, &status) == nil && status.ID == id {
			switch {
			case status.OK:
				return status.Warnings, nil
			case status.Conflict:
				return nil, errHostsConflict
			}
			return nil, &requestError{status: 400, code: "invalid_input", message: status.Message}
		}
		select {
		case <-wait.Done():
			return nil, &requestError{status: 504, code: "hosts_uncertain", uncertain: true,
				message: "The server has not finished this change yet. Refresh in a moment to see whether it took effect."}
		case <-nudge.C:
			_ = writePrivate(path, data)
		case <-time.After(hostsPollEvery):
		}
	}
}

// hostsView is the page: the hosts, how their devices are, and the devices to
// choose from. Without the coordinator's answer it still lists the hosts.
func (s *Server) hostsView(ctx context.Context) (map[string]any, error) {
	list, err := s.hosts.read()
	if err != nil {
		return nil, err
	}
	var out wire
	nodesErr := s.upstream.call(ctx, "GET", "/api/v1/node", nil, &out)
	byID, byName := map[string]Device{}, map[string]bool{}
	devices := []HostDevice{}
	var hostsDevice *HostDevice
	for _, node := range out.list("nodes") {
		d := deviceDTO(node)
		byID[d.ID], byName[d.Name] = d, true
		if slices.Contains(d.Tags, hostsTag) {
			hostsDevice = &HostDevice{Name: d.Name, Online: d.Online}
		}
		// The network's own devices are not somewhere to send people.
		if !slices.ContainsFunc(d.Tags, func(tag string) bool { return strings.HasPrefix(tag, coveeTagPrefix) }) {
			devices = append(devices, HostDevice{Name: d.Name, Online: d.Online})
		}
	}
	slices.SortFunc(devices, func(a, b HostDevice) int { return strings.Compare(a.Name, b.Name) })
	rows := []HostRow{}
	for _, entry := range list.entries {
		row := HostRow{HostInput: entry.input(list.label(entry.Name)), URL: "https://" + entry.Name}
		if nodesErr == nil {
			device, known := byID[entry.NodeID]
			switch {
			case !known:
				row.Status = "missing"
			case device.Name != entry.Device:
				row.Status = "renamed"
			case device.Online:
				row.Status = "online"
			default:
				row.Status = "offline"
			}
		}
		rows = append(rows, row)
	}
	view := map[string]any{"enabled": true, "domain": list.domain, "revision": list.revision, "hosts": rows, "devices": devices, "hostsDevice": hostsDevice, "problem": ""}
	if nodesErr != nil {
		view["problem"] = "The coordinator did not answer, so this page cannot show which devices are online."
	}
	return view, nil
}

func (s *Server) getHosts(w http.ResponseWriter, r *http.Request) {
	if s.hosts == nil {
		respond(w, 200, map[string]any{"enabled": false})
		return
	}
	view, err := s.hostsView(r.Context())
	if err != nil {
		fail(w, 503, "hosts_unreadable", "The list of hosts on the server could not be read.")
		return
	}
	respond(w, 200, view)
}

func (s *Server) setHosts(w http.ResponseWriter, r *http.Request) {
	if s.hosts == nil {
		fail(w, 404, "not_found", "This network has no hosts yet; add the first one with `covee host add`")
		return
	}
	var in struct {
		Hosts    []HostInput `json:"hosts"`
		Revision string      `json:"revision"`
	}
	if !decode(w, r, &in) {
		return
	}
	// A request that forgot its list must not read as "no hosts".
	if in.Hosts == nil {
		fail(w, 400, "invalid_input", "Send the complete list of hosts")
		return
	}
	wanted, err := cleanHosts(in.Hosts)
	if err != nil {
		fail(w, 400, "invalid_input", err.Error())
		return
	}
	list, err := s.hosts.read()
	if err != nil {
		fail(w, 503, "hosts_unreadable", "The list of hosts on the server could not be read.")
		return
	}
	old := []HostInput{}
	for _, entry := range list.entries {
		old = append(old, entry.input(list.label(entry.Name)))
	}
	s.mutate(w, r, "hosts.update", changedHosts(old, wanted), func() (any, error) {
		warnings, err := s.hosts.apply(r.Context(), wanted, in.Revision)
		if err != nil {
			return nil, err
		}
		if warnings == nil {
			warnings = []string{}
		}
		// The change has taken effect; the page reloads the list by itself.
		return map[string]any{"warnings": warnings}, nil
	}, 200)
}
