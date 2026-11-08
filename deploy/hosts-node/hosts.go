package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// maxHosts bounds the hosts file; deploy.py refuses more.
	maxHosts = 256
	// maxHostsFileSize bounds what is read from the hosts file.
	maxHostsFileSize = 1 << 20
	maxPathLength    = 1024
)

// The network's own address ranges. Every target must be a device in the
// network, so a file naming anything else is refused here, before peersOnly
// would refuse the address at each connection.
var networkRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

// Host is one name served in the network, as deploy.py writes it.
type Host struct {
	Name    string // full lowercase DNS name, for example grafana.mesh.covee.io
	Address string // the target device's network address
	Port    int
	Path    string // "" or a path prefix starting with "/"
	Scheme  string // http or https
	Verify  bool   // check an https target's certificate
	Device  string // the target device's name, for logs and error pages
}

// readHosts reads the hosts file deploy.py writes:
//
//	{"hosts": [{"name": "grafana.mesh.covee.io", "address": "100.64.0.7", "port": 8080,
//	  "path": "/some/sub/service", "scheme": "http", "verify": true, "device": "mac-mini"}]}
//
// A missing file means no hosts. Every entry is checked strictly, so a
// damaged file cannot send requests anywhere but a device in the network.
func readHosts(path string) ([]Host, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxHostsFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxHostsFileSize {
		return nil, errors.New("the hosts file is too large")
	}
	return parseHosts(raw)
}

func parseHosts(raw []byte) ([]Host, error) {
	var file struct {
		Hosts []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
			Port    int    `json:"port"`
			Path    string `json:"path"`
			Scheme  string `json:"scheme"`
			Verify  *bool  `json:"verify"`
			Device  string `json:"device"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("the hosts file is not valid JSON: %w", err)
	}
	if len(file.Hosts) > maxHosts {
		return nil, fmt.Errorf("the hosts file lists %d hosts; at most %d are allowed", len(file.Hosts), maxHosts)
	}
	out := make([]Host, 0, len(file.Hosts))
	seen := make(map[string]bool, len(file.Hosts))
	for i, e := range file.Hosts {
		// An entry without "verify" checks the certificate.
		h := Host{Name: e.Name, Address: e.Address, Port: e.Port, Path: e.Path, Scheme: e.Scheme, Verify: e.Verify == nil || *e.Verify, Device: e.Device}
		if err := checkHost(h); err != nil {
			return nil, fmt.Errorf("host %d: %w", i+1, err)
		}
		if seen[h.Name] {
			return nil, fmt.Errorf("host %d: %s is listed more than once", i+1, h.Name)
		}
		seen[h.Name] = true
		out = append(out, h)
	}
	return out, nil
}

func checkHost(h Host) error {
	if !isDNSName(h.Name) {
		return fmt.Errorf("%q is not a lowercase DNS name such as grafana.mesh.example.com", h.Name)
	}
	addr, err := netip.ParseAddr(h.Address)
	if err != nil || addr.Zone() != "" || addr.String() != h.Address {
		return fmt.Errorf("%s: %q is not a network address such as 100.64.0.7", h.Name, h.Address)
	}
	inNetwork := false
	for _, p := range networkRanges {
		inNetwork = inNetwork || p.Contains(addr)
	}
	if !inNetwork {
		return fmt.Errorf("%s: %s is not an address in the network", h.Name, h.Address)
	}
	if h.Port < 1 || h.Port > 65535 {
		return fmt.Errorf("%s: port %d is not between 1 and 65535", h.Name, h.Port)
	}
	if err := checkPath(h.Path); err != nil {
		return fmt.Errorf("%s: %w", h.Name, err)
	}
	if h.Scheme != "http" && h.Scheme != "https" {
		return fmt.Errorf("%s: scheme %q is not http or https", h.Name, h.Scheme)
	}
	if h.Device != "" && !isLabel(h.Device) {
		return fmt.Errorf("%s: %q is not a device name", h.Name, h.Device)
	}
	return nil
}

// checkPath accepts "" or an absolute URL path without a query, a fragment,
// or "..", in raw or percent-encoded form.
func checkPath(p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must start with /", p)
	}
	if len(p) > maxPathLength {
		return fmt.Errorf("the path is longer than %d characters", maxPathLength)
	}
	plain, err := url.PathUnescape(p)
	if err != nil {
		return fmt.Errorf("path %q is not a valid URL path", p)
	}
	if strings.Contains(p, "..") || strings.Contains(plain, "..") {
		return fmt.Errorf("path %q must not contain ..", p)
	}
	// Spaces are allowed only percent-encoded; control characters and
	// backslashes not at all.
	if strings.ContainsFunc(p, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '\\' }) ||
		strings.ContainsFunc(plain, func(r rune) bool { return r < ' ' || r == 0x7f || r == '\\' }) {
		return fmt.Errorf("path %q contains characters a URL path cannot", p)
	}
	if strings.ContainsAny(p, "?#") {
		return fmt.Errorf("path %q must not contain a query or fragment", p)
	}
	return nil
}

// isDNSName reports whether name is a lowercase name of at least two labels,
// without a trailing dot.
func isDNSName(name string) bool {
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !isLabel(l) {
			return false
		}
	}
	return true
}

func isLabel(l string) bool {
	if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// hostsFile follows the hosts file. It reads the file again only when its
// size or modification time changes (deploy.py replaces it by renaming), and
// a file that does not read or check leaves the hosts served as they were.
type hostsFile struct {
	path    string
	seen    fileStamp
	started bool
}

type fileStamp struct {
	exists bool
	size   int64
	mod    time.Time
}

func (a fileStamp) same(b fileStamp) bool {
	return a.exists == b.exists && a.size == b.size && a.mod.Equal(b.mod)
}

func stampOf(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileStamp{}, nil
	}
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{exists: true, size: info.Size(), mod: info.ModTime()}, nil
}

// check reports the hosts to serve when the file changed since the last
// check, and changed false when it has not.
func (f *hostsFile) check() (hosts []Host, changed bool, err error) {
	stamp, err := stampOf(f.path)
	if err != nil {
		return nil, false, err
	}
	if f.started && stamp.same(f.seen) {
		return nil, false, nil
	}
	// Recorded before reading, so a bad file is reported once, not on every check.
	f.seen, f.started = stamp, true
	hosts, err = readHosts(f.path)
	if err != nil {
		return nil, false, err
	}
	return hosts, true, nil
}
