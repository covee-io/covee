package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"covee.io/cli/internal/payload"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
)

// Hosts are names under the network's mesh domain, such as
// https://grafana.<mesh domain>, that devices in the network open in a
// browser. A hosts device on the server joins the network, answers for every
// such name with the network's public certificate (which then covers
// *.<mesh domain>) and passes each request on to a device and port in the
// network. Nothing new is reachable from the internet.

// serverHosts is the private file the complete list of hosts is sent in;
// serverHostsFile is what the hosts device serves, inside the runtime.
const (
	serverHosts     = "/srv/covee/hosts.json"
	serverHostsFile = "state/hosts/hosts.json"
)

// maxHosts and maxHostPath match what the hosts device accepts.
const (
	maxHosts    = 256
	maxHostPath = 1024
)

// reservedHostNames are names the network itself uses under its mesh domain.
var reservedHostNames = []string{"hosts", "console", "gateway", "admin"}

// checkHostName applies the server's rules for a host's name: one lowercase
// DNS label that the network does not use itself.
func checkHostName(v string) error {
	if v == "" || len(v) > 63 || !labelRE.MatchString(v) {
		return fmt.Errorf("%q cannot be a host name; use 1 to 63 lowercase letters, digits or dashes, such as grafana or home-assistant (no dots, and no dash at either end)", v)
	}
	for _, r := range reservedHostNames {
		if v == r {
			return fmt.Errorf("%s is a name the network uses itself; choose another one", v)
		}
	}
	return nil
}

// hostName turns what someone typed into a host's name: grafana, or the full
// grafana.<mesh domain>, in any case.
func hostName(v, meshDomain string) (string, error) {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if meshDomain != "" {
		v = strings.TrimSuffix(v, "."+meshDomain)
	}
	if strings.Contains(v, ".") {
		return "", fmt.Errorf("%q cannot be a host name; give one word such as grafana, and devices open it at https://grafana.%s", v, meshDomain)
	}
	return v, checkHostName(v)
}

const toExample = "such as mac-mini:8080 or mac-mini:8080/some/sub/service"

// parseTarget reads --to: device:port, optionally followed by a path. The
// device is a name in the network (mac-mini, or mac-mini.<mesh domain>). A
// leading https:// is the same as --https.
func parseTarget(v, meshDomain string) (h record.Host, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return h, fmt.Errorf("say where the host goes with --to device:port, %s", toExample)
	}
	h.Scheme = "http"
	lower := strings.ToLower(v)
	switch {
	case strings.HasPrefix(lower, "https://"):
		h.Scheme, v = "https", v[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		v = v[len("http://"):]
	case strings.Contains(v, "://"):
		return h, fmt.Errorf("--to %s: only http and https services can be hosts", v)
	}
	address, path := v, ""
	if i := strings.Index(v, "/"); i >= 0 {
		address, path = v[:i], v[i:]
	}
	device, port, ok := strings.Cut(address, ":")
	if !ok || port == "" {
		return h, fmt.Errorf("--to %s: give the device's name and the port its service listens on, %s", v, toExample)
	}
	device = strings.TrimSuffix(strings.ToLower(device), ".")
	if meshDomain != "" {
		device = strings.TrimSuffix(device, "."+meshDomain)
	}
	if device == "" || !labelRE.MatchString(device) {
		return h, fmt.Errorf("--to %s: %q is not a device name; use the device's name in the network, as the console's Devices page shows it, %s", v, device, toExample)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || port[0] == '0' || port[0] == '+' {
		return h, fmt.Errorf("--to %s: the port must be a number from 1 to 65535, %s", v, toExample)
	}
	if path == "/" {
		path = ""
	}
	if err := checkTargetPath(path); err != nil {
		return h, fmt.Errorf("--to %s: %w", v, err)
	}
	h.Device, h.Port, h.Path = device, n, path
	return h, nil
}

// checkTargetPath applies the rules of the hosts device (checkPath in
// deploy/hosts-node/hosts.go) and of the server (validate_hosts in
// scripts/deploy.py), in raw and percent-encoded form, so a bad path is refused
// here rather than after a certificate and a restart.
func checkTargetPath(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxHostPath {
		return fmt.Errorf("the path is longer than %d characters", maxHostPath)
	}
	if strings.HasPrefix(p, "//") {
		return errors.New("the path cannot begin with //; give the folder the service lives under, such as /some/sub/service")
	}
	if strings.ContainsAny(p, "?#") {
		return errors.New("the path cannot contain ? or #; give only the folder the service lives under, such as /some/sub/service")
	}
	for _, c := range p {
		if c <= ' ' || c >= 0x7f || c == '\\' {
			return errors.New("the path cannot contain spaces, backslashes, control characters or letters outside plain English; write a space as %20")
		}
	}
	plain, err := url.PathUnescape(p)
	if err != nil {
		return errors.New("the path has a % that is not followed by two hexadecimal digits; write a % as %25")
	}
	if strings.Contains(p, "..") || strings.Contains(plain, "..") {
		return errors.New("the path cannot contain .., written out or as %2e%2e")
	}
	if strings.ContainsFunc(plain, func(r rune) bool { return r < ' ' || r == 0x7f || r == '\\' }) {
		return errors.New("the path cannot contain an encoded backslash or control character, such as %5C or %00")
	}
	return nil
}

// hostURL is the address devices in the network open.
func hostURL(n *record.Network, h record.Host) string {
	return "https://" + h.Name + "." + n.DNSBaseDomain
}

// hostTarget describes where a host goes, as --to takes it.
func hostTarget(h record.Host) string {
	t := fmt.Sprintf("%s:%d%s", h.Device, h.Port, h.Path)
	if h.Scheme == "https" {
		if h.NoVerify {
			return t + " (https, its certificate is not checked)"
		}
		return t + " (https)"
	}
	return t
}

func hostScheme(h record.Host) string {
	if h.Scheme == "" {
		return "http"
	}
	return h.Scheme
}

// hostsZoneOK reports whether names under the mesh domain can be proved in
// the network's DNS zone, which the certificate's wildcard needs.
func (s *session) hostsZoneOK() bool {
	z, base := s.n.DNS.Zone, s.n.DNSBaseDomain
	return z == "" || base == z || strings.HasSuffix(base, "."+z)
}

// HostList prints a network's hosts, as this computer knows them.
func HostList(env *Env, name string) error {
	n, err := env.Records.Load(name)
	if err != nil {
		return err
	}
	if len(n.Hosts) == 0 {
		env.Ask.Say("Network %s has no hosts. Add one with `covee host add %s grafana --to mac-mini:8080`.", n.Name, n.Name)
		return nil
	}
	for _, h := range n.Hosts {
		env.Ask.Say("%s → %s", hostURL(n, h), hostTarget(h))
	}
	return nil
}

// HostAdd adds a host, or changes where an existing one goes. The first host
// of a network starts its hosts device and renews its certificate.
func HostAdd(ctx context.Context, env *Env, name, host, to string, https, noVerify bool) error {
	n, err := env.Records.Load(name)
	if err != nil {
		return err
	}
	label, err := hostName(host, n.DNSBaseDomain)
	if err != nil {
		return err
	}
	target, err := parseTarget(to, n.DNSBaseDomain)
	if err != nil {
		return err
	}
	if https {
		target.Scheme = "https"
	}
	if noVerify {
		if target.Scheme != "https" {
			return errors.New("--no-verify only applies to a service that uses https; add --https too, or leave both out")
		}
		target.NoVerify = true
	}
	target.Name = label
	if target.Device == "hosts" {
		return errors.New("hosts is the network's own hosts device; give the device the service runs on")
	}
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	srv := s.server(true)
	if err := s.useServerHosts(ctx, srv); err != nil {
		return err
	}
	hosts := append([]record.Host(nil), s.n.Hosts...)
	replaced := -1
	for i, h := range hosts {
		if h.Name == label {
			replaced = i
		}
	}
	if replaced >= 0 && hosts[replaced] == target {
		s.say("Devices in network %s already open %s → %s.", s.n.Name, hostURL(s.n, target), hostTarget(target))
		return nil
	}
	if replaced >= 0 {
		hosts[replaced] = target
	} else {
		if len(hosts) >= maxHosts {
			return fmt.Errorf("network %s has %d hosts, the most it can serve; remove one first", s.n.Name, maxHosts)
		}
		hosts = append(hosts, target)
	}
	if !s.n.HostsEnabled {
		if err := s.enableHosts(ctx, srv, target, hosts); err != nil {
			return err
		}
	}
	if err := s.setHosts(ctx, srv, hosts); err != nil {
		if replaced < 0 && len(s.n.Hosts) == 0 {
			return fmt.Errorf("hosts are on for %s, but %s was not added: %w", s.n.Name, label, err)
		}
		return fmt.Errorf("the network kept its previous hosts: %w", err)
	}
	if replaced >= 0 {
		s.say("Devices in network %s now open %s → %s.", s.n.Name, hostURL(s.n, target), hostTarget(target))
	} else {
		s.say("Devices in network %s can now open %s → %s.", s.n.Name, hostURL(s.n, target), hostTarget(target))
	}
	s.say("%s needs to be on and connected to the network, with its service answering on port %d for other devices (not only for itself).", target.Device, target.Port)
	return nil
}

// HostRemove removes one host. The hosts device keeps running.
func HostRemove(ctx context.Context, env *Env, name, host string) error {
	n, err := env.Records.Load(name)
	if err != nil {
		return err
	}
	label, err := hostName(host, n.DNSBaseDomain)
	if err != nil {
		return err
	}
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	srv := s.server(true)
	if err := s.useServerHosts(ctx, srv); err != nil {
		return err
	}
	var keep []record.Host
	var removed *record.Host
	for _, h := range s.n.Hosts {
		if h.Name == label {
			removed = &h
			continue
		}
		keep = append(keep, h)
	}
	if removed == nil {
		return fmt.Errorf("network %s has no host named %s; `covee host list %s` shows its hosts", s.n.Name, label, s.n.Name)
	}
	ok, err := env.Ask.Confirm("host_remove", fmt.Sprintf("Remove %s → %s? Devices in network %s can then no longer open it", hostURL(s.n, *removed), hostTarget(*removed), s.n.Name), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	if err := s.setHosts(ctx, srv, keep); err != nil {
		return fmt.Errorf("the network kept its previous hosts: %w", err)
	}
	s.say("Removed %s; devices in network %s can no longer open it.", hostURL(s.n, *removed), s.n.Name)
	if len(keep) == 0 {
		s.say("Network %s has no hosts now. Its hosts device keeps running for the next one; `covee host off %s` turns it off.", s.n.Name, s.n.Name)
	}
	return nil
}

// HostsOff removes every host and the hosts device.
func HostsOff(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	if !s.n.HostsEnabled {
		s.say("Network %s has no hosts.", s.n.Name)
		return nil
	}
	what := "Its hosts device leaves the network"
	if len(s.n.Hosts) > 0 {
		what = fmt.Sprintf("Devices can no longer open its %d host(s), and the hosts device leaves the network", len(s.n.Hosts))
	}
	ok, err := env.Ask.Confirm("hosts_off", fmt.Sprintf("Turn off hosts for %s? %s; the coordinator restarts once, and devices reconnect within a minute", s.n.Name, what), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	srv := s.server(true)
	out, err := srv.deployResult(ctx, "disable-hosts --directory "+remote.Quote(s.n.Runtime))
	if err != nil {
		return err
	}
	var result struct {
		Hosts *bool `json:"hosts"`
	}
	if err := lastJSON(out, &result); err != nil || result.Hosts == nil || *result.Hosts {
		return errors.New("the server did not confirm that hosts are off")
	}
	s.n.HostsEnabled, s.n.Hosts = false, nil
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	if err := s.syncConfig(ctx, srv); err != nil {
		return err
	}
	s.say("Hosts are off for %s, and its hosts device has left the network.", s.n.Name)
	return nil
}

// enableHosts starts the hosts device, after confirmation, with a new
// certificate that covers every name under the mesh domain. The server first
// checks the intended hosts, so a mistyped device costs neither a certificate
// nor a restart.
func (s *session) enableHosts(ctx context.Context, srv *server, first record.Host, hosts []record.Host) error {
	base := s.n.DNSBaseDomain
	if !s.hostsZoneOK() {
		return fmt.Errorf("names under %s are outside the DNS zone %s, so the certificate for them cannot be issued", base, s.n.DNS.Zone)
	}
	archive := s.env.Archive
	if archive == nil {
		archive = payload.Archive
	}
	var err error
	if s.archive, s.digest, err = archive(); err != nil {
		return err
	}
	if s.n.Payload != s.digest {
		return fmt.Errorf("network %s runs older Covee files; run `covee update %s` first", s.n.Name, s.n.Name)
	}
	if err := s.checkHosts(ctx, srv, hosts); err != nil {
		return err
	}
	ok, err := s.env.Ask.Confirm("hosts", fmt.Sprintf("Add hosts to network %s? Devices in the network will open %s, and other names you add, while devices outside the network cannot. "+
		"A hosts device joins the network, the certificate is renewed to cover every name under %s, and the coordinator restarts once (devices reconnect within a minute)", s.n.Name, hostURL(s.n, first), base), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	if c := s.n.Certificate; c != nil {
		s.opts.Staging = c.Staging
	}
	s.n.HostsEnabled = true
	s.say("[1/3] Get a certificate for %s and every name under %s", s.n.Hostname, base)
	if err := s.obtainCertificate(ctx, false); err != nil {
		s.n.HostsEnabled = false
		return err
	}
	// The record's certificate now covers the wildcard; keep it even if the next step fails.
	s.n.HostsEnabled = false
	if err := s.env.Records.Save(s.n); err != nil {
		return err
	}
	chain, err := os.ReadFile(s.certPath())
	if err != nil {
		return err
	}
	key, err := s.store().Get(ctx, "tls-private-key")
	if err != nil {
		return err
	}
	s.say("[2/3] Install it and start the hosts device (the coordinator restarts once)")
	if err := srv.putFile(ctx, serverSecrets+"/tls/fullchain.pem", chain, "400"); err != nil {
		return err
	}
	if err := srv.putFile(ctx, serverSecrets+"/tls/privkey.pem", key, "400"); err != nil {
		return err
	}
	out, err := srv.deployResult(ctx, "enable-hosts --cert "+serverSecrets+"/tls/fullchain.pem --key "+serverSecrets+"/tls/privkey.pem --directory "+remote.Quote(s.n.Runtime))
	if err != nil {
		return fmt.Errorf("hosts were not turned on: %w", refusal(err))
	}
	var result struct {
		Hosts *bool `json:"hosts"`
	}
	if err := lastJSON(out, &result); err != nil || result.Hosts == nil || !*result.Hosts {
		return errors.New("the server did not confirm that hosts are on; check it with `covee status " + s.n.Name + "`")
	}
	s.n.HostsEnabled = true
	if err := s.env.Records.Save(s.n); err != nil {
		return err
	}
	if err := s.syncConfig(ctx, srv); err != nil {
		return err
	}
	s.say("[3/3] Check the hosts device")
	if state := srv.containerState(ctx, "hosts-node"); state != "healthy" {
		s.say("  The hosts device is %s; it usually joins within a minute. Check it later with `covee status %s`.", state, s.n.Name)
	}
	return nil
}

// sendHosts uploads the complete list of hosts, for check-hosts and set-hosts.
func (s *session) sendHosts(ctx context.Context, srv *server, hosts []record.Host) error {
	type entry struct {
		Name   string `json:"name"`
		Device string `json:"device"`
		Port   int    `json:"port"`
		Path   string `json:"path"`
		Scheme string `json:"scheme"`
		Verify bool   `json:"verify"`
	}
	list := []entry{}
	for _, h := range hosts {
		list = append(list, entry{Name: h.Name, Device: h.Device, Port: h.Port, Path: h.Path, Scheme: hostScheme(h), Verify: !h.NoVerify})
	}
	data, err := json.MarshalIndent(map[string]any{"hosts": list}, "", "  ")
	if err != nil {
		return err
	}
	return srv.putFile(ctx, serverHosts, append(data, '\n'), "600")
}

// checkHosts asks the server whether it would take these hosts. It changes nothing.
func (s *session) checkHosts(ctx context.Context, srv *server, hosts []record.Host) error {
	if err := s.sendHosts(ctx, srv, hosts); err != nil {
		return err
	}
	out, err := srv.deployResult(ctx, "check-hosts --config "+serverHosts+" --directory "+remote.Quote(s.n.Runtime))
	if err != nil {
		return fmt.Errorf("nothing was changed: %w", refusal(err))
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := lastJSON(out, &result); err != nil || !result.OK {
		return errors.New("the server could not check the hosts; nothing was changed")
	}
	return nil
}

// setHosts sends the complete list of hosts to the server and records it
// once the server confirms it. Nothing restarts.
func (s *session) setHosts(ctx context.Context, srv *server, hosts []record.Host) error {
	if err := s.sendHosts(ctx, srv, hosts); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, h := range hosts {
		want[h.Name+"."+s.n.DNSBaseDomain] = true
	}
	out, err := srv.deployResult(ctx, "set-hosts --config "+serverHosts+" --directory "+remote.Quote(s.n.Runtime))
	if err != nil {
		return refusal(err)
	}
	var result struct {
		Hosts *[]struct {
			Name string `json:"name"`
		} `json:"hosts"`
		Warnings []string `json:"warnings"`
	}
	if err := lastJSON(out, &result); err != nil {
		return err
	}
	confirmed := result.Hosts != nil && len(*result.Hosts) == len(want)
	if confirmed {
		for _, h := range *result.Hosts {
			confirmed = confirmed && want[h.Name]
		}
	}
	if !confirmed {
		return errors.New("the server did not confirm the hosts; check them with `covee status " + s.n.Name + "`")
	}
	for _, warning := range result.Warnings {
		s.say("Note: %s", warning)
	}
	if len(hosts) == 0 {
		hosts = nil
	}
	s.n.Hosts = hosts
	return s.env.Records.Save(s.n)
}

// hostsFromFile reads hosts.json, as the server keeps it, into the record's form.
func hostsFromFile(raw []byte, meshDomain string) ([]record.Host, error) {
	var file struct {
		Hosts []struct {
			Name   string `json:"name"`
			Device string `json:"device"`
			Port   int    `json:"port"`
			Path   string `json:"path"`
			Scheme string `json:"scheme"`
			Verify *bool  `json:"verify"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, errors.New("the list of hosts is unreadable")
	}
	var hosts []record.Host
	for _, e := range file.Hosts {
		label, ok := strings.CutSuffix(e.Name, "."+meshDomain)
		if !ok || !labelRE.MatchString(label) {
			return nil, fmt.Errorf("the host %q is not a name under %s", e.Name, meshDomain)
		}
		if e.Device == "" || e.Port < 1 || e.Port > 65535 {
			return nil, fmt.Errorf("the host %s has no device and port", e.Name)
		}
		scheme := e.Scheme
		if scheme == "" {
			scheme = "http"
		}
		hosts = append(hosts, record.Host{Name: label, Device: e.Device, Port: e.Port, Path: e.Path, Scheme: scheme, NoVerify: e.Verify != nil && !*e.Verify})
	}
	return hosts, nil
}

// useServerHosts starts from the hosts the server holds, which are the ones
// devices actually get. set-hosts replaces the whole list, so a list on this
// computer that fell behind (another computer changed it, say) would otherwise
// silently drop hosts.
func (s *session) useServerHosts(ctx context.Context, srv *server) error {
	file := remote.Quote(s.n.Runtime + "/" + serverHostsFile)
	out, err := srv.covee.Output(ctx, "if [ -e "+file+" ]; then cat "+file+"; fi", nil)
	if err != nil {
		return fmt.Errorf("reading the network's hosts from the server: %w", err)
	}
	var held []record.Host
	if len(bytes.TrimSpace(out)) == 0 {
		if s.n.HostsEnabled {
			return fmt.Errorf("the server has no list of hosts although hosts are on for %s; check it with `covee status %s`", s.n.Name, s.n.Name)
		}
	} else if held, err = hostsFromFile(out, s.n.DNSBaseDomain); err != nil {
		return fmt.Errorf("reading the network's hosts from the server: %w", err)
	}
	here := map[string]record.Host{}
	for _, h := range s.n.Hosts {
		h.Scheme = hostScheme(h)
		here[h.Name] = h
	}
	var differs []string
	for _, h := range held {
		mine, ok := here[h.Name]
		switch {
		case !ok:
			differs = append(differs, h.Name+" is only on the server")
		case mine != h:
			differs = append(differs, h.Name+" goes elsewhere on the server")
		}
		delete(here, h.Name)
	}
	for name := range here {
		differs = append(differs, name+" is only on this computer")
	}
	if len(differs) == 0 {
		return nil
	}
	sort.Strings(differs)
	s.say("This computer's list of hosts differs from the network's (%s); another computer may have changed it. Continuing from the network's list.", strings.Join(differs, ", "))
	s.n.Hosts = held
	if !s.n.HostsEnabled {
		return nil
	}
	return s.env.Records.Save(s.n)
}

// refusal is the server's own explanation when deploy.py refused a change
// (its "ERROR: ..." line), such as "No device named mac-mini in this
// network", or err itself when there is none.
func refusal(err error) error {
	msg := err.Error()
	i := strings.LastIndex(msg, "ERROR: ")
	if i < 0 {
		return err
	}
	msg = msg[i+len("ERROR: "):]
	if j := strings.Index(msg, " | "); j >= 0 {
		msg = msg[:j]
	}
	if msg = strings.TrimSpace(msg); msg == "" {
		return err
	}
	return errors.New(msg)
}
