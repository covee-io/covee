package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"covee.io/cli/internal/entra"
	"covee.io/cli/internal/record"
)

// Server-side locations. They match the pilot layout (docs/guide/server.md).
const (
	serverSource    = "/opt/covee/src"
	serverSecrets   = "/srv/covee/secrets"
	serverConfig    = "/srv/covee/deployment.json"
	serverGrants    = "/srv/covee/grants.json"
	serverProviders = "/srv/covee/providers.json"
)

var (
	labelRE      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	regexpUser   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	regexpRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
)

// sshSources parses the networks allowed to reach SSH. They must be IPv4
// networks of /24 or narrower and include the address setup connects from,
// or the firewall would lock this computer out.
func sshSources(v string, client net.IP) ([]string, error) {
	var out []string
	covered := false
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			part += "/32"
		}
		ip, network, err := net.ParseCIDR(part)
		if err != nil || ip.To4() == nil || !ip.Equal(network.IP) {
			return nil, fmt.Errorf("%s is not an IPv4 network such as 192.168.1.0/24 or 203.0.113.7/32", part)
		}
		if ones, _ := network.Mask.Size(); ones < 24 {
			return nil, fmt.Errorf("%s is too wide; use /24 or narrower", part)
		}
		covered = covered || network.Contains(client)
		out = append(out, network.String())
	}
	if len(out) == 0 || len(out) > 8 {
		return nil, errors.New("give 1 to 8 networks")
	}
	if !covered {
		return nil, fmt.Errorf("include %s, the address you are connecting from, or you would be locked out", client)
	}
	return out, nil
}

// checkHostname applies the deployment tool's rules for a public hostname.
func checkHostname(v string) error {
	if len(v) > 253 || v != strings.ToLower(v) || strings.Count(v, ".") < 1 {
		return errors.New("use a full lowercase hostname on your domain, for example vpn.example.com")
	}
	for _, label := range strings.Split(v, ".") {
		if !labelRE.MatchString(label) {
			return errors.New("use a full lowercase hostname on your domain, for example vpn.example.com")
		}
	}
	if net.ParseIP(v) != nil {
		return errors.New("use a hostname, not an IP address")
	}
	for _, reserved := range []string{"example.com", "example.net", "example.org", "invalid", "test", "localhost", "local"} {
		if v == reserved || strings.HasSuffix(v, "."+reserved) {
			return errors.New("use a hostname on a domain you own")
		}
	}
	return nil
}

// checkMeshDomain applies the coordinator's rules for the name suffix devices
// get: devices answer names under it themselves, so the public hostname must
// stay outside it.
func checkMeshDomain(host, v string) error {
	if err := checkHostname(v); err != nil {
		return err
	}
	if v == host {
		return errors.New("use a different name from the public hostname")
	}
	if strings.HasSuffix(host, "."+v) {
		return fmt.Errorf("%s would be inside it, and devices could no longer find the network; use a suffix such as %s", host, defaultMeshDomain(host))
	}
	return nil
}

// defaultMeshDomain suggests the name suffix devices get inside the network.
// consoleHost is the admin console's name inside the network, or "" when it is not served there.
func consoleHost(n *record.Network) string {
	if !n.ConsoleInNetwork {
		return ""
	}
	return "console." + n.DNSBaseDomain
}

// certNames are the names the public certificate covers.
func certNames(n *record.Network) []string {
	if host := consoleHost(n); host != "" {
		return []string{n.Hostname, host}
	}
	return []string{n.Hostname}
}

func defaultMeshDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return "mesh." + strings.Join(parts[1:], ".")
	}
	return "mesh." + host
}

func checkIPv4(v string) error {
	ip := net.ParseIP(v)
	if ip == nil || ip.To4() == nil {
		return errors.New("type an IPv4 address such as 203.0.113.10")
	}
	return nil
}

func providerFile(kind string, n *record.Network) string {
	switch kind {
	case "entra":
		return serverSecrets + "/entra-client-secret"
	case "google":
		return serverSecrets + "/google-client-secret"
	default:
		return serverSecrets + "/apple-AuthKey_" + n.SignIn.Apple.KeyID + ".p8"
	}
}

// providersConfig renders the enabled sign-in providers with their server-side
// secret files, as the deployment tool expects them.
func providersConfig(n *record.Network) []map[string]any {
	var providers []map[string]any
	if e := n.SignIn.Entra; e != nil {
		providers = append(providers, map[string]any{
			"id": "entra", "kind": "entra", "issuer": entra.Issuer(e.TenantID), "client_id": e.ClientID,
			"client_secret_file": providerFile("entra", n), "allowed_group_ids": []string{e.GroupID}})
	}
	if g := n.SignIn.Google; g != nil {
		providers = append(providers, map[string]any{
			"id": "google", "kind": "google", "client_id": g.ClientID, "client_secret_file": providerFile("google", n)})
	}
	if a := n.SignIn.Apple; a != nil {
		providers = append(providers, map[string]any{
			"id": "apple", "kind": "apple", "client_id": a.ServicesID, "team_id": a.TeamID, "key_id": a.KeyID,
			"private_key_file": providerFile("apple", n)})
	}
	if n.SignIn.Local != nil {
		providers = append(providers, map[string]any{"id": "local", "kind": "local"})
	}
	return providers
}

// deploymentConfig renders the deployment tool's configuration (the social
// identity profile, see deploy/deployment.social.example.json).
func deploymentConfig(n *record.Network, grants []map[string]any) ([]byte, error) {
	providers := providersConfig(n)
	if len(providers) == 0 {
		return nil, errors.New("at least one sign-in method is required")
	}
	if grants == nil {
		grants = []map[string]any{}
	}
	spec := map[string]any{
		"control_host": n.Hostname, "admin_host": "localhost", "public_bind": "0.0.0.0",
		"public_port": 443, "admin_port": 8444, "stun_port": 3478,
		"dns_base_domain": n.DNSBaseDomain, "node_expiry": "30d",
		"identity": map[string]any{"providers": providers, "grants": grants},
		"tls":      map[string]any{"control_cert_file": serverSecrets + "/tls/fullchain.pem", "control_key_file": serverSecrets + "/tls/privkey.pem"},
	}
	if n.ConsoleInNetwork {
		spec["console_in_network"] = true
	}
	if n.Gateway {
		spec["gateway"] = true
	}
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
