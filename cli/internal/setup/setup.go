// Package setup implements `covee setup` and the commands that manage a
// network afterwards. Setup asks every question first and changes nothing
// until the admin confirms a summary. It then runs each step, saving progress
// after every one, so an interrupted setup continues where it stopped.
package setup

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"covee.io/cli/internal/cert"
	"covee.io/cli/internal/dns"
	"covee.io/cli/internal/entra"
	"covee.io/cli/internal/guided"
	"covee.io/cli/internal/payload"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
	"covee.io/cli/internal/secrets"
)

// Env holds everything setup talks to, so tests can replace it.
type Env struct {
	Ask        prompt.Asker
	Out        io.Writer
	Home       string
	Records    *record.Store
	AWS        func(ctx context.Context, region string) (aws.Config, error)
	Caller     func(ctx context.Context, cfg aws.Config) (string, error)
	NewRoute53 func(aws.Config) dns.Route53API
	NewSSM     func(aws.Config) secrets.SSMAPI
	NewIAM     func(aws.Config) dns.IAMAPI
	EntraToken entra.TokenSource
	GraphBase  string
	// CloudflareBase and CloudflareLookup replace Cloudflare's API and name
	// servers (tests).
	CloudflareBase   string
	CloudflareLookup func(ctx context.Context, server, name string) ([]string, error)
	Open             func(string)
	SSH              string // ssh program; empty means "ssh"
	HTTP             *http.Client
	Archive          func() ([]byte, string, error)
	// CA replaces Let's Encrypt (tests).
	CA func(staging bool) CertAuthority
}

// CertAuthority issues the network's public certificate.
type CertAuthority interface {
	Terms(ctx context.Context) (string, error)
	// Obtain issues one certificate for every name in hosts.
	Obtain(ctx context.Context, hosts []string, account []byte, provider dns.Provider, say func(string, ...any)) (*cert.Result, []byte, error)
}

type letsEncrypt struct{ directory string }

func (l letsEncrypt) Terms(ctx context.Context) (string, error) {
	return cert.TermsURL(ctx, l.directory)
}

func (l letsEncrypt) Obtain(ctx context.Context, hosts []string, account []byte, provider dns.Provider, say func(string, ...any)) (*cert.Result, []byte, error) {
	issuer := &cert.Issuer{DirectoryURL: l.directory, AccountKeyPEM: account, DNS: provider, Say: say}
	return issuer.Obtain(ctx, hosts[0], hosts[1:]...)
}

// Options are the command-line choices for setup.
type Options struct {
	Network string
	Staging bool // use the Let's Encrypt staging service (tests only)
}

const (
	labelEntra         = "Microsoft (Entra ID / Office 365)"
	labelGoogle        = "Google"
	labelApple         = "Apple"
	labelLocalAccounts = "Covee accounts (passkey or password with an authenticator app)"
	labelR53           = "AWS Route 53"
	labelCloudflare    = "Cloudflare (covee changes the records with an API token)"
	labelManual        = "Somewhere else (I will add the records by hand)"
	labelSSM           = "AWS Parameter Store"
	labelLocal         = "Only on this computer"
	labelEmpty         = "A new, empty network"
	labelBackup        = "A backup of a network (to move or rebuild it)"
)

type session struct {
	env     *Env
	n       *record.Network
	opts    Options
	archive []byte
	digest  string
	awsCfg  *aws.Config
	zone    *dns.Route53
	// restoreKey holds a backup's key between the questions and its first step.
	restoreKey []byte
	// cfToken holds the Cloudflare token between the questions and the step
	// that keeps it in the secrets store.
	cfToken string
}

func (s *session) say(format string, args ...any) { s.env.Ask.Say(format, args...) }

// Run carries out `covee setup`.
func Run(ctx context.Context, env *Env, opts Options) error {
	archive := env.Archive
	if archive == nil {
		archive = payload.Archive
	}
	data, digest, err := archive()
	if err != nil {
		return err
	}
	s := &session{env: env, opts: opts, archive: data, digest: digest}
	if opts.Network != "" {
		n, err := env.Records.Load(opts.Network)
		switch {
		case err == nil:
			s.n = n
		case errors.Is(err, record.ErrNotFound):
		default:
			return err
		}
	}
	if s.n != nil {
		if len(s.n.Completed) > 0 && s.n.Done("verify") {
			s.say("Network %s is already set up (%s). Use `covee status %s`.", s.n.Name, s.n.Hostname, s.n.Name)
			return nil
		}
		s.say("Continuing the setup of network %s (%s). Finished steps are skipped.", s.n.Name, s.n.Hostname)
		ok, err := env.Ask.Confirm("resume", "Continue", true)
		if err != nil {
			return err
		}
		if !ok {
			return prompt.ErrAborted
		}
	} else {
		if err := s.questions(ctx); err != nil {
			return err
		}
	}
	return s.apply(ctx)
}

func (s *session) loadAWS(ctx context.Context, region string) (aws.Config, error) {
	if s.awsCfg != nil && s.awsCfg.Region == region {
		return *s.awsCfg, nil
	}
	cfg, err := s.env.AWS(ctx, region)
	if err != nil {
		return aws.Config{}, fmt.Errorf("reading your AWS settings: %w", err)
	}
	who, err := s.env.Caller(ctx, cfg)
	if err != nil {
		return aws.Config{}, fmt.Errorf("your AWS sign-in does not work (run `aws sts get-caller-identity` to check): %w", err)
	}
	if s.awsCfg == nil {
		s.say("  Using AWS as %s", who)
	}
	s.awsCfg = &cfg
	return cfg, nil
}

func (s *session) questions(ctx context.Context) error {
	ask := s.env.Ask
	n := &record.Network{Server: record.Server{Kind: "ssh", ServiceUser: "covee"}}
	s.say("Covee setup builds a complete network on a server you choose. Nothing is changed until you confirm the summary at the end.\n")
	defOrg := ""
	if all, err := s.env.Records.List(); err == nil && len(all) > 0 {
		defOrg = all[len(all)-1].Organization
	}
	var err error
	if n.Organization, err = ask.Text("organization", "Organization name", defOrg, func(v string) error {
		if len(v) > 80 {
			return errors.New("use at most 80 characters")
		}
		return nil
	}); err != nil {
		return err
	}
	if n.Name, err = ask.Text("network", "Network name (short, such as home or office)", s.opts.Network, func(v string) error {
		if err := record.CheckName(v); err != nil {
			return err
		}
		if _, err := s.env.Records.Load(v); err == nil {
			return fmt.Errorf("a network named %s already exists on this computer", v)
		}
		return nil
	}); err != nil {
		return err
	}
	origin, err := ask.Choose("start_from", "Start from", []string{labelEmpty, labelBackup}, labelEmpty)
	if err != nil {
		return err
	}
	if origin == labelBackup {
		if err := s.askBackup(ctx, n); err != nil {
			return err
		}
	} else {
		if n.Hostname, err = ask.Text("hostname", "Public hostname for this network, on your own domain", "", checkHostname); err != nil {
			return err
		}
		if n.DNSBaseDomain, err = ask.Text("mesh_domain", "Name suffix devices get inside the network", defaultMeshDomain(n.Hostname), func(v string) error {
			return checkMeshDomain(n.Hostname, v)
		}); err != nil {
			return err
		}
	}

	// Domain host.
	choice, err := ask.Choose("dns_host", "Where is the DNS for "+n.Hostname+" hosted?", []string{labelR53, labelCloudflare, labelManual}, labelR53)
	if err != nil {
		return err
	}
	n.DNS.Host = "manual"
	switch choice {
	case labelCloudflare:
		s.n = n
		if err := s.askCloudflareToken(ctx); err != nil {
			return err
		}
		zone, err := dns.FindCloudflareZone(ctx, s.cloudflare(), n.Hostname)
		if err != nil {
			return err
		}
		s.say("  Found %s", zone.Describe())
		n.DNS = record.DNS{Host: "cloudflare", ZoneID: zone.ZoneID, Zone: zone.Zone}
	case labelR53:
		cfg, err := s.loadAWS(ctx, "us-east-1")
		if err != nil {
			return err
		}
		zone, err := dns.FindZone(ctx, s.env.NewRoute53(cfg), n.Hostname)
		if err != nil {
			return err
		}
		s.say("  Found %s", zone.Describe())
		s.zone = zone
		n.DNS = record.DNS{Host: "route53", ZoneID: zone.ZoneID, Zone: zone.Zone}
	}

	// The console inside the network.
	if s.n = n; s.consoleZoneOK() {
		if n.ConsoleInNetwork, err = ask.Confirm("console_in_network", "Also open the admin console from your devices in the network, at https://console."+n.DNSBaseDomain+"? Devices outside the network cannot reach it", true); err != nil {
			return err
		}
	}

	// Server.
	kind, err := ask.Choose("server_kind", "Where should the network run?", []string{labelExisting, labelProxmox}, labelExisting)
	if err != nil {
		return err
	}
	var client net.IP
	defAddr := ""
	if kind == labelProxmox {
		s.n = n
		if client, err = s.askProxmox(ctx, n); err != nil {
			return err
		}
		defAddr = s.publicIPv4(ctx)
	} else if client, defAddr, err = s.askExisting(ctx, n); err != nil {
		return err
	}
	s.n = n
	def := client.String() + "/32"
	if _, lan, err := net.ParseCIDR(n.Server.IPv4CIDR); err == nil && lan.Contains(client) && client.IsPrivate() {
		if ones, _ := lan.Mask.Size(); ones >= 24 {
			def = lan.String()
		}
	}
	sources, err := ask.Text("ssh_sources", "Networks allowed to reach SSH (comma separated)", def, func(v string) error {
		_, err := sshSources(v, client)
		return err
	})
	if err != nil {
		return err
	}
	n.Server.SSHSources, _ = sshSources(sources, client)

	// Public address.
	serverIP, _, _ := net.ParseCIDR(n.Server.IPv4CIDR)
	if n.PublicAddress, err = ask.Text("public_address", "Public IPv4 address that "+n.Hostname+" should point to", defAddr, checkIPv4); err != nil {
		return err
	}
	if !serverIP.Equal(net.ParseIP(n.PublicAddress)) {
		s.say("  The server's own address is %s, so your router, firewall or cloud must forward TCP 443\n  and UDP 3478 from %s to it (a cloud server's public address usually does). Setup reminds\n  you before the final check.", serverIP, n.PublicAddress)
		if n.DNS.Host == "route53" {
			if n.DNS.Dynamic, err = ask.Confirm("dynamic_address", "Can your internet provider change this address from time to time (most home connections do)? If so,\n  the server keeps "+n.Hostname+" pointing at the current one", true); err != nil {
				return err
			}
		}
	}
	provider := s.dnsProvider()
	current, err := provider.CurrentA(ctx, n.Hostname)
	if err != nil {
		return err
	}
	if len(current) > 0 && !(len(current) == 1 && current[0] == n.PublicAddress) {
		ok, err := ask.Confirm("replace_dns", fmt.Sprintf("%s already points to %s. Replace that record", n.Hostname, strings.Join(current, ", ")), false)
		if err != nil {
			return err
		}
		if !ok {
			return prompt.ErrAborted
		}
	}

	// Sign-in.
	var picked []string
	if n.RestoredFrom != nil {
		for _, p := range n.Providers {
			picked = append(picked, map[string]string{"entra": labelEntra, "google": labelGoogle, "apple": labelApple, "local": labelLocalAccounts}[p])
		}
	} else {
		if picked, err = ask.ChooseMany("sign_in", "Sign-in methods for this network", []string{labelEntra, labelGoogle, labelApple, labelLocalAccounts}, nil); err != nil {
			return err
		}
		for _, p := range picked {
			n.Providers = append(n.Providers, map[string]string{labelEntra: "entra", labelGoogle: "google", labelApple: "apple", labelLocalAccounts: "local"}[p])
		}
		if contains(n.Providers, "local") {
			email, err := ask.Text("local_admin_email", "Your email address, for your own Covee account (it becomes an admin)", "", checkEmail)
			if err != nil {
				return err
			}
			name, err := ask.Text("local_admin_name", "Your name", strings.Split(email, "@")[0], checkDisplayName)
			if err != nil {
				return err
			}
			n.SignIn.Local = &record.Local{FirstAdmin: strings.ToLower(email), FirstAdminName: name}
		}
	}

	// Secrets.
	store, err := ask.Choose("secrets_store", "Where should Covee keep the copy of record of its keys and secrets", []string{labelSSM, labelLocal}, labelSSM)
	if err != nil {
		return err
	}
	n.Secrets = record.Secrets{Store: "local"}
	if store == labelSSM {
		region, err := ask.Text("aws_region", "AWS region for Parameter Store", "us-east-1", func(v string) error {
			if !regexpRegion.MatchString(v) {
				return errors.New("use a region code such as us-east-1")
			}
			return nil
		})
		if err != nil {
			return err
		}
		if _, err := s.loadAWS(ctx, region); err != nil {
			return err
		}
		n.Secrets = record.Secrets{Store: "ssm", Region: region, Prefix: "/covee/" + n.Name + "/"}
	}

	// Summary.
	s.say("\nSummary for network %s (%s):", n.Name, n.Organization)
	s.say("  • %s will point to %s, using %s", n.Hostname, n.PublicAddress, provider.Describe())
	s.say("  • Devices inside the network get names ending in .%s", n.DNSBaseDomain)
	if p := n.Server.Proxmox; p != nil {
		s.say("  • A new VM %d (%s) on Proxmox node %s: %d CPUs, %d GB memory, %d GB disk on %s, address %s (SSH from %s only)",
			p.VMID, p.Name, p.Node, p.Cores, p.MemoryMiB/1024, p.DiskGiB, p.Storage, n.Server.IPv4CIDR, strings.Join(n.Server.SSHSources, ", "))
	} else {
		s.say("  • Server %s@%s will be dedicated to Covee (SSH from %s only)", n.Server.AdminUser, n.Server.Address, strings.Join(n.Server.SSHSources, ", "))
	}
	if r := n.RestoredFrom; r != nil {
		s.say("  • Rebuilt from the backup %s of %s: its devices, settings and %d approved Google/Apple accounts carry over", filepath.Base(r.File), r.SourceHost, r.Grants)
		s.say("    %s moves to the new server only at the end, once it is running", n.Hostname)
	}
	s.say("  • Sign-in: %s", strings.Join(picked, ", "))
	if n.Secrets.Store == "ssm" {
		s.say("  • Keys and secrets: AWS Parameter Store %s%s* (SecureString), plus a private copy on this computer", n.Secrets.Region+" ", n.Secrets.Prefix)
	} else {
		s.say("  • Keys and secrets: a private folder on this computer only")
	}
	s.say("  • A free Let's Encrypt certificate for %s", strings.Join(certNames(n), " and "))
	if host := consoleHost(n); host != "" {
		s.say("  • The admin console also opens at https://%s, for devices in the network only (a console device joins it)", host)
	}
	if n.DNS.Dynamic {
		s.say("  • The server checks the public address every 5 minutes and updates %s when it changes, using AWS IAM user %s, which may only change that record", n.Hostname, dns.UpdaterUser(n.Name))
	}
	if n.DNS.Host == "route53" {
		s.say("  Nothing here costs money except the server you provide and AWS's usual fees for DNS.")
	} else {
		s.say("  Nothing here costs money except the server you provide.")
	}
	if ok, err := ask.Confirm("start", "Set up now", true); err != nil || !ok {
		if err == nil {
			err = prompt.ErrAborted
		}
		return err
	}
	return s.env.Records.Save(n)
}

// askExisting asks about an existing server and reads its details. It
// returns the address this computer connects from and the server's public
// address. It changes nothing.
func (s *session) askExisting(ctx context.Context, n *record.Network) (net.IP, string, error) {
	ask := s.env.Ask
	var err error
	s.say(`
The network runs on a fresh Ubuntu 24.04 (amd64) server that you can already
reach with ssh, using an account that has sudo. It can be a cloud VM, a
Proxmox VM or a machine at home. It must stay on and be reachable from the
internet on TCP 443 and UDP 3478.`)
	if n.Server.Address, err = ask.Text("server_address", "Server address (the IP or name you use with ssh)", "", func(v string) error {
		if strings.ContainsAny(v, " @'\"`$;") || v == "" {
			return errors.New("type just the address, without a user name")
		}
		return nil
	}); err != nil {
		return nil, "", err
	}
	if n.Server.AdminUser, err = ask.Text("server_user", "SSH user on that server with sudo", "ubuntu", func(v string) error {
		if !regexpUser.MatchString(v) || v == "covee" || v == "root" {
			return errors.New("use your normal administrator account (not root or covee)")
		}
		return nil
	}); err != nil {
		return nil, "", err
	}
	s.n = n
	srv := s.server(false)
	s.say("  Connecting to %s@%s...", n.Server.AdminUser, n.Server.Address)
	dir, err := srv.stageAdmin(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("%w\n  Make sure `ssh %s@%s` works from this computer without a password prompt", err, n.Server.AdminUser, n.Server.Address)
	}
	facts, err := srv.facts(ctx, dir)
	srv.cleanupAdmin(ctx, dir)
	if err != nil {
		return nil, "", err
	}
	if err := facts.Supported(); err != nil {
		return nil, "", err
	}
	if !facts.PasswordlessSudo {
		return nil, "", fmt.Errorf("%s cannot use sudo without a password on that server; allow it (for example with a file in /etc/sudoers.d) and run setup again", n.Server.AdminUser)
	}
	if facts.ServiceUser || facts.Prepared {
		return nil, "", errors.New("that server already has a covee account; setup needs a fresh server")
	}
	dhcp := ""
	if facts.DHCP {
		dhcp = " (from DHCP: reserve it in your router or cloud so it does not change)"
	}
	s.say("  Server %s: %s, address %s on %s%s", facts.Hostname, facts.Pretty, facts.IPv4CIDR, facts.Interface, dhcp)
	n.Server.Interface, n.Server.IPv4CIDR = facts.Interface, facts.IPv4CIDR
	ok, err := ask.Confirm("dedicated", fmt.Sprintf(`This server will be dedicated to Covee. Afterwards SSH accepts only a new "covee"
  account with a key that Covee creates (your %s login will stop working), and the
  firewall admits only SSH from your network plus TCP 443 and UDP 3478. Continue`, n.Server.AdminUser), false)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return nil, "", prompt.ErrAborted
	}
	client := net.ParseIP(facts.SSHClient)
	if client == nil || client.To4() == nil {
		return nil, "", errors.New("could not tell which address you are connecting from")
	}
	return client, facts.PublicIPv4, nil
}

func (s *session) dnsProvider() dns.Provider {
	switch s.n.DNS.Host {
	case "route53":
		if s.zone == nil {
			s.zone = &dns.Route53{API: s.env.NewRoute53(*s.awsCfg), ZoneID: s.n.DNS.ZoneID, Zone: s.n.DNS.Zone, Poll: 5 * time.Second}
		}
		return s.zone
	case "cloudflare":
		return s.cloudflare()
	}
	return &dns.Manual{Ask: s.env.Ask}
}

// cloudflare returns the network's Cloudflare zone, with the token from the
// questions or the secrets store.
func (s *session) cloudflare() *dns.Cloudflare {
	return &dns.Cloudflare{Base: s.env.CloudflareBase, Lookup: s.env.CloudflareLookup, ZoneID: s.n.DNS.ZoneID, Zone: s.n.DNS.Zone,
		Token: func(ctx context.Context) (string, error) {
			if s.cfToken != "" {
				return s.cfToken, nil
			}
			v, err := s.store().Get(ctx, cloudflareSecret)
			if err != nil {
				return "", fmt.Errorf("the Cloudflare token is not available: %w", err)
			}
			return strings.TrimSpace(string(v)), nil
		}}
}

const cloudflareSecret = "cloudflare-dns-token"

// askCloudflareToken asks for the token that lets covee change the zone's
// records. It is read from a file or Parameter Store, or pasted unseen.
func (s *session) askCloudflareToken(ctx context.Context) error {
	ask := s.env.Ask
	s.say(`
Covee changes the records in Cloudflare with an API token. Create one in the
Cloudflare dashboard (Manage Account > Account API Tokens, or My Profile > API
Tokens) from the "Edit zone DNS" template, for the zone that holds %s only.`, s.n.Hostname)
	ref, err := ask.Text("cloudflare_token", "The token: a file holding it or its Parameter Store name, or leave empty to paste it", "", nil)
	if err != nil {
		return err
	}
	var token []byte
	if ref = strings.TrimSpace(ref); ref == "" {
		v, err := ask.Secret("cloudflare_token_value", "Paste the token (it is not shown)", checkToken)
		if err != nil {
			return err
		}
		token = []byte(v)
	} else if token, err = s.readSecretRef(ctx, ref); err != nil {
		return err
	}
	value := strings.TrimSpace(string(token))
	if err := checkToken(value); err != nil {
		return err
	}
	s.cfToken = value
	return nil
}

func checkToken(v string) error {
	v = strings.TrimSpace(v)
	if len(v) < 20 || len(v) > 200 || strings.ContainsAny(v, " \t\r\n") {
		return errors.New("that does not look like a Cloudflare API token")
	}
	return nil
}

// stepCloudflareToken keeps the Cloudflare token in the secrets store, so
// certificate renewals and other computers can use it.
func (s *session) stepCloudflareToken(ctx context.Context) error {
	st := s.store()
	if s.cfToken == "" {
		if _, err := st.Get(ctx, cloudflareSecret); err == nil {
			s.n.DNS.Token = st.Ref(cloudflareSecret)
			return nil
		}
		if err := s.askCloudflareToken(ctx); err != nil {
			return err
		}
	}
	desc := fmt.Sprintf("Cloudflare API token that lets covee change DNS records in %s for the %s network (%s).", s.n.DNS.Zone, s.n.Name, s.n.Hostname)
	if err := st.Put(ctx, cloudflareSecret, []byte(s.cfToken), desc, false); err != nil {
		return err
	}
	s.n.DNS.Token = st.Ref(cloudflareSecret)
	return nil
}

func (s *session) store() *secrets.Store {
	st := &secrets.Store{Local: filepath.Join(s.env.Home, "secrets", s.n.Name)}
	if s.n.Secrets.Store == "ssm" {
		st.SSM = s.env.NewSSM(*s.awsCfg)
		st.Prefix = s.n.Secrets.Prefix
	}
	return st
}

// server returns the SSH logins for the network server. withKey also prepares
// the covee login, which needs the key created during setup.
func (s *session) server(withKey bool) *server {
	known := filepath.Join(s.env.Home, "known_hosts")
	srv := &server{
		admin:   &remote.Host{Address: s.n.Server.Address, User: s.n.Server.AdminUser, KnownHosts: known, Binary: s.env.SSH},
		covee:   &remote.Host{Address: s.n.Server.Address, User: "covee", KnownHosts: known, Binary: s.env.SSH},
		out:     s.env.Out,
		archive: s.archive,
		digest:  s.digest,
	}
	if withKey {
		srv.covee.KeyFile = filepath.Join(s.env.Home, "secrets", s.n.Name, "ssh-private-key")
	}
	return srv
}

// ensureAWS loads AWS settings when the record needs them (on resume).
func (s *session) ensureAWS(ctx context.Context) error {
	if s.n.DNS.Host != "route53" && s.n.Secrets.Store != "ssm" {
		return nil
	}
	region := "us-east-1"
	if s.n.Secrets.Store == "ssm" {
		region = s.n.Secrets.Region
	}
	_, err := s.loadAWS(ctx, region)
	return err
}

type step struct {
	id, title string
	run       func(context.Context) error
}

func (s *session) apply(ctx context.Context) error {
	if err := s.ensureAWS(ctx); err != nil {
		return err
	}
	n := s.n
	if n.Done("source") && !n.Done("start") && n.Payload != s.digest {
		// This CLI carries newer server files than an interrupted setup installed.
		s.say("This version of covee has newer Covee files; they will be installed again.")
		n.Unmark("source", "secrets", "build")
	}
	restored := n.RestoredFrom != nil
	dnsStep := step{"dns", "Point " + n.Hostname + " at " + n.PublicAddress, s.stepDNS}
	var steps []step
	if n.DNS.Host == "cloudflare" {
		steps = append(steps, step{"dns-token", "Keep the Cloudflare token in the secrets store", s.stepCloudflareToken})
	}
	steps = append(steps, step{"ssh-key", "Create the server login key", s.stepKey})
	if restored {
		steps = append(steps, step{"backup-key", "Keep the backup's key in the secrets store", s.stepBackupKey},
			step{"import", "Take the sign-in secrets from the backup", s.stepImport})
	} else {
		for _, p := range n.Providers {
			switch p {
			case "entra":
				steps = append(steps, step{"sign-in-entra", "Set up Microsoft sign-in", s.stepEntra})
			case "google":
				steps = append(steps, step{"sign-in-google", "Set up Google sign-in", s.stepGoogle})
			case "apple":
				steps = append(steps, step{"sign-in-apple", "Set up Apple sign-in", s.stepApple})
			}
		}
		steps = append(steps, dnsStep)
	}
	steps = append(steps, step{"certificate", "Get the certificate for " + n.Hostname, s.stepCertificate})
	if n.Server.Kind == "proxmox" {
		steps = append(steps,
			step{"vm", fmt.Sprintf("Create VM %d on Proxmox", n.Server.Proxmox.VMID), s.stepVM},
			step{"vm-ready", "Wait for the VM to install updates, the firewall and Docker (5-10 minutes)", s.stepVMReady})
	} else {
		steps = append(steps,
			step{"account", "Create the covee account on the server", s.stepAccount},
			step{"system", "Harden the server and install Docker (a few minutes)", s.stepSystem})
	}
	steps = append(steps,
		step{"source", "Install the Covee files", s.stepSource},
		step{"secrets", "Copy keys and secrets to the server", s.stepSecrets},
		step{"build", "Build the Covee services (about 10 minutes)", s.stepBuild})
	if restored {
		steps = append(steps, step{"start", "Restore the backup and start the network", s.stepRestoreStart}, dnsStep)
	} else {
		steps = append(steps, step{"start", "Prepare and start the network", s.stepStart})
		if l := n.SignIn.Local; l != nil && l.FirstAdmin != "" {
			steps = append(steps, step{"local-admin", "Create your Covee account invite", s.stepLocalAdmin})
		}
	}
	steps = append(steps, step{"maintenance", "Schedule the console's key renewal", s.stepMaintenance})
	if n.DNS.Dynamic {
		steps = append(steps, step{"dns-updater", "Keep " + n.Hostname + " pointing at this connection's public address", s.stepDNSUpdater})
	}
	steps = append(steps, step{"verify", "Check the network", s.stepVerify})
	for i, st := range steps {
		if n.Done(st.id) {
			s.say("[%d/%d] %s: done earlier", i+1, len(steps), st.title)
			continue
		}
		s.say("[%d/%d] %s", i+1, len(steps), st.title)
		if err := st.run(ctx); err != nil {
			if errors.Is(err, prompt.ErrAborted) {
				return err
			}
			return fmt.Errorf("%s: %w\nFix the problem, then run `covee setup %s` to continue from this step", st.title, err, n.Name)
		}
		n.Mark(st.id)
		if err := s.env.Records.Save(n); err != nil {
			return err
		}
	}
	s.finish()
	return nil
}

func (s *session) stepKey(ctx context.Context) error {
	st := s.store()
	if _, err := st.Get(ctx, "ssh-private-key"); err == nil {
		s.n.Server.SSHKey = st.Ref("ssh-private-key")
		return nil
	}
	private, _, err := remote.NewKey("covee@" + s.n.Name)
	if err != nil {
		return err
	}
	if err := st.Put(ctx, "ssh-private-key", private, fmt.Sprintf("SSH private key for the covee account on the %s network server (%s).", s.n.Name, s.n.Hostname), false); err != nil {
		return err
	}
	s.n.Server.SSHKey = st.Ref("ssh-private-key")
	return nil
}

func (s *session) stepEntra(ctx context.Context) error {
	token, err := s.env.EntraToken(ctx)
	if err != nil {
		return err
	}
	base := s.env.GraphBase
	if base == "" {
		base = "https://graph.microsoft.com/v1.0"
	}
	g := &entra.Graph{Base: base, Token: token.AccessToken, Settle: 2 * time.Minute}
	plan, err := g.Prepare(ctx, token.TenantID, s.n.Name)
	if err != nil {
		return err
	}
	s.say("  Microsoft tenant %s, signed in as %s. Covee will:", plan.TenantName, plan.Admin)
	for _, line := range plan.Describe() {
		s.say("    - %s", line)
	}
	ok, err := s.env.Ask.Confirm("entra_apply", "Make these changes in "+plan.TenantName, true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	res, err := g.Apply(ctx, plan, s.n.Hostname, guided.CallbackURL(s.n.Hostname, "entra"))
	if err != nil {
		return err
	}
	st := s.store()
	desc := fmt.Sprintf("Microsoft Entra client secret for the %s Covee network (tenant %s, app %s). Expires %s.", s.n.Name, res.TenantName, res.ClientID, res.SecretExpires.Format("2006-01-02"))
	if err := st.Put(ctx, "entra-client-secret", []byte(res.Secret), desc, true); err != nil {
		return err
	}
	s.n.SignIn.Entra = &record.Entra{TenantID: res.TenantID, TenantName: res.TenantName, ClientID: res.ClientID, AppObjectID: res.AppObjectID,
		GroupID: res.GroupID, GroupName: res.GroupName, SecretName: st.Ref("entra-client-secret"), SecretKeyID: res.SecretKeyID, SecretExpires: res.SecretExpires}
	s.say("  Done. You have the Covee Admin role; add colleagues to the %s to let them add devices.", groupLabel(s.n.SignIn.Entra))
	return nil
}

// sameOrganization returns another finished network of this organization that
// already has the given provider, to reuse its registration.
func (s *session) sameOrganization(has func(*record.Network) bool) *record.Network {
	all, err := s.env.Records.List()
	if err != nil {
		return nil
	}
	for _, other := range all {
		if other.Name != s.n.Name && other.Organization == s.n.Organization && has(other) {
			return other
		}
	}
	return nil
}

func (s *session) stepGoogle(ctx context.Context) error {
	open := s.env.Open
	if open == nil {
		open = guided.Open
	}
	st := s.store()
	reuse := ""
	var secret []byte
	if other := s.sameOrganization(func(o *record.Network) bool { return o.SignIn.Google != nil }); other != nil {
		otherStore := &secrets.Store{Local: filepath.Join(s.env.Home, "secrets", other.Name), SSM: st.SSM, Prefix: other.Secrets.Prefix}
		if v, err := otherStore.Get(ctx, "google-client-secret"); err == nil {
			reuse, secret = other.SignIn.Google.ClientID, v
		}
	}
	res, err := guided.Google(s.env.Ask, open, s.n.Hostname, s.n.Name, reuse)
	if err != nil {
		return err
	}
	if reuse != "" {
		res.Secret = string(secret)
	}
	if err := st.Put(ctx, "google-client-secret", []byte(res.Secret), fmt.Sprintf("Google OAuth client secret for the %s Covee network (client %s).", s.n.Name, res.ClientID), true); err != nil {
		return err
	}
	s.n.SignIn.Google = &record.Google{ClientID: res.ClientID, SecretName: st.Ref("google-client-secret")}
	return nil
}

func (s *session) stepApple(ctx context.Context) error {
	open := s.env.Open
	if open == nil {
		open = guided.Open
	}
	res, err := guided.Apple(s.env.Ask, open, s.n.Hostname)
	if err != nil {
		return err
	}
	st := s.store()
	if err := st.Put(ctx, "apple-private-key", res.KeyPEM, fmt.Sprintf("Sign in with Apple private key for the %s Covee network (team %s, key %s, Services ID %s).", s.n.Name, res.TeamID, res.KeyID, res.ServicesID), true); err != nil {
		return err
	}
	s.n.SignIn.Apple = &record.Apple{TeamID: res.TeamID, ServicesID: res.ServicesID, KeyID: res.KeyID, SecretName: st.Ref("apple-private-key")}
	return nil
}

func (s *session) stepDNS(ctx context.Context) error {
	return s.dnsProvider().SetA(ctx, s.n.Hostname, s.n.PublicAddress)
}

func (s *session) certPath() string {
	return filepath.Join(s.env.Home, "certificates", s.n.Name, "fullchain.pem")
}

func (s *session) stepCertificate(ctx context.Context) error {
	return s.obtainCertificate(ctx, true)
}

// obtainCertificate gets a new public certificate and keeps it in the secrets
// store and this computer. The Subscriber Agreement is asked about when a new
// ACME account is needed, or always when askTerms is set.
func (s *session) obtainCertificate(ctx context.Context, askTerms bool) error {
	var ca CertAuthority
	if s.env.CA != nil {
		ca = s.env.CA(s.opts.Staging)
	} else if s.opts.Staging {
		ca = letsEncrypt{cert.LetsEncryptStaging}
	} else {
		ca = letsEncrypt{cert.LetsEncrypt}
	}
	st := s.store()
	account, _ := st.Get(ctx, "acme-account-key")
	if askTerms || len(account) == 0 {
		terms, err := ca.Terms(ctx)
		if err != nil {
			return err
		}
		ok, err := s.env.Ask.Confirm("acme_terms", "The certificate comes from Let's Encrypt. Do you accept its Subscriber Agreement ("+terms+")", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("a certificate is required; it cannot be obtained without accepting the agreement")
		}
	}
	res, accountKey, err := ca.Obtain(ctx, certNames(s.n), account, s.dnsProvider(), s.say)
	if err != nil {
		return err
	}
	if err := st.Put(ctx, "acme-account-key", accountKey, fmt.Sprintf("Let's Encrypt account key used for the %s Covee network's certificate.", s.n.Name), false); err != nil {
		return err
	}
	if err := st.Put(ctx, "tls-private-key", res.KeyPEM, fmt.Sprintf("TLS private key for %s (Covee network %s), certificate valid until %s.", s.n.Hostname, s.n.Name, res.NotAfter.Format("2006-01-02")), true); err != nil {
		return err
	}
	path := s.certPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, res.FullChainPEM, 0o600); err != nil {
		return err
	}
	s.n.Certificate = &record.Certificate{Issuer: res.Issuer, NotAfter: res.NotAfter, KeySecret: st.Ref("tls-private-key"),
		Staging: s.opts.Staging, AccountKey: st.Ref("acme-account-key")}
	s.say("  Certificate issued by %s, valid until %s.", res.Issuer, res.NotAfter.Format("2 January 2006"))
	return nil
}

func (s *session) publicKey(ctx context.Context) (string, error) {
	private, err := s.store().Get(ctx, "ssh-private-key")
	if err != nil {
		return "", err
	}
	return remote.PublicKey(private)
}

func (s *session) stepAccount(ctx context.Context) error {
	pub, err := s.publicKey(ctx)
	if err != nil {
		return err
	}
	srv := s.server(true)
	if err := srv.checkCovee(ctx); err == nil {
		return nil // created in an earlier attempt
	}
	dir, err := srv.stageAdmin(ctx)
	if err != nil {
		return err
	}
	defer srv.cleanupAdmin(ctx, dir)
	if err := srv.account(ctx, dir, pub); err != nil {
		return err
	}
	return srv.checkCovee(ctx)
}

func (s *session) stepSystem(ctx context.Context) error {
	pub, err := s.publicKey(ctx)
	if err != nil {
		return err
	}
	srv := s.server(true)
	dir, err := srv.stageCovee(ctx)
	if err != nil {
		return err
	}
	if err := srv.system(ctx, dir, s.systemConfig(pub)); err != nil {
		return err
	}
	// A new login picks up the docker group membership.
	if err := srv.checkCovee(ctx); err != nil {
		return err
	}
	if _, err := srv.covee.Output(ctx, "docker info --format '{{.ServerVersion}}'", nil); err != nil {
		return fmt.Errorf("Docker is not working for the covee account: %w", err)
	}
	return nil
}

// systemConfig is host_prepare.py's input for this network's server.
func (s *session) systemConfig(publicKey string) map[string]any {
	return map[string]any{"network_interface": s.n.Server.Interface, "ipv4_cidr": s.n.Server.IPv4CIDR,
		"ssh_source_cidrs": s.n.Server.SSHSources, "ssh_public_key": publicKey, "control_host": s.n.Hostname}
}

func (s *session) stepSource(ctx context.Context) error {
	if err := s.server(true).installSource(ctx); err != nil {
		return err
	}
	s.n.Payload = s.digest
	return nil
}

func (s *session) stepSecrets(ctx context.Context) error {
	srv := s.server(true)
	st := s.store()
	chain, err := os.ReadFile(s.certPath())
	if err != nil {
		return fmt.Errorf("the certificate is missing on this computer: %w", err)
	}
	files := []struct {
		path string
		data func() ([]byte, error)
	}{
		{serverSecrets + "/tls/fullchain.pem", func() ([]byte, error) { return chain, nil }},
		{serverSecrets + "/tls/privkey.pem", func() ([]byte, error) { return st.Get(ctx, "tls-private-key") }},
	}
	for _, p := range s.n.Providers {
		if p == "local" {
			continue
		}
		name := providerSecret[p]
		files = append(files, struct {
			path string
			data func() ([]byte, error)
		}{providerFile(p, s.n), func() ([]byte, error) { return st.Get(ctx, name) }})
	}
	for _, f := range files {
		data, err := f.data()
		if err != nil {
			return err
		}
		if err := srv.putFile(ctx, f.path, data, "400"); err != nil {
			return err
		}
	}
	config, err := deploymentConfig(s.n, nil)
	if err != nil {
		return err
	}
	return srv.putFile(ctx, serverConfig, config, "600")
}

func (s *session) stepBuild(ctx context.Context) error {
	srv := s.server(true)
	if err := srv.deploy(ctx, "build --with-identity"); err != nil {
		return srv.buildFailure(ctx, err)
	}
	return nil
}

// buildFailure adds the end of the newest build log to a failed build. The
// deployment tool hides command output in case it holds credentials; build
// logs hold only compiler and test output.
func (s *server) buildFailure(ctx context.Context, err error) error {
	out, logErr := s.covee.Output(ctx, "f=$(ls -t "+serverSource+"/.cache/covee/deploy/headscale-build/*.log 2>/dev/null | head -1); [ -n \"$f\" ] && echo \"== $(basename \"$f\")\" && tail -n 15 \"$f\"", nil)
	if logErr != nil || len(strings.TrimSpace(string(out))) == 0 {
		return err
	}
	return fmt.Errorf("%w\n  Newest build log:\n%s", err, indentLines(string(out)))
}

func indentLines(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

func (s *session) stepStart(ctx context.Context) error {
	srv := s.server(true)
	if s.n.Runtime != "" {
		if err := srv.deploy(ctx, "validate --directory "+remote.Quote(s.n.Runtime)); err != nil {
			s.say("  The runtime prepared earlier is incomplete; preparing a new one.")
			s.n.Runtime = ""
		}
	}
	if s.n.Runtime == "" {
		dir, err := srv.nextRuntime(ctx)
		if err != nil {
			return err
		}
		s.n.Runtime = dir
		if err := s.env.Records.Save(s.n); err != nil {
			return err
		}
		if err := srv.deploy(ctx, "prepare --config "+serverConfig+" --directory "+remote.Quote(dir)); err != nil {
			return err
		}
		if err := srv.deploy(ctx, "validate --directory "+remote.Quote(dir)); err != nil {
			return err
		}
	}
	return srv.deploy(ctx, "up --directory "+remote.Quote(s.n.Runtime))
}

func (s *session) stepVerify(ctx context.Context) error {
	srv := s.server(true)
	want := "https://" + s.n.Hostname + "/identity"
	issuer, err := srv.localIssuer(ctx, s.n.Hostname)
	if err != nil {
		return fmt.Errorf("the sign-in service does not answer on the server: %w", err)
	}
	if issuer != want {
		return fmt.Errorf("the sign-in service reports %q instead of %q", issuer, want)
	}
	s.say("  On the server: the network answers at https://%s.", s.n.Hostname)
	serverIP, _, _ := net.ParseCIDR(s.n.Server.IPv4CIDR)
	if !serverIP.Equal(net.ParseIP(s.n.PublicAddress)) {
		s.say("  Reminder: forward TCP 443 and UDP 3478 from %s to %s on your router or firewall.", s.n.PublicAddress, serverIP)
	}
	if err := s.outsideCheck(ctx, want); err != nil {
		s.say("  From this computer: not reachable yet (%v).", err)
		s.say("  This can be normal inside the same network as the server. Check from a phone on")
		s.say("  mobile data: https://%s/identity/.well-known/openid-configuration should open.", s.n.Hostname)
	} else {
		s.say("  From this computer: reachable at https://%s.", s.n.Hostname)
	}
	return nil
}

func (s *session) outsideCheck(ctx context.Context, want string) error {
	client := s.env.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
		if s.n.Certificate != nil && s.n.Certificate.Staging {
			// Staging certificates are untrusted by design; only reachability is checked.
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", want+"/.well-known/openid-configuration", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var d struct{ Issuer string }
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d) != nil || d.Issuer != want {
		return fmt.Errorf("unexpected answer (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// groupLabel names the Microsoft group whose members may add devices.
func groupLabel(e *record.Entra) string {
	if e.GroupName != "" {
		return fmt.Sprintf("%q group", e.GroupName)
	}
	return "Microsoft group " + e.GroupID
}

func (s *session) finish() {
	n := s.n
	s.say("\nNetwork %s is running at https://%s.", n.Name, n.Hostname)
	if n.SignIn.Entra != nil {
		s.say("  • Microsoft: you are already a Covee Admin. Colleagues in the %s can add devices.", groupLabel(n.SignIn.Entra))
	}
	if r := n.RestoredFrom; r != nil && r.Grants > 0 {
		s.say("  • The backup's %d approved Google/Apple accounts carried over; approve new ones with `covee grant %s`.", r.Grants, n.Name)
	} else if n.SignIn.Google != nil || n.SignIn.Apple != nil {
		s.say("  • Google or Apple accounts need approval once: run `covee console %s`, sign in,", n.Name)
		s.say("    copy the ID shown on the \"not approved\" page, then run")
		s.say("    `covee grant %s --provider google --subject <ID>` (or --provider apple).", n.Name)
	}
	s.say("  • Open the admin console any time with `covee console %s`.", n.Name)
	if r := n.RestoredFrom; r != nil {
		s.say("  • Now stop the old server of %s so devices cannot reconnect to the outdated copy.", r.SourceHost)
	}
	if n.Certificate != nil {
		s.say("  • The certificate is valid until %s; renew it before then with `covee cert renew %s`.", n.Certificate.NotAfter.Format("2 January 2006"), n.Name)
	}
}
