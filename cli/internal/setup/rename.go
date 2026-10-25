package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"covee.io/cli/internal/dns"
	"covee.io/cli/internal/entra"
	"covee.io/cli/internal/guided"
	"covee.io/cli/internal/payload"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
)

// A network can move to a new public hostname and a new name suffix for its
// devices, for example from a hostname on someone else's domain to one on the
// owner's own. Everything that names the new hosts is prepared first, while
// the network keeps running: the DNS record, each sign-in provider's return
// address and the certificate. The server then switches in one restart. People
// keep their accounts and devices keep their keys; each device needs the new
// address once.

// While a provider takes up a new return address.
var (
	redirectPoll = 15 * time.Second
	redirectWait = 20 * time.Minute
)

// Rename moves a running network to hostname, with devices named under meshDomain.
func Rename(ctx context.Context, env *Env, name, hostname, meshDomain string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	old := *s.n
	if meshDomain == "" {
		meshDomain = defaultMeshDomain(hostname)
	}
	if err := checkHostname(hostname); err != nil {
		return err
	}
	if err := checkMeshDomain(hostname, meshDomain); err != nil {
		return fmt.Errorf("the device name suffix %s: %w", meshDomain, err)
	}
	if hostname == old.Hostname && meshDomain == old.DNSBaseDomain {
		s.say("Network %s already answers at %s, with devices named under %s.", old.Name, hostname, meshDomain)
		return nil
	}
	if old.SignIn.Local != nil {
		return fmt.Errorf("Covee accounts sign in with passkeys that belong to %s; turn them off with `covee auth remove %s accounts` before renaming", old.Hostname, old.Name)
	}
	archive := env.Archive
	if archive == nil {
		archive = payload.Archive
	}
	if s.archive, s.digest, err = archive(); err != nil {
		return err
	}
	if old.Payload != s.digest {
		return fmt.Errorf("network %s runs older Covee files; run `covee update %s` first", old.Name, old.Name)
	}

	renamed := old
	renamed.Hostname, renamed.DNSBaseDomain = hostname, meshDomain
	var provider dns.Provider = &dns.Manual{Ask: env.Ask}
	var zone *dns.Route53
	switch old.DNS.Host {
	case "route53":
		if zone, err = dns.FindZone(ctx, env.NewRoute53(*s.awsCfg), hostname); err != nil {
			return err
		}
		renamed.DNS.ZoneID, renamed.DNS.Zone = zone.ZoneID, zone.Zone
		provider = zone
	case "cloudflare":
		cf, err := dns.FindCloudflareZone(ctx, s.cloudflare(), hostname)
		if err != nil {
			return err
		}
		renamed.DNS.ZoneID, renamed.DNS.Zone = cf.ZoneID, cf.Zone
		provider = cf
	}
	if z := renamed.DNS.Zone; old.DNS.Host != "manual" {
		if host := consoleHost(&renamed); host != "" && !strings.HasSuffix(host, "."+z) {
			return fmt.Errorf("the console's name %s is outside the DNS zone %s, so its certificate cannot be issued; choose a device name suffix inside %s", host, z, z)
		}
	}
	// The address updater keeps the old name current, so it holds the connection's address.
	address := old.PublicAddress
	if current, err := s.dnsProvider().CurrentA(ctx, old.Hostname); err == nil && len(current) == 1 && net.ParseIP(current[0]).To4() != nil {
		address = current[0]
	}
	renamed.PublicAddress = address

	s.say("Network %s moves from %s to %s:", old.Name, old.Hostname, hostname)
	s.say("  • %s will point to %s, using %s", hostname, address, provider.Describe())
	s.say("  • Devices get names ending in .%s instead of .%s", meshDomain, old.DNSBaseDomain)
	if host := consoleHost(&renamed); host != "" {
		s.say("  • The admin console inside the network moves to https://%s", host)
	}
	var names []string
	for _, p := range old.Providers {
		names = append(names, providerLabel[p])
	}
	s.say("  • %s sign-in also accept the new address; people keep their accounts", strings.Join(names, ", "))
	s.say("  • A new certificate names the new hosts, and the services restart once")
	if old.DNS.Updater != nil {
		s.say("  • The address updater looks after %s from then on", hostname)
	}
	s.say("Afterwards each device needs the new address once. It keeps its sign-in.")
	ok, err := env.Ask.Confirm("rename", "Move "+old.Name+" to "+hostname, true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}

	s.say("[1/5] Point %s at %s", hostname, address)
	existing, err := provider.CurrentA(ctx, hostname)
	if err != nil {
		return err
	}
	if !(len(existing) == 1 && existing[0] == address) {
		if len(existing) > 0 {
			ok, err := env.Ask.Confirm("replace_dns", fmt.Sprintf("%s already points to %s. Replace that record", hostname, strings.Join(existing, ", ")), false)
			if err != nil {
				return err
			}
			if !ok {
				return prompt.ErrAborted
			}
		}
		if err := provider.SetA(ctx, hostname, address); err != nil {
			return err
		}
	}

	s.say("[2/5] Let sign-in return to %s", hostname)
	if err := s.renameSignIn(ctx, hostname); err != nil {
		return err
	}

	s.say("[3/5] Get a certificate for the new names")
	s.n = &renamed
	if zone != nil {
		s.zone = zone
	}
	if c := renamed.Certificate; c != nil {
		s.opts.Staging = c.Staging
	}
	if err := s.obtainCertificate(ctx, false); err != nil {
		return err
	}

	s.say("[4/5] Switch the network to the new names (the services restart once)")
	srv := s.server(true)
	if err := s.switchNames(ctx, srv, &old); err != nil {
		return err
	}
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	if err := s.syncConfig(ctx, srv); err != nil {
		return err
	}

	// The network already runs at the new name, so the remaining steps go on even if the updater fails.
	var updaterErr error
	if renamed.DNS.Updater != nil {
		s.say("[5/5] Let the address updater look after %s", hostname)
		if updaterErr = s.enableUpdater(ctx, srv); updaterErr == nil {
			if err := env.Records.Save(s.n); err != nil {
				return err
			}
		} else {
			s.say("  The address updater could not be moved yet: %v", updaterErr)
		}
	} else {
		s.say("[5/5] The address updater is off; nothing to move")
	}
	if old.Hostname != hostname {
		s.removeOldRecord(ctx, &old)
	}

	s.say("\nNetwork %s now answers at https://%s.", old.Name, hostname)
	s.say("Each device needs the new address once, and keeps its sign-in:")
	s.say("  • Covee app (Mac, iPhone): Disconnect, change the coordinator address to https://%s, and Connect.", hostname)
	s.say("  • Linux (Tailscale client): sudo tailscale down && sudo tailscale up --login-server=https://%s", hostname)
	s.say("    If it asks for the settings the device already has, run the complete command it shows.")
	if host := consoleHost(s.n); host != "" {
		s.say("  • The admin console inside the network is now https://%s.", host)
	}
	s.say("The sign-in providers still accept %s as well; remove that address there once no device uses it.", old.Hostname)
	if updaterErr != nil {
		return fmt.Errorf("the network runs at %s, but the address updater still needs moving: run `covee dns auto %s`", hostname, old.Name)
	}
	return nil
}

// renameSignIn makes each sign-in provider accept the new return address,
// keeping the current one so sign-in works until the switch.
func (s *session) renameSignIn(ctx context.Context, hostname string) error {
	n := s.n
	open := s.env.Open
	if open == nil {
		open = guided.Open
	}
	if e := n.SignIn.Entra; e != nil {
		token, err := s.env.EntraToken(ctx)
		if err != nil {
			return err
		}
		if token.TenantID != e.TenantID {
			return fmt.Errorf("the Azure CLI is signed in to tenant %s, not %s (%s); sign in to that tenant and run this again", token.TenantID, e.TenantID, e.TenantName)
		}
		base := s.env.GraphBase
		if base == "" {
			base = "https://graph.microsoft.com/v1.0"
		}
		g := &entra.Graph{Base: base, Token: token.AccessToken, Settle: 2 * time.Minute}
		added, err := g.AddRedirectURI(ctx, e.AppObjectID, guided.CallbackURL(hostname, "entra"))
		if err != nil {
			return err
		}
		if added {
			s.say("  Microsoft: added the new address to the Covee app.")
		} else {
			s.say("  Microsoft: the Covee app already has the new address.")
		}
	}
	if g := n.SignIn.Google; g != nil {
		redirect := guided.CallbackURL(hostname, "google")
		accepts := func() (bool, error) { return guided.GoogleAccepts(ctx, s.env.HTTP, g.ClientID, redirect) }
		if ok, err := accepts(); err != nil || !ok {
			if err := guided.GoogleAddRedirect(s.env.Ask, open, g.ClientID, redirect); err != nil {
				return err
			}
			if err := s.waitForRedirect(ctx, "Google", accepts); err != nil {
				return err
			}
		} else {
			s.say("  Google: the client already accepts the new address.")
		}
	}
	if a := n.SignIn.Apple; a != nil {
		redirect := guided.CallbackURL(hostname, "apple")
		accepts := func() (bool, error) { return guided.AppleAccepts(ctx, s.env.HTTP, a.ServicesID, redirect) }
		if ok, err := accepts(); err != nil || !ok {
			if err := guided.AppleAddRedirect(s.env.Ask, open, a.ServicesID, hostname, redirect); err != nil {
				return err
			}
			if err := s.waitForRedirect(ctx, "Apple", accepts); err != nil {
				return err
			}
		} else {
			s.say("  Apple: the Services ID already accepts the new address.")
		}
	}
	return nil
}

// waitForRedirect waits until a provider takes up a return address the admin
// added. When the provider cannot be asked, the admin's word is taken.
func (s *session) waitForRedirect(ctx context.Context, provider string, accepts func() (bool, error)) error {
	deadline := time.Now().Add(redirectWait)
	for waiting := false; ; {
		ok, err := accepts()
		if err != nil {
			s.say("  Could not ask %s whether it accepts the new address (%v); continuing as you confirmed.", provider, err)
			return nil
		}
		if ok {
			s.say("  %s accepts the new address.", provider)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s still does not accept the new address; check that it was saved, then run this again (nothing has changed on the network)", provider)
		}
		if !waiting {
			s.say("  Waiting until %s accepts it; this can take a few minutes...", provider)
			waiting = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(redirectPoll):
		}
	}
}

// switchNames installs the new certificate and moves the running network to
// s.n's names. The server restores everything itself if the switch fails.
func (s *session) switchNames(ctx context.Context, srv *server, old *record.Network) error {
	n := s.n
	chain, err := os.ReadFile(s.certPath())
	if err != nil {
		return err
	}
	key, err := s.store().Get(ctx, "tls-private-key")
	if err != nil {
		return err
	}
	next := serverSecrets + "/tls/next-"
	if err := srv.putFile(ctx, next+"fullchain.pem", chain, "400"); err != nil {
		return err
	}
	if err := srv.putFile(ctx, next+"privkey.pem", key, "400"); err != nil {
		return err
	}
	out, err := srv.deployResult(ctx, "rename --control-host "+remote.Quote(n.Hostname)+
		" --dns-base-domain "+remote.Quote(n.DNSBaseDomain)+" --cert "+next+"fullchain.pem --key "+next+"privkey.pem --directory "+remote.Quote(n.Runtime))
	if err != nil {
		_, _ = srv.covee.Output(ctx, "rm -f "+next+"fullchain.pem "+next+"privkey.pem", nil)
		return fmt.Errorf("the network kept %s (run this again once the problem is fixed): %w", old.Hostname, err)
	}
	var result struct {
		Control       string `json:"control"`
		AccountsMoved int    `json:"accounts_moved"`
	}
	if err := lastJSON(out, &result); err != nil || result.Control != "https://"+n.Hostname {
		return errors.New("the server did not confirm the new names; check it with `covee status " + n.Name + "`")
	}
	// The new certificate is now the one the server keeps for a future preparation.
	if _, err := srv.covee.Output(ctx, "mv -f "+next+"fullchain.pem "+serverSecrets+"/tls/fullchain.pem && mv -f "+next+"privkey.pem "+serverSecrets+"/tls/privkey.pem", nil); err != nil {
		return err
	}
	want := "https://" + n.Hostname + "/identity"
	if issuer, err := srv.localIssuer(ctx, n.Hostname); err != nil || issuer != want {
		return fmt.Errorf("the network did not answer at %s after the switch (%v); check it with `covee status %s`", n.Hostname, err, n.Name)
	}
	s.say("  The network answers at https://%s; %d account(s) moved with it.", n.Hostname, result.AccountsMoved)
	if consoleHost(n) != "" {
		if state := srv.consoleNodeState(ctx); state != "healthy" {
			s.say("  The console device is %s; it usually reconnects within a minute.", state)
		}
	}
	return nil
}

// removeOldRecord offers to delete the old hostname's record: nothing uses it
// now, and nothing keeps it current, so it would come to point at an address
// that may belong to someone else.
func (s *session) removeOldRecord(ctx context.Context, old *record.Network) {
	var remove func(context.Context, string) error
	switch old.DNS.Host {
	case "route53":
		remove = (&dns.Route53{API: s.env.NewRoute53(*s.awsCfg), ZoneID: old.DNS.ZoneID, Zone: old.DNS.Zone, Poll: 5 * time.Second}).RemoveA
	case "cloudflare":
		cf := s.cloudflare()
		cf.ZoneID, cf.Zone = old.DNS.ZoneID, old.DNS.Zone
		remove = cf.RemoveA
	default:
		s.say("You can now delete the record %s at your DNS host.", old.Hostname)
		return
	}
	ok, err := s.env.Ask.Confirm("remove_old_record", fmt.Sprintf("Delete the old record %s? Nothing uses it now, and nothing keeps it current", old.Hostname), true)
	if err != nil || !ok {
		s.say("The record %s stays; delete it once you no longer need it.", old.Hostname)
		return
	}
	if err := remove(ctx, old.Hostname); err != nil {
		s.say("Could not delete %s (%v); delete it at your DNS host by hand.", old.Hostname, err)
		return
	}
	s.say("Deleted the old record %s.", old.Hostname)
}
