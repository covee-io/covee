package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"covee.io/cli/internal/payload"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/remote"
)

// The admin console can also be served inside the network: a console device
// joins the network and passes port 443 to the console, so devices in the
// network open https://console.<mesh domain> while nothing new is reachable
// from the internet. The public certificate then names that host too.

// consoleZoneOK reports whether the console host can be proved in the network's DNS zone.
func (s *session) consoleZoneOK() bool {
	host := "console." + s.n.DNSBaseDomain
	return s.n.DNS.Zone == "" || strings.HasSuffix(host, "."+s.n.DNS.Zone)
}

// ConsoleInNetwork turns on the in-network console for a running network.
func ConsoleInNetwork(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	host := "console." + s.n.DNSBaseDomain
	if s.n.ConsoleInNetwork {
		s.say("The admin console of %s is already at https://%s for devices in the network.", s.n.Name, host)
		return nil
	}
	if !s.consoleZoneOK() {
		return fmt.Errorf("%s is outside the DNS zone %s, so its certificate cannot be issued", host, s.n.DNS.Zone)
	}
	archive := env.Archive
	if archive == nil {
		archive = payload.Archive
	}
	if s.archive, s.digest, err = archive(); err != nil {
		return err
	}
	if s.n.Payload != s.digest {
		return fmt.Errorf("network %s runs older Covee files; run `covee update %s` first", s.n.Name, s.n.Name)
	}
	ok, err := env.Ask.Confirm("console_in_network", fmt.Sprintf("Open the admin console from devices in network %s, at https://%s? A console device joins the network, and devices outside it cannot reach the console. The certificate is renewed to name it, and the services restart once", s.n.Name, host), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	if c := s.n.Certificate; c != nil {
		s.opts.Staging = c.Staging
	}
	s.n.ConsoleInNetwork = true
	s.say("[1/3] Get a certificate for %s and %s", s.n.Hostname, host)
	if err := s.obtainCertificate(ctx, false); err != nil {
		return err
	}
	srv := s.server(true)
	chain, err := os.ReadFile(s.certPath())
	if err != nil {
		return err
	}
	key, err := s.store().Get(ctx, "tls-private-key")
	if err != nil {
		return err
	}
	s.say("[2/3] Install it and start the console device (the services restart once)")
	if err := srv.putFile(ctx, serverSecrets+"/tls/fullchain.pem", chain, "400"); err != nil {
		return err
	}
	if err := srv.putFile(ctx, serverSecrets+"/tls/privkey.pem", key, "400"); err != nil {
		return err
	}
	// The record's certificate already names both hosts; keep it even if the next step fails.
	s.n.ConsoleInNetwork = false
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	out, err := srv.covee.Output(ctx, "cd "+serverSource+" && python3 scripts/deploy.py enable-console-network --cert "+serverSecrets+"/tls/fullchain.pem --key "+serverSecrets+"/tls/privkey.pem --directory "+remote.Quote(s.n.Runtime), nil)
	if err != nil {
		return err
	}
	var result struct {
		Console string `json:"console"`
	}
	if err := lastJSON(out, &result); err != nil || result.Console != "https://"+host {
		return errors.New("the server did not confirm the in-network console")
	}
	s.n.ConsoleInNetwork = true
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	if err := s.syncConfig(ctx, srv); err != nil {
		return err
	}
	s.say("[3/3] Check the console device")
	if state := srv.consoleNodeState(ctx); state != "healthy" {
		s.say("  The console device is %s; it usually joins within a minute. Check it later with `covee status %s`.", state, s.n.Name)
	}
	s.say("The admin console of %s is now at https://%s for devices in the network, such as this computer while the Covee app is connected.", s.n.Name, host)
	return nil
}

// consoleNodeState is the console device container's health on the server.
func (s *server) consoleNodeState(ctx context.Context) string {
	out, err := s.covee.Output(ctx, "docker ps --filter name=console-node --format '{{.Status}}' | head -1", nil)
	status := strings.TrimSpace(string(out))
	switch {
	case err != nil || status == "":
		return "not running"
	case strings.Contains(status, "(healthy)"):
		return "healthy"
	case strings.Contains(status, "starting"):
		return "starting"
	}
	return "not connected"
}
