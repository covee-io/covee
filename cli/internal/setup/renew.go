package setup

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"covee.io/cli/internal/remote"
)

// CertRenew gets a new public certificate, installs it on the network and
// reissues the network's 90-day internal certificates. The services restart
// once; devices reconnect within a minute.
func CertRenew(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	if c := s.n.Certificate; c != nil {
		s.opts.Staging = c.Staging
	}
	s.say("[1/3] Get a new certificate for %s", s.n.Hostname)
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
	s.say("[2/3] Install it and renew the internal certificates (the services restart once)")
	if err := srv.putFile(ctx, serverSecrets+"/tls/fullchain.pem", chain, "400"); err != nil {
		return err
	}
	if err := srv.putFile(ctx, serverSecrets+"/tls/privkey.pem", key, "400"); err != nil {
		return err
	}
	out, err := srv.covee.Output(ctx, "cd "+serverSource+" && python3 scripts/deploy.py renew-certificates --cert "+serverSecrets+"/tls/fullchain.pem --key "+serverSecrets+"/tls/privkey.pem --directory "+remote.Quote(s.n.Runtime), nil)
	if err != nil {
		return err
	}
	var result struct {
		PublicDaysLeft     int    `json:"public_days_left"`
		InternalDaysLeft   int    `json:"internal_days_left"`
		InternalCADaysLeft int    `json:"internal_ca_days_left"`
		AdminCertificate   string `json:"admin_certificate"`
	}
	if err := lastJSON(out, &result); err != nil {
		return err
	}
	s.say("[3/3] Check what the network now serves")
	served, err := srv.servedDaysLeft(ctx, s.n.Hostname)
	if err != nil {
		return err
	}
	if served < result.PublicDaysLeft-1 {
		return fmt.Errorf("the network still serves a certificate valid for %d days", served)
	}
	if issuer, err := srv.localIssuer(ctx, s.n.Hostname); err != nil || issuer != "https://"+s.n.Hostname+"/identity" {
		return fmt.Errorf("the network did not answer correctly after the restart (%v); check it with `covee status %s`", err, s.n.Name)
	}
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	s.say("Done: the public certificate is valid for %d days and the internal certificates for %d days.", result.PublicDaysLeft, result.InternalDaysLeft)
	if result.InternalCADaysLeft < 60 {
		s.say("Note: the network's internal CA expires in %d days and needs a new runtime before then.", result.InternalCADaysLeft)
	}
	return nil
}

// servedDaysLeft reads the certificate the gateway serves for host.
func (s *server) servedDaysLeft(ctx context.Context, host string) (int, error) {
	cmd := "echo | openssl s_client -connect 127.0.0.1:443 -servername " + remote.Quote(host) + " 2>/dev/null | openssl x509 -noout -checkend 0 >/dev/null && " +
		"echo | openssl s_client -connect 127.0.0.1:443 -servername " + remote.Quote(host) + " 2>/dev/null | openssl x509 -noout -enddate | sed 's/notAfter=//' | xargs -I{} date -d {} +%s"
	out, err := s.covee.Output(ctx, cmd, nil)
	if err != nil {
		return 0, fmt.Errorf("reading the served certificate: %w", err)
	}
	return secondsToDays(strings.TrimSpace(string(out)))
}

// certificateDays reports days left for the runtime's certificates.
func (s *server) certificateDays(ctx context.Context, runtime string) (map[string]int, error) {
	out, err := s.covee.Output(ctx, "cd "+remote.Quote(runtime)+" && for f in ingress-control headscale-internal internal-ca; do printf '%s ' $f; openssl x509 -in $f.crt -noout -enddate | sed 's/notAfter=//' | xargs -I{} date -d {} +%s; done", nil)
	if err != nil {
		return nil, err
	}
	days := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if d, err := secondsToDays(value); err == nil {
			days[name] = d
		}
	}
	return days, nil
}

func secondsToDays(value string) (int, error) {
	end, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unexpected date %q", value)
	}
	return int((end - nowUnix()) / 86400), nil
}

var nowUnix = func() int64 { return timeNow().Unix() }

var timeNow = time.Now
