package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"covee.io/cli/internal/remote"
)

var subjectRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)

// open loads a finished or partly finished network for a management command.
func open(ctx context.Context, env *Env, name string) (*session, error) {
	n, err := env.Records.Load(name)
	if err != nil {
		return nil, err
	}
	s := &session{env: env, n: n}
	if _, err := os.Stat(filepath.Join(env.Home, "secrets", n.Name, "ssh-private-key")); err != nil {
		if err := s.ensureAWS(ctx); err != nil {
			return nil, err
		}
		if _, err := s.store().Get(ctx, "ssh-private-key"); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *session) requireRunning() error {
	if s.n.Runtime == "" || !s.n.Done("start") {
		return fmt.Errorf("network %s is not running yet; run `covee setup %s` to finish it", s.n.Name, s.n.Name)
	}
	return nil
}

// List prints every network this computer manages.
func List(env *Env) error {
	all, err := env.Records.List()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		env.Ask.Say("No networks yet. Run `covee setup` to create one.")
		return nil
	}
	for _, n := range all {
		state := "running"
		if !n.Done("verify") {
			state = "setup not finished"
		}
		env.Ask.Say("%-16s %-28s %-20s %s  (%s)", n.Name, n.Hostname, n.Organization, strings.Join(n.Providers, ","), state)
	}
	return nil
}

// Status shows a network's services and upcoming expiry dates.
func Status(ctx context.Context, env *Env, name string) error {
	s, err := open(ctx, env, name)
	if err != nil {
		return err
	}
	n := s.n
	s.say("Network %s (%s), organization %s", n.Name, n.Hostname, n.Organization)
	s.say("  Server: %s (runtime %s)", n.Server.Address, n.Runtime)
	now := time.Now()
	days := func(t time.Time) string {
		return fmt.Sprintf("%s, in %d days", t.Format("2006-01-02"), int(t.Sub(now).Hours()/24))
	}
	if c := n.Certificate; c != nil {
		note := ""
		if c.Staging {
			note = " (test certificate, not trusted by browsers)"
		}
		s.say("  Certificate expires %s%s", days(c.NotAfter), note)
	}
	if e := n.SignIn.Entra; e != nil {
		if e.SecretExpires.IsZero() {
			// A network restored from a backup does not know when its secret expires.
			s.say("  Microsoft client secret expiry: unknown (see the app's Certificates & secrets in Entra)")
		} else {
			s.say("  Microsoft client secret expires %s", days(e.SecretExpires))
		}
	}
	if err := s.requireRunning(); err != nil {
		return err
	}
	srv := s.server(true)
	if n.DNS.Updater != nil {
		s.say("  Address updater: %s", s.updaterStatus(ctx, srv))
	}
	if host := consoleHost(n); host != "" {
		s.say("  Console in the network: https://%s (console device %s)", host, srv.consoleNodeState(ctx))
	}
	if n.Gateway {
		s.say("  Gateway: device %s; choose what goes through it on the console's Gateway page", srv.containerState(ctx, "gateway"))
	}
	if days, err := srv.certificateDays(ctx, n.Runtime); err == nil {
		labels := map[string]string{"ingress-control": "Public certificate on the server", "headscale-internal": "Internal certificates", "internal-ca": "Internal CA"}
		for _, name := range []string{"ingress-control", "headscale-internal", "internal-ca"} {
			d, ok := days[name]
			if !ok {
				continue
			}
			advice := ""
			if name != "internal-ca" && d < 30 {
				advice = fmt.Sprintf(": renew now with `covee cert renew %s`", n.Name)
			} else if name == "internal-ca" && d < 60 {
				advice = ": needs a new runtime before then"
			}
			s.say("  %s: %d days left%s", labels[name], d, advice)
		}
	}
	return srv.deploy(ctx, "status --directory "+remote.Quote(n.Runtime))
}

// consolePort is fixed: the console only accepts https://localhost:8444, the
// address registered for its sign-in.
const consolePort = 8444

// Console opens the private admin console through an SSH tunnel.
func Console(ctx context.Context, env *Env, name string) error {
	port := consolePort
	s, err := open(ctx, env, name)
	if err != nil {
		return err
	}
	if err := s.requireRunning(); err != nil {
		return err
	}
	if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		return fmt.Errorf("port %d on this computer is in use, probably by another console tunnel; close it first (the console only works on this port)", port)
	} else {
		l.Close()
	}
	srv := s.server(true)
	done := make(chan error, 1)
	go func() { done <- srv.covee.Tunnel(ctx, port, 8444) }()
	url := fmt.Sprintf("https://localhost:%d", port)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			c.Close()
			break
		}
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("the tunnel closed")
			}
			return fmt.Errorf("opening the console tunnel: %w", err)
		default:
		}
		if time.Now().After(deadline) {
			return errors.New("the console tunnel did not open")
		}
		time.Sleep(300 * time.Millisecond)
	}
	s.say("The admin console of %s is open at %s", s.n.Name, url)
	s.say("Your browser warns about its private certificate the first time; that is expected.")
	s.say("Press Ctrl-C here to close it.")
	if env.Open != nil {
		env.Open(url)
	}
	return <-done
}

// Grant approves a Google or Apple account by its verified subject.
func Grant(ctx context.Context, env *Env, name, provider, subject, role string, enroll bool) error {
	s, err := open(ctx, env, name)
	if err != nil {
		return err
	}
	if err := s.requireRunning(); err != nil {
		return err
	}
	if provider != "google" && provider != "apple" {
		return errors.New("only Google and Apple accounts are approved here; Microsoft access is managed with the Covee roles and group in your tenant")
	}
	enabled := (provider == "google" && s.n.SignIn.Google != nil) || (provider == "apple" && s.n.SignIn.Apple != nil)
	if !enabled {
		return fmt.Errorf("%s sign-in is not enabled on network %s", provider, s.n.Name)
	}
	if !subjectRE.MatchString(subject) {
		return errors.New("the ID must be copied exactly from the \"not approved\" page")
	}
	switch role {
	case "admin":
		role = "Covee.Admin"
	case "reader":
		role = "Covee.Reader"
	case "none":
		role = ""
	default:
		return errors.New("role must be admin, reader or none")
	}
	if role == "" && !enroll {
		return errors.New("grant at least console access or adding devices")
	}
	srv := s.server(true)
	grants, err := srv.readGrants(ctx, s.n.Runtime)
	if err != nil {
		return err
	}
	entry := map[string]any{"provider": provider, "subject": subject, "role": role, "enroll": enroll}
	replaced := false
	for i, g := range grants {
		if g["provider"] == provider && g["subject"] == subject {
			grants[i], replaced = entry, true
		}
	}
	if !replaced {
		grants = append(grants, entry)
	}
	data, err := json.MarshalIndent(grants, "", "  ")
	if err != nil {
		return err
	}
	if err := srv.putFile(ctx, serverGrants, append(data, '\n'), "600"); err != nil {
		return err
	}
	if err := srv.deploy(ctx, "update-identity-grants --config "+serverGrants+" --directory "+remote.Quote(s.n.Runtime)); err != nil {
		return err
	}
	s.say("Approved the %s account %s (%d accounts approved in total). Reload the sign-in page.", provider, subject, len(grants))
	return nil
}
