package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
)

// ProviderKind maps the names people type to provider IDs.
func ProviderKind(name string) (string, error) {
	switch strings.ToLower(name) {
	case "microsoft", "entra", "office365", "office-365", "m365":
		return "entra", nil
	case "google":
		return "google", nil
	case "apple":
		return "apple", nil
	case "local", "accounts", "covee", "passkey", "passkeys":
		return "local", nil
	}
	return "", fmt.Errorf("unknown sign-in method %q; use microsoft, google, apple or accounts", name)
}

var providerLabel = map[string]string{"entra": "Microsoft", "google": "Google", "apple": "Apple", "local": "Covee account"}
var providerSecret = map[string]string{"entra": "entra-client-secret", "google": "google-client-secret", "apple": "apple-private-key"}

// opened loads a running network with everything management commands need.
func opened(ctx context.Context, env *Env, name string) (*session, error) {
	s, err := open(ctx, env, name)
	if err != nil {
		return nil, err
	}
	if err := s.requireRunning(); err != nil {
		return nil, err
	}
	if err := s.ensureAWS(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// applyProviders sends the complete provider list to the running network.
// Only the sign-in service restarts; the server keeps the previous providers
// if anything fails.
func (s *session) applyProviders(ctx context.Context, srv *server) error {
	data, err := json.MarshalIndent(providersConfig(s.n), "", "  ")
	if err != nil {
		return err
	}
	if err := srv.putFile(ctx, serverProviders, append(data, '\n'), "600"); err != nil {
		return err
	}
	return srv.deploy(ctx, "update-identity-providers --config "+serverProviders+" --directory "+remote.Quote(s.n.Runtime))
}

// syncConfig keeps /srv/covee/deployment.json describing the running network,
// so a future prepare on the server starts from the same settings.
func (s *session) syncConfig(ctx context.Context, srv *server) error {
	grants, err := srv.readGrants(ctx, s.n.Runtime)
	if err != nil {
		return err
	}
	config, err := deploymentConfig(s.n, grants)
	if err != nil {
		return err
	}
	return srv.putFile(ctx, serverConfig, config, "600")
}

func orderProviders(list []string) []string {
	var out []string
	for _, p := range []string{"entra", "google", "apple", "local"} {
		for _, have := range list {
			if have == p {
				out = append(out, p)
			}
		}
	}
	return out
}

// AuthAdd turns on a sign-in method on a running network.
func AuthAdd(ctx context.Context, env *Env, name, provider string) error {
	kind, err := ProviderKind(provider)
	if err != nil {
		return err
	}
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	for _, p := range s.n.Providers {
		if p == kind {
			return fmt.Errorf("%s sign-in is already on for network %s", providerLabel[kind], s.n.Name)
		}
	}
	saved := *s.n
	switch kind {
	case "entra":
		err = s.stepEntra(ctx)
	case "google":
		err = s.stepGoogle(ctx)
	case "apple":
		err = s.stepApple(ctx)
	case "local":
		s.n.SignIn.Local = &record.Local{}
	}
	if err != nil {
		return err
	}
	srv := s.server(true)
	if kind != "local" {
		secret, err := s.store().Get(ctx, providerSecret[kind])
		if err != nil {
			return err
		}
		if err := srv.putFile(ctx, providerFile(kind, s.n), secret, "400"); err != nil {
			return err
		}
	}
	s.n.Providers = orderProviders(append(s.n.Providers, kind))
	s.say("Turning on %s sign-in (only the sign-in service restarts; devices stay connected)...", providerLabel[kind])
	if err := s.applyProviders(ctx, srv); err != nil {
		restored := saved
		*s.n = restored
		return fmt.Errorf("the network kept its previous sign-in methods: %w", err)
	}
	if err := s.env.Records.Save(s.n); err != nil {
		return err
	}
	if err := s.syncConfig(ctx, srv); err != nil {
		return err
	}
	s.say("%s sign-in is on for %s.", providerLabel[kind], s.n.Hostname)
	if kind == "local" {
		s.say("Invite people with `covee users invite %s --email ... --name ...`.", s.n.Name)
	} else if kind != "entra" {
		s.say("New %s accounts need approval once: see `covee grant`.", providerLabel[kind])
	}
	return nil
}

// AuthRemove turns off a sign-in method. Accounts approved through it lose
// access, after confirmation.
func AuthRemove(ctx context.Context, env *Env, name, provider string) error {
	kind, err := ProviderKind(provider)
	if err != nil {
		return err
	}
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	enabled := false
	for _, p := range s.n.Providers {
		enabled = enabled || p == kind
	}
	if !enabled {
		return fmt.Errorf("%s sign-in is not on for network %s", providerLabel[kind], s.n.Name)
	}
	if len(s.n.Providers) == 1 {
		return errors.New("a network needs at least one sign-in method; add another one first")
	}
	srv := s.server(true)
	grants, err := srv.readGrants(ctx, s.n.Runtime)
	if err != nil {
		return err
	}
	var keep []map[string]any
	for _, g := range grants {
		if g["provider"] != kind {
			keep = append(keep, g)
		}
	}
	if len(keep) != len(grants) {
		ok, err := s.env.Ask.Confirm("remove_grants", fmt.Sprintf("%d approved %s account(s) will lose access to %s. Continue", len(grants)-len(keep), providerLabel[kind], s.n.Name), false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("nothing was changed")
		}
		if keep == nil {
			keep = []map[string]any{}
		}
		data, err := json.MarshalIndent(keep, "", "  ")
		if err != nil {
			return err
		}
		if err := srv.putFile(ctx, serverGrants, append(data, '\n'), "600"); err != nil {
			return err
		}
		if err := srv.deploy(ctx, "update-identity-grants --config "+serverGrants+" --directory "+remote.Quote(s.n.Runtime)); err != nil {
			return err
		}
	}
	saved := *s.n
	file := providerFile(kind, s.n)
	var rest []string
	for _, p := range s.n.Providers {
		if p != kind {
			rest = append(rest, p)
		}
	}
	s.n.Providers = rest
	switch kind {
	case "entra":
		s.n.SignIn.Entra = nil
	case "google":
		s.n.SignIn.Google = nil
	case "apple":
		s.n.SignIn.Apple = nil
	case "local":
		s.n.SignIn.Local = nil
	}
	if err := s.applyProviders(ctx, srv); err != nil {
		restored := saved
		*s.n = restored
		return fmt.Errorf("the network kept its previous sign-in methods: %w", err)
	}
	if err := s.env.Records.Save(s.n); err != nil {
		return err
	}
	if kind != "local" {
		if _, err := srv.covee.Output(ctx, "rm -f "+remote.Quote(file), nil); err != nil {
			return err
		}
	}
	if err := s.syncConfig(ctx, srv); err != nil {
		return err
	}
	s.say("%s sign-in is off for %s.", providerLabel[kind], s.n.Hostname)
	if kind == "local" {
		s.say("The accounts stay on the server and work again if Covee accounts are turned back on.")
	} else {
		s.say("The %s registration itself still exists; its copy of this network's secret is kept in your secrets store.", providerLabel[kind])
	}
	return nil
}

var tagRE = regexp.MustCompile(`^tag:[a-z0-9][a-z0-9-]{0,62}$`)

// DeviceToken creates an enrollment key for a device that cannot sign in
// itself, such as a Linux server, and shows how to use it.
func DeviceToken(ctx context.Context, env *Env, name string, tags []string, expires string, reusable, ephemeral bool) error {
	if len(tags) == 0 {
		tags = []string{"server"}
	}
	for i, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if !strings.HasPrefix(t, "tag:") {
			t = "tag:" + t
		}
		if !tagRE.MatchString(t) {
			return fmt.Errorf("%q is not a valid tag; use letters, digits and dashes, such as server or office-nas", tags[i])
		}
		tags[i] = t
	}
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	args := "create-device-key --directory " + remote.Quote(s.n.Runtime) + " --tags " + remote.Quote(strings.Join(tags, ",")) + " --expiration " + remote.Quote(expires)
	if reusable {
		args += " --reusable"
	}
	if ephemeral {
		args += " --ephemeral"
	}
	out, err := s.server(true).covee.Output(ctx, "cd "+serverSource+" && python3 scripts/deploy.py "+args, nil)
	if err != nil {
		return err
	}
	var created struct {
		Key        string          `json:"key"`
		Expiration json.RawMessage `json:"expiration"`
	}
	if err := lastJSON(out, &created); err != nil || created.Key == "" {
		return errors.New("the network did not return a device key")
	}
	use := "one device"
	if reusable {
		use = "several devices"
	}
	s.say("Device key for %s (for %s, valid %s, tagged %s):\n\n  %s\n", s.n.Name, use, expires, strings.Join(tags, ", "), created.Key)
	s.say("On the Linux machine, install the Tailscale client (https://tailscale.com/download/linux), then run:\n")
	s.say("  sudo tailscale up --login-server https://%s --auth-key %s\n", s.n.Hostname, created.Key)
	s.say("Keep the key private; anyone holding it can add a device until it expires.")
	s.say("The network denies all traffic by default: allow %s in the console's access rules (`covee console %s`).", strings.Join(tags, ", "), s.n.Name)
	return nil
}
