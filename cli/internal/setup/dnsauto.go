package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"covee.io/cli/internal/dns"
	"covee.io/cli/internal/payload"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
)

// On a home or office connection the public address can change. The address
// updater runs on the network server every five minutes and points the
// hostname at the connection's current address, using its own AWS key that
// may only change that one record.
const (
	updaterScript  = "/opt/covee/dns-updater/dns_updater.py"
	updaterConfig  = "/srv/covee/dns-updater.json"
	updaterKeyFile = serverSecrets + "/dns-updater-key.json"
	updaterSecret  = "dns-updater-key"
)

// updaterRetryDelay spaces the first checks while a new AWS key becomes usable.
var updaterRetryDelay = 5 * time.Second

func updaterUnits(host string) (service, timer string) {
	service = fmt.Sprintf(`# Installed by covee. Keeps %[1]s pointing at this connection's public address.
[Unit]
Description=Keep %[1]s pointing at the public address
Wants=network-online.target
After=network-online.target
ConditionPathExists=%[2]s

[Service]
Type=oneshot
User=covee
Group=covee
ExecStart=/usr/bin/python3 %[3]s --config %[2]s
TimeoutStartSec=2min
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
`, host, updaterConfig, updaterScript)
	timer = `# Installed by covee.
[Unit]
Description=Check the public address every 5 minutes

[Timer]
OnBootSec=2min
OnActiveSec=5min
OnUnitActiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
`
	return service, timer
}

type updaterCheck struct {
	Public string   `json:"public"`
	Record []string `json:"record"`
	Serves bool     `json:"serves"`
}

func (s *session) putUpdaterScript(ctx context.Context, srv *server) error {
	script, err := payload.File(s.archive, "scripts/dns_updater.py")
	if err != nil {
		return err
	}
	return srv.putFile(ctx, updaterScript, script, "500")
}

// installUpdater writes the script and its systemd units and enables the
// timer. It does not need AWS, so `covee update` uses it to refresh them.
func (s *session) installUpdater(ctx context.Context, srv *server) error {
	if err := s.putUpdaterScript(ctx, srv); err != nil {
		return err
	}
	return s.installUpdaterUnits(ctx, srv)
}

func (s *session) installUpdaterUnits(ctx context.Context, srv *server) error {
	service, timer := updaterUnits(s.n.Hostname)
	for name, body := range map[string]string{"covee-dns.service": service, "covee-dns.timer": timer} {
		if _, err := srv.covee.Output(ctx, "sudo -n tee "+remote.Quote("/etc/systemd/system/"+name)+" >/dev/null", []byte(body)); err != nil {
			return fmt.Errorf("installing %s: %w", name, err)
		}
	}
	if _, err := srv.covee.Output(ctx, "sudo -n systemctl daemon-reload && sudo -n systemctl enable --now covee-dns.timer", nil); err != nil {
		return fmt.Errorf("enabling the address updater: %w", err)
	}
	return nil
}

func (s *session) writeUpdaterConfig(ctx context.Context, srv *server, verify bool) error {
	config, err := json.MarshalIndent(map[string]any{
		"hostname": s.n.Hostname, "zone_id": s.n.DNS.ZoneID, "ttl": 300, "verify": verify, "credentials": updaterKeyFile,
	}, "", "  ")
	if err != nil {
		return err
	}
	return srv.putFile(ctx, updaterConfig, config, "600")
}

func missingSecret(err error) bool {
	var notFound *ssmtypes.ParameterNotFound
	return errors.Is(err, os.ErrNotExist) || errors.As(err, &notFound)
}

// updaterKey returns the stored updater key while AWS still has it active,
// otherwise replaces it. fresh reports a key created just now.
func (s *session) updaterKey(ctx context.Context, api dns.IAMAPI) (key dns.UpdaterKey, fresh bool, err error) {
	st := s.store()
	raw, err := st.Get(ctx, updaterSecret)
	switch {
	case err == nil:
		if json.Unmarshal(raw, &key) == nil && key.AccessKeyID != "" {
			active, err := dns.HasActiveKey(ctx, api, s.n.Name, key.AccessKeyID)
			if err != nil {
				return key, false, err
			}
			if active {
				return key, false, nil
			}
		}
	case !missingSecret(err):
		return key, false, err
	}
	if key, err = dns.NewUpdaterKey(ctx, api, s.n.Name); err != nil {
		return key, false, err
	}
	raw, err = json.Marshal(key)
	if err != nil {
		return key, false, err
	}
	desc := fmt.Sprintf("AWS access key of IAM user %s, used by the %s Covee network's server to keep %s pointing at its public address. It may only read zone %s and UPSERT that A record.",
		dns.UpdaterUser(s.n.Name), s.n.Name, s.n.Hostname, s.n.DNS.ZoneID)
	if err := st.Put(ctx, updaterSecret, raw, desc, true); err != nil {
		return key, false, err
	}
	return key, true, nil
}

// enableUpdater sets up the address updater: its IAM user and key, the files
// on the server, a first check, and the timer.
func (s *session) enableUpdater(ctx context.Context, srv *server) error {
	n := s.n
	if n.DNS.Host != "route53" || n.DNS.ZoneID == "" {
		return errors.New("the address updater needs the hostname's DNS in Route 53")
	}
	if s.env.NewIAM == nil {
		return errors.New("this covee binary cannot manage AWS IAM users")
	}
	api := s.env.NewIAM(*s.awsCfg)
	created, err := dns.EnsureUpdaterUser(ctx, api, n.Name, n.DNS.ZoneID, n.Hostname)
	if err != nil {
		return err
	}
	if created {
		s.say("  Created AWS IAM user %s, which may only change the A record of %s", dns.UpdaterUser(n.Name), n.Hostname)
	}
	key, _, err := s.updaterKey(ctx, api)
	if err != nil {
		return err
	}
	keyJSON, err := json.Marshal(key)
	if err != nil {
		return err
	}
	if err := srv.putFile(ctx, updaterKeyFile, keyJSON, "400"); err != nil {
		return err
	}
	if err := s.writeUpdaterConfig(ctx, srv, true); err != nil {
		return err
	}
	if err := s.putUpdaterScript(ctx, srv); err != nil {
		return err
	}

	// A new AWS key, or a policy just changed for another record (after
	// `covee rename`), can take a little while to work everywhere.
	var check updaterCheck
	for attempt := 1; ; attempt++ {
		out, err := srv.covee.Output(ctx, "python3 "+remote.Quote(updaterScript)+" --config "+remote.Quote(updaterConfig)+" --check --json", nil)
		if err == nil {
			if err := json.Unmarshal(out, &check); err != nil {
				return fmt.Errorf("reading the updater's first check: %w", err)
			}
			break
		}
		if attempt == 8 {
			return fmt.Errorf("the updater's first check failed: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(updaterRetryDelay):
		}
	}
	s.say("  This connection's public address is %s; %s points to %s", check.Public, n.Hostname, orNone(check.Record))
	if len(check.Record) > 0 && !(len(check.Record) == 1 && check.Record[0] == check.Public) {
		ok, err := s.env.Ask.Confirm("dns_updater_replace", fmt.Sprintf("The server's internet traffic comes from %s, not %s. If it goes through a VPN, answer no. Point %s at %s from now on",
			check.Public, strings.Join(check.Record, ", "), n.Hostname, check.Public), false)
		if err != nil {
			return err
		}
		if !ok {
			return prompt.ErrAborted
		}
	}
	if !check.Serves {
		s.say("  The server could not reach %s through %s: the router's port forwards are not set yet, or the\n  router does not loop connections back. So the updater will not test a new address before using it.\n  Run `covee dns auto %s` again later to turn that test on.", n.Hostname, check.Public, n.Name)
		if err := s.writeUpdaterConfig(ctx, srv, false); err != nil {
			return err
		}
	}
	if err := s.installUpdaterUnits(ctx, srv); err != nil {
		return err
	}
	if _, err := srv.covee.Output(ctx, "sudo -n systemctl start covee-dns.service", nil); err != nil {
		return fmt.Errorf("the updater's first run failed (see `journalctl -u covee-dns` on the server): %w", err)
	}
	out, err := srv.covee.Output(ctx, "systemctl show -p Result --value covee-dns.service; systemctl is-active covee-dns.timer", nil)
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "success") || !strings.Contains(string(out), "active") {
		return fmt.Errorf("the address updater did not report success: %s", strings.TrimSpace(string(out)))
	}
	n.DNS.Dynamic = true
	n.DNS.Updater = &record.DNSUpdater{IAMUser: dns.UpdaterUser(n.Name), AccessKeyID: key.AccessKeyID, SecretName: s.store().Ref(updaterSecret), Verify: check.Serves, Installed: time.Now().UTC()}
	return nil
}

func orNone(values []string) string {
	if len(values) == 0 {
		return "nothing yet"
	}
	return strings.Join(values, ", ")
}

func (s *session) stepDNSUpdater(ctx context.Context) error {
	if err := s.enableUpdater(ctx, s.server(true)); err != nil {
		return err
	}
	s.say("  %s now follows this connection's public address; the server checks it every 5 minutes.", s.n.Hostname)
	return nil
}

// DNSAuto turns the address updater on (or refreshes it) for a running network.
func DNSAuto(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	if s.n.DNS.Host != "route53" {
		return fmt.Errorf("network %s's DNS is not in Route 53, so covee cannot update its record", s.n.Name)
	}
	archive := env.Archive
	if archive == nil {
		archive = payload.Archive
	}
	if s.archive, s.digest, err = archive(); err != nil {
		return err
	}
	if s.n.DNS.Updater == nil {
		s.say("The server will check this connection's public address every 5 minutes and point %s at it when it changes.", s.n.Hostname)
		s.say("For that, covee creates AWS IAM user %s. Its key may only read zone %s and change the A record of %s;", dns.UpdaterUser(s.n.Name), s.n.DNS.Zone, s.n.Hostname)
		s.say("it is kept in your secrets store and on the server.")
		ok, err := env.Ask.Confirm("dns_auto", "Turn this on", true)
		if err != nil {
			return err
		}
		if !ok {
			return prompt.ErrAborted
		}
	}
	if err := s.enableUpdater(ctx, s.server(true)); err != nil {
		return err
	}
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	s.say("%s now follows this connection's public address; the server checks it every 5 minutes.", s.n.Hostname)
	return nil
}

// DNSAutoOff removes the address updater from the server and deletes its IAM
// user and key. The record keeps its current address.
func DNSAutoOff(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	if s.n.DNS.Updater == nil {
		s.say("Network %s has no address updater.", s.n.Name)
		return nil
	}
	ok, err := env.Ask.Confirm("dns_auto_off", fmt.Sprintf("Stop updating %s automatically and delete AWS IAM user %s and its key? The record keeps pointing at its current address",
		s.n.Hostname, s.n.DNS.Updater.IAMUser), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	srv := s.server(true)
	cmd := "sudo -n systemctl disable --now covee-dns.timer; sudo -n rm -f /etc/systemd/system/covee-dns.service /etc/systemd/system/covee-dns.timer && sudo -n systemctl daemon-reload && rm -f " +
		remote.Quote(updaterKeyFile) + " " + remote.Quote(updaterConfig) + " " + remote.Quote(updaterScript)
	if _, err := srv.covee.Output(ctx, cmd, nil); err != nil {
		return fmt.Errorf("removing the address updater from the server: %w", err)
	}
	if err := dns.RemoveUpdaterUser(ctx, env.NewIAM(*s.awsCfg), s.n.Name); err != nil {
		return err
	}
	secret := s.n.DNS.Updater.SecretName
	s.n.DNS.Dynamic, s.n.DNS.Updater = false, nil
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	s.say("The address updater is off and its AWS user is deleted. The stored key copy (%s) no longer works and can be deleted.", secret)
	return nil
}

// updaterStatus describes the updater's last run for `covee status`.
func (s *session) updaterStatus(ctx context.Context, srv *server) string {
	u := s.n.DNS.Updater
	out, err := srv.covee.Output(ctx, "systemctl is-active covee-dns.timer; systemctl show -p Result --value covee-dns.service; systemctl show -p ExecMainExitTimestamp --value covee-dns.service", nil)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if err != nil || len(lines) < 2 {
		return fmt.Sprintf("on since %s (its state could not be read)", u.Installed.Format("2006-01-02"))
	}
	state := "on"
	if strings.TrimSpace(lines[0]) != "active" {
		state = "STOPPED (run `covee dns auto " + s.n.Name + "` to restart it)"
	}
	last := ""
	if len(lines) > 2 && strings.TrimSpace(lines[2]) != "" {
		last = ", last check " + strings.TrimSpace(lines[2])
	}
	result := strings.TrimSpace(lines[1])
	if result != "success" {
		result = "FAILED (see `journalctl -u covee-dns` on the server)"
	}
	return fmt.Sprintf("%s%s: %s", state, last, result)
}
