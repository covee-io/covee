package setup

import (
	"context"
	"fmt"
	"strings"

	"covee.io/cli/internal/remote"
)

// The console's coordinator API key lasts 24 hours (deploy.py creates it at
// every start), so a timer must rotate it while the network runs. Without it
// the private console stops working a day after each start.
func apiKeyUnits(runtime string) (service, timer string) {
	service = fmt.Sprintf(`# Installed by covee. Rotates the console's 24-hour coordinator API key.
[Unit]
Description=Rotate the Covee console's coordinator API key (%[1]s)
Wants=network-online.target
After=network-online.target docker.service
ConditionPathExists=%[1]s/runtime.env

[Service]
Type=oneshot
User=covee
Group=covee
WorkingDirectory=%[2]s
ExecStart=/usr/bin/python3 %[2]s/scripts/deploy.py rotate-api-key --directory %[1]s
TimeoutStartSec=5min
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
`, runtime, serverSource)
	timer = `# Installed by covee.
[Unit]
Description=Rotate the Covee console's coordinator API key every 12 hours

[Timer]
OnBootSec=10min
OnActiveSec=12h
OnUnitActiveSec=12h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
`
	return service, timer
}

// ensureMaintenance installs (or refreshes) the server's scheduled jobs and
// runs the key rotation once to prove it works.
func (s *session) ensureMaintenance(ctx context.Context, srv *server) error {
	service, timer := apiKeyUnits(s.n.Runtime)
	for name, body := range map[string]string{"covee-api-key.service": service, "covee-api-key.timer": timer} {
		if _, err := srv.covee.Output(ctx, "sudo -n tee "+remote.Quote("/etc/systemd/system/"+name)+" >/dev/null", []byte(body)); err != nil {
			return fmt.Errorf("installing %s: %w", name, err)
		}
	}
	if _, err := srv.covee.Output(ctx, "sudo -n systemctl daemon-reload && sudo -n systemctl enable --now covee-api-key.timer", nil); err != nil {
		return fmt.Errorf("enabling the key rotation timer: %w", err)
	}
	if _, err := srv.covee.Output(ctx, "sudo -n systemctl start covee-api-key.service", nil); err != nil {
		return fmt.Errorf("the first key rotation failed (see `journalctl -u covee-api-key` on the server): %w", err)
	}
	out, err := srv.covee.Output(ctx, "systemctl show -p Result --value covee-api-key.service; systemctl is-active covee-api-key.timer", nil)
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "success") || !strings.Contains(string(out), "active") {
		return fmt.Errorf("the key rotation did not report success: %s", strings.TrimSpace(string(out)))
	}
	if s.n.DNS.Updater != nil {
		// Refresh the address updater's script and units from these Covee files.
		if err := s.installUpdater(ctx, srv); err != nil {
			return err
		}
	}
	if s.n.Gateway {
		if err := s.installGatewayDNS(ctx, srv); err != nil {
			return err
		}
		if err := s.applyFirewall(ctx, srv); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) stepMaintenance(ctx context.Context) error {
	if err := s.ensureMaintenance(ctx, s.server(true)); err != nil {
		return err
	}
	s.say("  The console's access key now renews itself every 12 hours.")
	return nil
}
