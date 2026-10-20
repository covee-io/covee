package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"covee.io/cli/internal/payload"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/remote"
)

// A network's gateway is a device on its server that carries members'
// traffic to places only the server can reach, such as a cloud's private
// networks, or out with the server's own address for allowlists. `covee
// gateway` turns the device on or off; what goes through it, and who may use
// it, is chosen on the console's Gateway page. The server applies the
// page's private DNS settings itself: a path unit watches the file the
// management service writes and runs deploy.py apply-gateway-dns.
const (
	gatewayDNSService = "covee-gateway-dns.service"
	gatewayDNSPath    = "covee-gateway-dns.path"
)

func gatewayDNSUnits(runtime string) (service, path string) {
	service = fmt.Sprintf(`# Installed by covee. Applies the console's private DNS settings (%[1]s).
[Unit]
Description=Apply the Covee console's private DNS settings
After=docker.service
ConditionPathExists=%[1]s/runtime.env

[Service]
Type=oneshot
User=covee
Group=covee
WorkingDirectory=%[2]s
ExecStart=/usr/bin/python3 %[2]s/scripts/deploy.py apply-gateway-dns --directory %[1]s
TimeoutStartSec=10min
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
`, runtime, serverSource)
	path = fmt.Sprintf(`# Installed by covee.
[Unit]
Description=Watch the Covee console's private DNS settings

[Path]
PathChanged=%[1]s/state/management/gateway/dns.json
Unit=%[2]s

[Install]
WantedBy=paths.target
`, runtime, gatewayDNSService)
	return service, path
}

// applyFirewall brings the server's firewall to the rules of the installed
// Covee files, which admit SSH from the gateway's network, so an admin can
// manage the server through the network itself. It changes nothing when the
// rules are current.
func (s *session) applyFirewall(ctx context.Context, srv *server) error {
	pub, err := s.publicKey(ctx)
	if err != nil {
		return err
	}
	in, _ := json.Marshal(s.systemConfig(pub))
	out, err := srv.covee.Output(ctx, "sudo -n python3 "+remote.Quote(serverSource+"/scripts/host_prepare.py")+" firewall", in)
	if err != nil {
		return fmt.Errorf("updating the server's firewall: %w", err)
	}
	var result struct {
		Firewall string `json:"firewall"`
	}
	if err := lastJSON(out, &result); err != nil || result.Firewall == "" {
		return errors.New("the server did not confirm its firewall")
	}
	return nil
}

// installGatewayDNS installs the units and applies the settings once.
func (s *session) installGatewayDNS(ctx context.Context, srv *server) error {
	service, path := gatewayDNSUnits(s.n.Runtime)
	for name, body := range map[string]string{gatewayDNSService: service, gatewayDNSPath: path} {
		if _, err := srv.covee.Output(ctx, "sudo -n tee "+remote.Quote("/etc/systemd/system/"+name)+" >/dev/null", []byte(body)); err != nil {
			return fmt.Errorf("installing %s: %w", name, err)
		}
	}
	if _, err := srv.covee.Output(ctx, "sudo -n systemctl daemon-reload && sudo -n systemctl enable --now "+gatewayDNSPath, nil); err != nil {
		return fmt.Errorf("enabling the private DNS watcher: %w", err)
	}
	if _, err := srv.covee.Output(ctx, "sudo -n systemctl start "+gatewayDNSService, nil); err != nil {
		return fmt.Errorf("applying the private DNS settings failed (see `journalctl -u covee-gateway-dns` on the server): %w", err)
	}
	return nil
}

func (s *session) removeGatewayDNS(ctx context.Context, srv *server) error {
	cmd := "sudo -n systemctl disable --now " + gatewayDNSPath + "; sudo -n rm -f " +
		remote.Quote("/etc/systemd/system/"+gatewayDNSPath) + " " + remote.Quote("/etc/systemd/system/"+gatewayDNSService) + " && sudo -n systemctl daemon-reload"
	if _, err := srv.covee.Output(ctx, cmd, nil); err != nil {
		return fmt.Errorf("removing the private DNS watcher: %w", err)
	}
	return nil
}

// Gateway turns a running network's gateway device on, or off with off.
func Gateway(ctx context.Context, env *Env, name string, off bool) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	srv := s.server(true)
	if off {
		if !s.n.Gateway {
			s.say("Network %s has no gateway.", s.n.Name)
			return nil
		}
		ok, err := env.Ask.Confirm("gateway_off", fmt.Sprintf("Turn off the gateway of %s? Devices can no longer reach what goes through it. Its settings on the console's Gateway page are kept for next time", s.n.Name), true)
		if err != nil {
			return err
		}
		if !ok {
			return prompt.ErrAborted
		}
		if err := s.setGateway(ctx, srv, false); err != nil {
			return err
		}
		if err := s.removeGatewayDNS(ctx, srv); err != nil {
			return err
		}
		s.say("The gateway of %s is off.", s.n.Name)
		return nil
	}
	if s.n.Gateway {
		s.say("Network %s already has a gateway (%s); checking its private DNS watcher and firewall.", s.n.Name, srv.containerState(ctx, "gateway"))
		if err := s.installGatewayDNS(ctx, srv); err != nil {
			return err
		}
		return s.applyFirewall(ctx, srv)
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
	ok, err := env.Ask.Confirm("gateway", fmt.Sprintf("Add a gateway to %s? A gateway device on the server joins the network; devices can then reach what you list on the console's Gateway page through the server, such as private networks it can reach. Nothing goes through it until you list it there", s.n.Name), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	s.say("[1/3] Start the gateway device")
	if err := s.setGateway(ctx, srv, true); err != nil {
		return err
	}
	s.say("[2/3] Let the server apply the console's private DNS settings")
	if err := s.installGatewayDNS(ctx, srv); err != nil {
		return err
	}
	s.say("[3/3] Let admins reach the server's SSH through the gateway")
	if err := s.applyFirewall(ctx, srv); err != nil {
		return err
	}
	if state := srv.containerState(ctx, "gateway"); state != "healthy" {
		s.say("  The gateway device is %s; it usually joins within a minute. Check it later with `covee status %s`.", state, s.n.Name)
	}
	s.say("Network %s has a gateway. Choose what goes through it, and who may use it, on the console's Gateway page (`covee console %s`).", s.n.Name, s.n.Name)
	return nil
}

func (s *session) setGateway(ctx context.Context, srv *server, on bool) error {
	command := "disable-gateway"
	if on {
		command = "enable-gateway"
	}
	out, err := srv.covee.Output(ctx, "cd "+serverSource+" && python3 scripts/deploy.py "+command+" --directory "+remote.Quote(s.n.Runtime), nil)
	if err != nil {
		return err
	}
	var result struct {
		Gateway bool `json:"gateway"`
	}
	if err := lastJSON(out, &result); err != nil || result.Gateway != on {
		return errors.New("the server did not confirm the gateway change")
	}
	s.n.Gateway = on
	if err := s.env.Records.Save(s.n); err != nil {
		return err
	}
	return s.syncConfig(ctx, srv)
}

// containerState is a service container's health on the server.
func (s *server) containerState(ctx context.Context, service string) string {
	out, err := s.covee.Output(ctx, "docker ps --filter "+remote.Quote("name=-"+service+"-")+" --format '{{.Status}}' | head -1", nil)
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
