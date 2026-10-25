package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"covee.io/cli/internal/remote"
)

// Facts is what scripts/host_prepare.py reports about a server.
type Facts struct {
	OS               string `json:"os"`
	Codename         string `json:"codename"`
	Pretty           string `json:"pretty"`
	Architecture     string `json:"architecture"`
	Hostname         string `json:"hostname"`
	Interface        string `json:"interface"`
	IPv4CIDR         string `json:"ipv4_cidr"`
	DHCP             bool   `json:"dhcp"`
	SSHClient        string `json:"ssh_client"`
	Virtualization   string `json:"virtualization"`
	PublicIPv4       string `json:"public_ipv4"`
	ServiceUser      bool   `json:"service_user"`
	Prepared         bool   `json:"prepared"`
	Docker           bool   `json:"docker"`
	PasswordlessSudo bool   `json:"passwordless_sudo"`
}

// Supported reports whether setup can prepare this server.
func (f *Facts) Supported() error {
	if f.OS != "ubuntu" || f.Codename != "noble" || f.Architecture != "amd64" {
		return fmt.Errorf("this server runs %s on %s; Covee setup currently supports Ubuntu 24.04 on amd64", f.Pretty, f.Architecture)
	}
	if f.IPv4CIDR == "" {
		return errors.New("could not find this server's IPv4 address on its main network interface")
	}
	return nil
}

type server struct {
	admin   *remote.Host
	covee   *remote.Host
	out     io.Writer
	archive []byte
	digest  string
}

// lastJSON decodes the final non-empty output line, which host_prepare.py
// always writes as JSON (progress lines come before it).
func lastJSON(out []byte, v any) error {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	var e struct{ Error string }
	if json.Unmarshal([]byte(last), &e) == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	if err := json.Unmarshal([]byte(last), v); err != nil {
		return fmt.Errorf("unexpected reply from the server: %q", last)
	}
	return nil
}

// stageAdmin unpacks the payload into a private temporary directory as the
// admin account and returns its path.
func (s *server) stageAdmin(ctx context.Context) (string, error) {
	out, err := s.admin.Output(ctx, `set -eu; d=$(mktemp -d); tar -xzf - -C "$d"; python3 "$d/scripts/host_prepare.py" verify-payload "$d" >/dev/null; echo "$d"`, s.archive)
	if err != nil {
		return "", fmt.Errorf("copying the Covee files to the server: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if !strings.HasPrefix(dir, "/tmp/") {
		return "", fmt.Errorf("unexpected temporary directory %q", dir)
	}
	return dir, nil
}

func (s *server) cleanupAdmin(ctx context.Context, dir string) {
	if strings.HasPrefix(dir, "/tmp/") {
		_, _ = s.admin.Output(ctx, "rm -rf "+remote.Quote(dir), nil)
	}
}

func (s *server) facts(ctx context.Context, dir string) (*Facts, error) {
	out, err := s.admin.Output(ctx, "python3 "+remote.Quote(dir+"/scripts/host_prepare.py")+" facts", nil)
	if err != nil {
		return nil, fmt.Errorf("reading the server's details: %w", err)
	}
	var f Facts
	if err := lastJSON(out, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *server) account(ctx context.Context, dir, publicKey string) error {
	in, _ := json.Marshal(map[string]string{"ssh_public_key": publicKey})
	out, err := s.admin.Output(ctx, "sudo -n python3 "+remote.Quote(dir+"/scripts/host_prepare.py")+" account", in)
	if err != nil {
		return fmt.Errorf("creating the covee account: %w", err)
	}
	var result map[string]any
	return lastJSON(out, &result)
}

// checkCovee confirms the CLI can log in as covee and use sudo.
func (s *server) checkCovee(ctx context.Context) error {
	out, err := s.covee.Output(ctx, "id -un && sudo -n true && echo ok", nil)
	if err != nil {
		return fmt.Errorf("logging in as covee: %w", err)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(out)), "ok") {
		return errors.New("the covee account cannot use sudo")
	}
	return nil
}

// stageCovee unpacks the payload in the covee account's home directory.
func (s *server) stageCovee(ctx context.Context) (string, error) {
	dir := "$HOME/covee-payload-" + s.digest[:12]
	script := `set -eu; umask 077; d="` + dir + `"; rm -rf "$d"; mkdir "$d"; tar -xzf - -C "$d"; python3 "$d/scripts/host_prepare.py" verify-payload "$d" >/dev/null; echo "$d"`
	out, err := s.covee.Output(ctx, script, s.archive)
	if err != nil {
		return "", fmt.Errorf("copying the Covee files to the server: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *server) system(ctx context.Context, dir string, config map[string]any) error {
	in, _ := json.Marshal(config)
	var buf bytes.Buffer
	err := s.covee.Stream(ctx, "sudo -n python3 "+remote.Quote(dir+"/scripts/host_prepare.py")+" system", in, io.MultiWriter(s.out, &buf))
	if err != nil {
		var result map[string]any
		if jerr := lastJSON(buf.Bytes(), &result); jerr != nil {
			return fmt.Errorf("preparing the server: %w", jerr)
		}
		return fmt.Errorf("preparing the server: %w", err)
	}
	var result map[string]any
	return lastJSON(buf.Bytes(), &result)
}

// installSource puts the verified payload at /opt/covee/src, keeping the
// previous tree and the build cache.
func (s *server) installSource(ctx context.Context) error {
	script := `set -eu
src=` + serverSource + `; new=$src.new
rm -rf "$new"; mkdir -m 0750 "$new"; tar -xzf - -C "$new"
python3 "$new/scripts/host_prepare.py" verify-payload "$new" >/dev/null
if [ -d "$src/.cache" ]; then mv "$src/.cache" "$new/.cache"; fi
if [ -d "$src" ]; then rm -rf "$src.previous"; mv "$src" "$src.previous"; fi
mv "$new" "$src"
rm -rf "$HOME"/covee-payload-*
echo ok`
	if _, err := s.covee.Output(ctx, script, s.archive); err != nil {
		return fmt.Errorf("installing the Covee files: %w", err)
	}
	return nil
}

// putFile writes a private file on the server without exposing its content
// on any command line.
func (s *server) putFile(ctx context.Context, path string, data []byte, mode string) error {
	q := remote.Quote(path)
	script := `set -eu; umask 077; mkdir -p "$(dirname ` + q + `)"; cat > ` + q + `.tmp; chmod ` + mode + ` ` + q + `.tmp; mv -f ` + q + `.tmp ` + q
	if _, err := s.covee.Output(ctx, script, data); err != nil {
		return fmt.Errorf("writing %s on the server: %w", path, err)
	}
	return nil
}

// deploy runs scripts/deploy.py on the server and shows its output. It runs
// apart from the SSH session, so a restart that cuts the session (when the
// admin comes in through the network's gateway) does not stop it halfway.
func (s *server) deploy(ctx context.Context, args string) error {
	_, err := s.covee.Apart(ctx, "cd "+serverSource+" && python3 scripts/deploy.py "+args, s.out)
	return err
}

// deployResult runs scripts/deploy.py like deploy, and returns its output
// instead of showing it.
func (s *server) deployResult(ctx context.Context, args string) ([]byte, error) {
	return s.covee.Apart(ctx, "cd "+serverSource+" && python3 scripts/deploy.py "+args, nil)
}

// nextRuntime returns the first unused /srv/covee/runtime-N directory, so a
// prepared runtime is never overwritten.
func (s *server) nextRuntime(ctx context.Context) (string, error) {
	out, err := s.covee.Output(ctx, `n=1; while [ -e /srv/covee/runtime-$n ]; do n=$((n+1)); done; echo /srv/covee/runtime-$n`, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// localIssuer asks the running broker for its issuer from the server itself.
func (s *server) localIssuer(ctx context.Context, host string) (string, error) {
	cmd := "curl -fsS --max-time 15 --resolve " + remote.Quote(host+":443:127.0.0.1") + " " + remote.Quote("https://"+host+"/identity/.well-known/openid-configuration")
	out, err := s.covee.Output(ctx, cmd, nil)
	if err != nil {
		return "", err
	}
	var d struct{ Issuer string }
	if err := json.Unmarshal(out, &d); err != nil {
		return "", errors.New("the sign-in service returned something unexpected")
	}
	return d.Issuer, nil
}

// readGrants returns the explicit Google/Apple grants of a prepared runtime.
func (s *server) readGrants(ctx context.Context, runtime string) ([]map[string]any, error) {
	out, err := s.covee.Output(ctx, "python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))[\"spec\"][\"identity\"][\"grants\"]))' "+remote.Quote(runtime+"/deployment.json"), nil)
	if err != nil {
		return nil, fmt.Errorf("reading the current access list: %w", err)
	}
	var grants []map[string]any
	if err := json.Unmarshal(out, &grants); err != nil {
		return nil, errors.New("the current access list is unreadable")
	}
	return grants, nil
}
