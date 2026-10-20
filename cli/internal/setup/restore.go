package setup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
)

// backupContents is what setup needs from a backup to rebuild its network.
type backupContents struct {
	ControlHost   string
	DNSBaseDomain string
	Providers     []map[string]any
	Grants        int
	Secrets       map[string][]byte // identity-secrets/<name>
	Files         int
}

// readBackup decrypts a backup on this computer and reads the network it holds.
func readBackup(path string, id *age.X25519Identity) (*backupContents, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	plain, err := age.Decrypt(f, id)
	if err != nil {
		return nil, fmt.Errorf("this key cannot decrypt the backup: %w", err)
	}
	reader := tar.NewReader(plain)
	out := &backupContents{Secrets: map[string][]byte{}}
	haveDatabase := false
	var metadata []byte
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("damaged backup: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		out.Files++
		switch {
		case h.Name == "deployment.json":
			if metadata, err = io.ReadAll(io.LimitReader(reader, 1<<20)); err != nil {
				return nil, err
			}
		case h.Name == "state/headscale/db.sqlite":
			haveDatabase = h.Size > 0
		case strings.HasPrefix(h.Name, "identity-secrets/") && h.Size <= 8192:
			data, err := io.ReadAll(io.LimitReader(reader, 8192))
			if err != nil {
				return nil, err
			}
			out.Secrets[strings.TrimPrefix(h.Name, "identity-secrets/")] = data
		}
	}
	var meta struct {
		Format int  `json:"format"`
		Lab    bool `json:"lab"`
		Spec   struct {
			ControlHost   string `json:"control_host"`
			DNSBaseDomain string `json:"dns_base_domain"`
			Identity      *struct {
				Providers []map[string]any `json:"providers"`
				Grants    []any            `json:"grants"`
			} `json:"identity"`
		} `json:"spec"`
	}
	if len(metadata) == 0 || json.Unmarshal(metadata, &meta) != nil || meta.Format != 1 {
		return nil, errors.New("the backup has no readable deployment description")
	}
	if meta.Lab {
		return nil, errors.New("this is a backup of a disposable test lab, not a network")
	}
	if meta.Spec.Identity == nil {
		return nil, errors.New("this backup uses the older direct-Entra setup; covee manages networks with the sign-in service")
	}
	if !haveDatabase {
		return nil, errors.New("the backup has no coordinator database")
	}
	out.ControlHost, out.DNSBaseDomain = meta.Spec.ControlHost, meta.Spec.DNSBaseDomain
	out.Providers, out.Grants = meta.Spec.Identity.Providers, len(meta.Spec.Identity.Grants)
	return out, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// applyBackup takes the network's identity and sign-in setup from a backup.
// Secret references are filled in when the secrets are imported.
func applyBackup(n *record.Network, c *backupContents) error {
	if err := checkHostname(c.ControlHost); err != nil {
		return fmt.Errorf("the backup's hostname %q: %w", c.ControlHost, err)
	}
	n.Hostname, n.DNSBaseDomain = c.ControlHost, c.DNSBaseDomain
	n.Providers, n.SignIn = nil, record.SignIn{}
	for _, p := range c.Providers {
		switch str(p, "id") {
		case "entra":
			issuer := str(p, "issuer")
			tenant := strings.TrimSuffix(strings.TrimPrefix(issuer, "https://login.microsoftonline.com/"), "/v2.0")
			groups, _ := p["allowed_group_ids"].([]any)
			if len(groups) == 0 {
				return errors.New("the backup's Microsoft sign-in has no device group")
			}
			group, _ := groups[0].(string)
			n.SignIn.Entra = &record.Entra{TenantID: tenant, ClientID: str(p, "client_id"), GroupID: group}
		case "google":
			n.SignIn.Google = &record.Google{ClientID: str(p, "client_id")}
		case "apple":
			n.SignIn.Apple = &record.Apple{TeamID: str(p, "team_id"), ServicesID: str(p, "client_id"), KeyID: str(p, "key_id")}
		case "local":
			n.SignIn.Local = &record.Local{}
		default:
			return fmt.Errorf("the backup has an unknown sign-in method %q", str(p, "id"))
		}
		n.Providers = append(n.Providers, str(p, "id"))
	}
	n.Providers = orderProviders(n.Providers)
	if len(n.Providers) == 0 {
		return errors.New("the backup has no sign-in methods")
	}
	return nil
}

// readSecretRef reads a secret from a file, or from Parameter Store when ref
// is a parameter name.
func (s *session) readSecretRef(ctx context.Context, ref string) ([]byte, error) {
	if data, err := os.ReadFile(expandHome(ref)); err == nil {
		return data, nil
	}
	if !strings.HasPrefix(ref, "/") {
		return nil, fmt.Errorf("%s is neither a readable file nor a Parameter Store name", ref)
	}
	cfg, err := s.loadAWS(ctx, "us-east-1")
	if err != nil {
		return nil, err
	}
	out, err := s.env.NewSSM(cfg).GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(ref), WithDecryption: aws.Bool(true)})
	if err != nil {
		return nil, fmt.Errorf("reading %s from Parameter Store: %w", ref, err)
	}
	return []byte(aws.ToString(out.Parameter.Value)), nil
}

// loadBackupKey reads an age identity from a file, or from Parameter Store
// when ref is a parameter name.
func (s *session) loadBackupKey(ctx context.Context, ref string) (*age.X25519Identity, []byte, error) {
	text, err := s.readSecretRef(ctx, ref)
	if err != nil {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, nil, errors.New("the backup key is unreadable")
			}
			return id, []byte(line + "\n"), nil
		}
	}
	return nil, nil, errors.New("no AGE-SECRET-KEY line found in the backup key")
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// stepImport keeps the backup's secrets in this network's secrets store, so
// later commands (sign-in changes, backups) work as for any other network.
func (s *session) stepImport(ctx context.Context) error {
	st := s.store()
	key, err := st.Get(ctx, "backup-age-identity")
	if err != nil {
		return errors.New("the backup key is missing from the secrets store; run setup again from the start")
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(key)))
	if err != nil {
		return err
	}
	if sum, err := fileSHA256(s.n.RestoredFrom.File); err != nil || sum != s.n.RestoredFrom.SHA256 {
		return fmt.Errorf("the backup file %s changed or is missing", s.n.RestoredFrom.File)
	}
	contents, err := readBackup(s.n.RestoredFrom.File, id)
	if err != nil {
		return err
	}
	for _, p := range s.n.Providers {
		if p == "local" {
			continue // its accounts travel in the runtime's state, not as a secret
		}
		name := providerSecret[p]
		data, ok := contents.Secrets[name]
		if !ok {
			return fmt.Errorf("the backup has no %s secret", providerLabel[p])
		}
		desc := fmt.Sprintf("%s sign-in secret of the %s Covee network, restored from a backup of %s.", providerLabel[p], s.n.Name, contents.ControlHost)
		if err := st.Put(ctx, name, data, desc, false); err != nil {
			return err
		}
		switch p {
		case "entra":
			s.n.SignIn.Entra.SecretName = st.Ref(name)
		case "google":
			s.n.SignIn.Google.SecretName = st.Ref(name)
		case "apple":
			s.n.SignIn.Apple.SecretName = st.Ref(name)
		}
	}
	s.n.BackupRecipient = id.Recipient().String()
	return nil
}

// stepRestoreStart restores the backup into a new runtime directory, installs
// the new certificate and starts the network.
func (s *session) stepRestoreStart(ctx context.Context) error {
	srv := s.server(true)
	if s.n.Runtime != "" {
		if err := srv.deploy(ctx, "validate --directory "+remote.Quote(s.n.Runtime)); err == nil {
			return srv.deploy(ctx, "up --directory "+remote.Quote(s.n.Runtime))
		}
		s.say("  The runtime restored earlier is incomplete; restoring into a new one.")
	}
	dir, err := srv.nextRuntime(ctx)
	if err != nil {
		return err
	}
	s.n.Runtime = dir
	if err := s.env.Records.Save(s.n); err != nil {
		return err
	}
	archive, err := os.ReadFile(s.n.RestoredFrom.File)
	if err != nil {
		return err
	}
	key, err := s.store().Get(ctx, "backup-age-identity")
	if err != nil {
		return err
	}
	remoteArchive := serverBackups + "/restore-" + s.n.RestoredFrom.SHA256[:12] + ".tar.age"
	remoteKey := "/srv/covee/.restore-identity"
	if _, err := srv.covee.Output(ctx, "mkdir -p -m 700 "+serverBackups, nil); err != nil {
		return err
	}
	if err := srv.putFile(ctx, remoteArchive, archive, "600"); err != nil {
		return err
	}
	if err := srv.putFile(ctx, remoteKey, key, "600"); err != nil {
		return err
	}
	restoreErr := srv.deploy(ctx, "restore --archive "+remote.Quote(remoteArchive)+" --identity "+remoteKey+" --directory "+remote.Quote(dir))
	// The key must not stay on the server, whatever happened.
	if _, err := srv.covee.Output(ctx, "rm -f "+remoteKey, nil); err != nil && restoreErr == nil {
		restoreErr = err
	}
	if restoreErr != nil {
		return restoreErr
	}
	tls := serverSecrets + "/tls/"
	if err := srv.deploy(ctx, "renew-certificates --cert "+tls+"fullchain.pem --key "+tls+"privkey.pem --directory "+remote.Quote(dir)); err != nil {
		return err
	}
	if err := srv.deploy(ctx, "validate --directory "+remote.Quote(dir)); err != nil {
		return err
	}
	if err := srv.deploy(ctx, "up --directory "+remote.Quote(dir)); err != nil {
		return err
	}
	s.n.RestoredFrom.At = time.Now().UTC().Truncate(time.Second)
	return s.syncConfig(ctx, srv)
}

// askBackup reads a backup and takes the network's identity from it. It
// changes nothing.
func (s *session) askBackup(ctx context.Context, n *record.Network) error {
	ask := s.env.Ask
	path, err := ask.Text("backup_file", "Backup file (.tar.age)", "", func(v string) error {
		info, err := os.Stat(expandHome(v))
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("that file does not exist")
		}
		return nil
	})
	if err != nil {
		return err
	}
	path, _ = filepath.Abs(expandHome(path))
	defKey := ""
	if rel, err := filepath.Rel(filepath.Join(s.env.Home, "backups"), path); err == nil && !strings.HasPrefix(rel, "..") {
		candidate := filepath.Join(s.env.Home, "secrets", strings.Split(rel, string(filepath.Separator))[0], "backup-age-identity")
		if _, err := os.Stat(candidate); err == nil {
			defKey = candidate
		}
	}
	ref, err := ask.Text("backup_key", "Its key: a file with the AGE-SECRET-KEY line, or its Parameter Store name", defKey, nil)
	if err != nil {
		return err
	}
	id, keyText, err := s.loadBackupKey(ctx, ref)
	if err != nil {
		return err
	}
	contents, err := readBackup(path, id)
	if err != nil {
		return err
	}
	if err := applyBackup(n, contents); err != nil {
		return err
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return err
	}
	n.RestoredFrom = &record.Restored{File: path, SHA256: sum, SourceHost: contents.ControlHost, Grants: contents.Grants}
	s.restoreKey = keyText
	var labels []string
	for _, p := range n.Providers {
		labels = append(labels, providerLabel[p])
	}
	s.say("  Backup of %s (%d files): sign-in with %s, %d approved Google/Apple accounts.", contents.ControlHost, contents.Files, strings.Join(labels, ", "), contents.Grants)
	return nil
}

// stepBackupKey keeps the backup's key with this network's other secrets, so
// an interrupted setup can continue and later backups use the same key.
func (s *session) stepBackupKey(ctx context.Context) error {
	st := s.store()
	if _, err := st.Get(ctx, "backup-age-identity"); err == nil {
		return nil
	}
	if len(s.restoreKey) == 0 {
		return errors.New("the backup key is no longer available; run setup again from the start")
	}
	desc := fmt.Sprintf("age identity that decrypts the %s Covee network's backups (%s).", s.n.Name, s.n.Hostname)
	return st.Put(ctx, "backup-age-identity", s.restoreKey, desc, false)
}
