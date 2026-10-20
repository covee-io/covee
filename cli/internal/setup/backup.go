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

	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
)

const (
	serverBackups = "/srv/covee/backups"
	keepOnServer  = 3
	keepInRecord  = 20
)

// backupIdentity returns the network's age identity, creating it once. The
// private identity is kept only in the secrets store, never on the server.
func (s *session) backupIdentity(ctx context.Context) (*age.X25519Identity, error) {
	st := s.store()
	if text, err := st.Get(ctx, "backup-age-identity"); err == nil {
		id, err := age.ParseX25519Identity(strings.TrimSpace(string(text)))
		if err != nil {
			return nil, errors.New("the stored backup key is unreadable")
		}
		return id, nil
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	desc := fmt.Sprintf("age identity that decrypts the %s Covee network's backups (%s).", s.n.Name, s.n.Hostname)
	if err := st.Put(ctx, "backup-age-identity", []byte(id.String()+"\n"), desc, false); err != nil {
		return nil, err
	}
	s.n.BackupRecipient = id.Recipient().String()
	if err := s.env.Records.Save(s.n); err != nil {
		return nil, err
	}
	return id, nil
}

// Backup takes an encrypted snapshot of a running network, downloads it to
// this computer and proves it can be restored by decrypting it here.
func Backup(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	ok, err := env.Ask.Confirm("backup", fmt.Sprintf("Back up %s now? The services pause for a few seconds while the snapshot is taken; devices reconnect on their own", s.n.Name), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	id, err := s.backupIdentity(ctx)
	if err != nil {
		return err
	}
	srv := s.server(true)
	created := time.Now().UTC().Truncate(time.Second)
	base := fmt.Sprintf("%s-%s.tar.age", s.n.Name, created.Format("20060102T150405Z"))
	remoteFile := serverBackups + "/" + base
	s.say("[1/3] Take the encrypted snapshot on the server")
	if _, err := srv.covee.Output(ctx, "mkdir -p -m 700 "+serverBackups, nil); err != nil {
		return err
	}
	if err := srv.deploy(ctx, "backup --directory "+remote.Quote(s.n.Runtime)+" --output "+remote.Quote(remoteFile)+" --recipient "+remote.Quote(id.Recipient().String())); err != nil {
		return err
	}
	s.say("[2/3] Download it")
	local := filepath.Join(s.env.Home, "backups", s.n.Name, base)
	if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	var errOut strings.Builder
	runErr := srv.covee.Run(ctx, "cat "+remote.Quote(remoteFile), nil, io.MultiWriter(f, hash), &errOut)
	closeErr := f.Close()
	if runErr != nil || closeErr != nil {
		os.Remove(local)
		return fmt.Errorf("downloading the backup: %v %v %s", runErr, closeErr, errOut.String())
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	out, err := srv.covee.Output(ctx, "sha256sum "+remote.Quote(remoteFile), nil)
	if err != nil || !strings.HasPrefix(string(out), sum+" ") {
		return errors.New("the downloaded backup differs from the one on the server")
	}
	s.say("[3/3] Prove it can be restored: decrypt it here and check its contents")
	files, err := verifyBackup(local, id, s.n.Hostname)
	if err != nil {
		return fmt.Errorf("the backup is not restorable: %w", err)
	}
	info, err := os.Stat(local)
	if err != nil {
		return err
	}
	// Keep the newest few on the server; this computer keeps every download.
	_, _ = srv.covee.Output(ctx, "ls -1t "+serverBackups+"/"+s.n.Name+"-*.tar.age | tail -n +"+fmt.Sprint(keepOnServer+1)+" | xargs -r rm -f", nil)
	s.n.Backups = append(s.n.Backups, record.Backup{Created: created, File: local, Server: remoteFile, SHA256: sum, Bytes: info.Size(), Files: files})
	if len(s.n.Backups) > keepInRecord {
		s.n.Backups = s.n.Backups[len(s.n.Backups)-keepInRecord:]
	}
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	s.say("Backup saved: %s (%d files, %.1f MB, verified). The newest %d also stay on the server in %s.", local, files, float64(info.Size())/1e6, keepOnServer, serverBackups)
	return nil
}

// verifyBackup decrypts an archive with the network's identity and checks
// that it is a complete snapshot of this network.
func verifyBackup(path string, id *age.X25519Identity, host string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	plain, err := age.Decrypt(f, id)
	if err != nil {
		return 0, fmt.Errorf("cannot decrypt it with the stored key: %w", err)
	}
	reader := tar.NewReader(plain)
	files, haveDatabase := 0, false
	var metadata []byte
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("damaged archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		files++
		switch h.Name {
		case "deployment.json":
			if metadata, err = io.ReadAll(io.LimitReader(reader, 1<<20)); err != nil {
				return 0, err
			}
		case "state/headscale/db.sqlite":
			haveDatabase = h.Size > 0
		}
	}
	var meta struct {
		Format int `json:"format"`
		Spec   struct {
			ControlHost string `json:"control_host"`
		} `json:"spec"`
	}
	if len(metadata) == 0 || json.Unmarshal(metadata, &meta) != nil || meta.Format != 1 {
		return 0, errors.New("it has no readable deployment description")
	}
	if meta.Spec.ControlHost != host {
		return 0, fmt.Errorf("it belongs to %s, not %s", meta.Spec.ControlHost, host)
	}
	if !haveDatabase {
		return 0, errors.New("it has no coordinator database")
	}
	return files, nil
}
