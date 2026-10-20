// Package remote runs commands on the network server over the admin's own
// OpenSSH client, so their SSH configuration, agent and keys apply.
package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Host is one SSH login on the network server.
type Host struct {
	Address string
	User    string
	// KeyFile is a private key to use instead of the admin's defaults.
	KeyFile string
	// KnownHosts is the CLI's own known-hosts file. The first connection
	// records the server's key; later connections must present the same key.
	KnownHosts string
	// Binary is the ssh program (tests replace it).
	Binary string
}

func (h *Host) args(extra ...string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=4",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + h.KnownHosts,
	}
	if h.KeyFile != "" {
		args = append(args, "-i", h.KeyFile, "-o", "IdentitiesOnly=yes")
	}
	args = append(args, extra...)
	return append(args, "-l", h.User, "--", h.Address)
}

func (h *Host) binary() string {
	if h.Binary != "" {
		return h.Binary
	}
	return "ssh"
}

// Run executes command on the server. stdin may be nil.
func (h *Host) Run(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, h.binary(), append(h.args(), command)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	return cmd.Run()
}

// Output runs command and returns its standard output. Standard error is
// included in the returned error for diagnosis; callers never pass secrets on
// the command line, so it carries none.
func (h *Host) Output(ctx context.Context, command string, stdin []byte) ([]byte, error) {
	var out, errOut bytes.Buffer
	var in io.Reader
	if stdin != nil {
		in = bytes.NewReader(stdin)
	}
	if err := h.Run(ctx, command, in, &out, &errOut); err != nil {
		return out.Bytes(), fmt.Errorf("%s@%s: %w: %s", h.User, h.Address, err, lastLines(errOut.String(), 6))
	}
	return out.Bytes(), nil
}

// Stream runs command, showing its output with an indent as it arrives.
func (h *Host) Stream(ctx context.Context, command string, stdin []byte, show io.Writer) error {
	var tail tailWriter
	w := io.MultiWriter(&indent{w: show}, &tail)
	var in io.Reader
	if stdin != nil {
		in = bytes.NewReader(stdin)
	}
	if err := h.Run(ctx, command, in, w, w); err != nil {
		return fmt.Errorf("%s@%s: %w: %s", h.User, h.Address, err, lastLines(tail.String(), 6))
	}
	return nil
}

// Tunnel forwards localPort on this computer to remotePort on the server's
// loopback until ctx ends.
func (h *Host) Tunnel(ctx context.Context, localPort, remotePort int) error {
	args := append([]string{"-N", "-o", "ExitOnForwardFailure=yes", "-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", localPort, remotePort)}, h.args()...)
	cmd := exec.CommandContext(ctx, h.binary(), args...)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Quote quotes a value for the server's POSIX shell.
func Quote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

// NewKey creates an Ed25519 SSH key pair: an OpenSSH private key and an
// authorized_keys public line.
func NewKey(comment string) (private []byte, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return pem.EncodeToMemory(block), line, nil
}

// PublicKey returns the authorized_keys line for an OpenSSH private key.
func PublicKey(private []byte) (string, error) {
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		return "", errors.New("stored SSH key is unreadable")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

type indent struct {
	w   io.Writer
	mid bool
}

func (i *indent) Write(p []byte) (int, error) {
	for _, b := range p {
		if !i.mid {
			if _, err := i.w.Write([]byte("    ")); err != nil {
				return 0, err
			}
			i.mid = true
		}
		if _, err := i.w.Write([]byte{b}); err != nil {
			return 0, err
		}
		if b == '\n' {
			i.mid = false
		}
	}
	return len(p), nil
}

// tailWriter keeps the last few kilobytes for error messages.
type tailWriter struct{ buf []byte }

func (t *tailWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > 8192 {
		t.buf = t.buf[len(t.buf)-8192:]
	}
	return len(p), nil
}

func (t *tailWriter) String() string { return string(t.buf) }
