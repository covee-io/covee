// Package remote runs commands on the network server over the admin's own
// OpenSSH client, so their SSH configuration, agent and keys apply.
package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

// The server keeps the output of commands run apart for a week.
const runs = "$HOME/.covee-runs"

// When a session drops, Apart connects again every reconnectEvery, and gives
// up once the server has sent nothing for reconnectFor.
var (
	reconnectEvery = 5 * time.Second
	reconnectFor   = 10 * time.Minute
)

// Apart runs command on the server apart from the SSH session and returns its
// output, standard output and error together. When show is not nil, the output
// is also shown with an indent as it arrives. The command reads no input.
//
// The admin may reach the server through the network's own gateway, which a
// restart briefly takes down. When that cuts the session, the command carries
// on regardless, and Apart connects again and continues from where the output
// left off.
func (h *Host) Apart(ctx context.Context, command string, show io.Writer) ([]byte, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	name := hex.EncodeToString(b)
	var out bytes.Buffer
	w := io.Writer(&out)
	var shown *indent
	if show != nil {
		shown = &indent{w: show}
		w = io.MultiWriter(&out, shown)
	}
	var errOut tailWriter
	// The server first answers with the run's name; a session that drops
	// before then may not have started the command at all.
	first := &firstLine{want: name, next: w}
	err := h.Run(ctx, startScript(name, command), nil, first, &errOut)
	if ferr := first.flush(); err == nil {
		err = ferr
	}
	if err != nil && dropped(err) && first.seen {
		if shown != nil {
			shown.line("(The connection to the server dropped; the command carries on there. Connecting again.)")
		}
		err = h.follow(ctx, name, &out, w, &errOut)
	}
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("stopped; the command may still finish on the server: %w", ctx.Err())
		}
		return out.Bytes(), fmt.Errorf("%s@%s: %w: %s", h.User, h.Address, err, lastLines(out.String()+errOut.String(), 6))
	}
	return out.Bytes(), nil
}

// follow reconnects to a command run apart and shows the rest of its output.
func (h *Host) follow(ctx context.Context, name string, out *bytes.Buffer, w io.Writer, errOut io.Writer) error {
	deadline := time.Now().Add(reconnectFor)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(reconnectEvery):
		}
		before := out.Len()
		err := h.Run(ctx, followScript(name, out.Len()), nil, w, errOut)
		if err == nil || !dropped(err) {
			return err
		}
		if out.Len() > before {
			deadline = time.Now().Add(reconnectFor)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the server stayed out of reach while the command runs there: %w", err)
		}
	}
}

// dropped reports a session that ended without the command's status: ssh
// exits 255 for its own errors, and a command run apart never does.
func dropped(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 255
}

// startScript starts command in the background, with its output in a private
// file, and follows that file. The command ignores the hangup of a dropped
// session and holds none of its streams.
func startScript(name, command string) string {
	return `d=` + runs + `; f="$d/` + name + `"
mkdir -p -m 700 "$d" && (umask 077 && : > "$f") || exit 1
find "$d" -type f -mtime +7 -exec rm -f {} + 2>/dev/null
(
trap '' HUP
(
` + command + `
) > "$f" 2>&1
s=$?; [ "$s" -eq 255 ] && s=254
echo "$s" > "$f.exit.tmp" && mv "$f.exit.tmp" "$f.exit"
) < /dev/null > /dev/null 2>&1 &
echo ` + name + `
` + followLoop(0)
}

// followScript continues a command started by startScript after the first
// offset bytes of its output.
func followScript(name string, offset int) string {
	return `f=` + runs + `/` + name + `
[ -f "$f" ] || { echo "The command's output is no longer on the server" >&2; exit 253; }
` + followLoop(offset)
}

// followLoop prints the output file as it grows, and exits with the command's
// status once it has ended.
func followLoop(offset int) string {
	return `n=` + strconv.Itoa(offset) + `
while :; do
  if [ -f "$f.exit" ]; then ended=1; else ended=0; fi
  size=$(wc -c < "$f") || exit 1; size=$((size))
  if [ "$size" -gt "$n" ]; then tail -c +$((n + 1)) "$f" | head -c $((size - n)) || exit 1; n=$size; fi
  if [ "$ended" = 1 ]; then exit "$(cat "$f.exit")"; fi
  sleep 1
done`
}

// firstLine passes output on, except a first line that is exactly want.
type firstLine struct {
	want          string
	next          io.Writer
	buf           []byte
	decided, seen bool
}

func (f *firstLine) Write(p []byte) (int, error) {
	if f.decided {
		return f.next.Write(p)
	}
	f.buf = append(f.buf, p...)
	end := bytes.IndexByte(f.buf, '\n')
	if end < 0 && len(f.buf) <= len(f.want) {
		return len(p), nil
	}
	f.decided = true
	rest := f.buf
	if end >= 0 && string(f.buf[:end]) == f.want {
		f.seen, rest = true, f.buf[end+1:]
	}
	f.buf = nil
	if _, err := f.next.Write(rest); err != nil {
		return 0, err
	}
	return len(p), nil
}

// flush passes on a short first line that never ended.
func (f *firstLine) flush() error {
	if f.decided || len(f.buf) == 0 {
		return nil
	}
	f.decided = true
	_, err := f.next.Write(f.buf)
	f.buf = nil
	return err
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

// line shows a note of the CLI's own on a line of its own.
func (i *indent) line(s string) {
	if i.mid {
		_, _ = i.Write([]byte("\n"))
	}
	_, _ = i.Write([]byte(s + "\n"))
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
