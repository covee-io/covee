package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/argon2"
)

// DefaultAccountsFile is where the broker keeps local accounts in its container.
const DefaultAccountsFile = "/var/lib/covee-identity/accounts.json"

const (
	accountsVersion = 1
	maxAccountsFile = 8 << 20
	totpPeriod      = 30
	lockAfter       = 5
	lockFor         = 15 * time.Minute
	// OWASP's argon2id baseline; the broker container is memory-limited.
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
)

// Account is one local (Covee) account. It never leaves the broker host.
type Account struct {
	// ID is 32 random bytes in base64url: the stable subject and WebAuthn user handle.
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Role         string    `json:"role"` // RoleAdmin, RoleReader or ""
	Enroll       bool      `json:"enroll"`
	Created      time.Time `json:"created"`
	Passkeys     []Passkey `json:"passkeys,omitempty"`
	PasswordHash string    `json:"password_hash,omitempty"` // argon2id PHC string
	TOTPSecret   string    `json:"totp_secret,omitempty"`   // base32, no padding
	TOTPLastStep int64     `json:"totp_last_step,omitempty"`
	Failures     int       `json:"failures,omitempty"`
	LockedUntil  time.Time `json:"locked_until,omitzero"`
	Invite       *Invite   `json:"invite,omitempty"`
	LastSignIn   time.Time `json:"last_sign_in,omitzero"`
}

// Passkey is a registered WebAuthn credential.
type Passkey struct {
	Credential webauthn.Credential `json:"credential"`
	Created    time.Time           `json:"created"`
	LastUsed   time.Time           `json:"last_used,omitzero"`
}

// Invite lets one person set up their account once.
type Invite struct {
	TokenSHA256  string                `json:"token_sha256"`
	Expires      time.Time             `json:"expires"`
	PendingTOTP  string                `json:"pending_totp,omitempty"`
	Registration *webauthn.SessionData `json:"registration,omitempty"`
}

type accountsDocument struct {
	Version  int       `json:"version"`
	Accounts []Account `json:"accounts"`
}

func (d *accountsDocument) byEmail(email string) int {
	for i := range d.Accounts {
		if d.Accounts[i].Email == email {
			return i
		}
	}
	return -1
}

func (d *accountsDocument) byID(id string) int {
	for i := range d.Accounts {
		if subtle.ConstantTimeCompare([]byte(d.Accounts[i].ID), []byte(id)) == 1 {
			return i
		}
	}
	return -1
}

// byInvite finds the account whose unexpired invite matches token.
func (d *accountsDocument) byInvite(token string, now time.Time) int {
	if len(token) < 32 || len(token) > 128 {
		return -1
	}
	sum := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(sum[:])
	found := -1
	for i := range d.Accounts {
		inv := d.Accounts[i].Invite
		if inv != nil && same(inv.TokenSHA256, want) && now.Before(inv.Expires) {
			found = i
		}
	}
	return found
}

// AccountStore is the accounts file, shared by the running broker and the
// admin subcommands through a lock file in the same directory.
type AccountStore struct{ path string }

func NewAccountStore(path string) *AccountStore { return &AccountStore{path: path} }

func (s *AccountStore) lock(how int) (func(), error) {
	if !filepath.IsAbs(s.path) {
		return nil, errors.New("accounts file path must be absolute")
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(s.path), "accounts.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("accounts lock unavailable")
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, errors.New("accounts lock unavailable")
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func (s *AccountStore) readUnlocked() (*accountsDocument, error) {
	doc := &accountsDocument{Version: accountsVersion}
	if _, err := os.Lstat(s.path); errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	b, err := privateFile(s.path, maxAccountsFile)
	if err != nil {
		return nil, errors.New("accounts file must be a bounded private regular file")
	}
	if err := json.Unmarshal(b, doc); err != nil || doc.Version != accountsVersion {
		return nil, errors.New("accounts file is unreadable")
	}
	return doc, nil
}

// Read returns a consistent snapshot of every account.
func (s *AccountStore) Read() (*accountsDocument, error) {
	unlock, err := s.lock(syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.readUnlocked()
}

// Update applies change to the accounts under an exclusive lock and replaces
// the file atomically. A change that returns an error writes nothing.
func (s *AccountStore) Update(change func(*accountsDocument) error) error {
	unlock, err := s.lock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock()
	doc, err := s.readUnlocked()
	if err != nil {
		return err
	}
	if err := change(doc); err != nil {
		return err
	}
	doc.Version = accountsVersion
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".accounts-*")
	if err != nil {
		return errors.New("accounts file cannot be written")
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("cryptographic randomness unavailable")
	}
	return b
}

func newAccountID() string { return base64.RawURLEncoding.EncodeToString(randomBytes(32)) }

// newInvite returns a token for the person and the invite to store.
func newInvite(now time.Time, lifetime time.Duration) (string, *Invite) {
	token := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	sum := sha256.Sum256([]byte(token))
	return token, &Invite{TokenSHA256: hex.EncodeToString(sum[:]), Expires: now.Add(lifetime).UTC().Truncate(time.Second)}
}

// normalizeEmail returns the lowercased address or an error.
func normalizeEmail(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) < 3 || len(v) > 254 || !textOK(v, 3, 254) || strings.ContainsAny(v, " <>\"") {
		return "", errors.New("invalid email address")
	}
	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Name != "" || addr.Address != v {
		return "", errors.New("invalid email address")
	}
	at := strings.LastIndexByte(v, '@')
	if at < 1 || !strings.Contains(v[at+1:], ".") || strings.HasSuffix(v, ".") {
		return "", errors.New("invalid email address")
	}
	return v, nil
}

// checkPassword applies the password policy.
func checkPassword(password, email string) error {
	n := utf8.RuneCountInString(password)
	if !utf8.ValidString(password) || n < 12 || n > 128 {
		return errors.New("use a password of 12 to 128 characters")
	}
	for _, r := range password {
		if r < 32 || r == 127 {
			return errors.New("the password contains control characters")
		}
	}
	if strings.EqualFold(password, email) {
		return errors.New("the password must not be the email address")
	}
	return nil
}

// hashPassword returns an argon2id PHC string.
func hashPassword(password string) string {
	salt := randomBytes(16)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// verifyPassword compares in constant time. Parameters come from the stored
// string but are bounded so a tampered file cannot exhaust memory.
func verifyPassword(phc, password string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m < 8*1024 || m > argonMemoryKiB || t < 1 || t > 10 || p < 1 || p > 4 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string { return base32NoPad.EncodeToString(randomBytes(20)) }

func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// totpMatch checks a 6-digit code against the current step ±1, never
// accepting a step at or before lastStep. It returns the matched step.
func totpMatch(secretB32, code string, now time.Time, lastStep int64) (int64, bool) {
	secret, err := base32NoPad.DecodeString(secretB32)
	if err != nil || len(secret) < 10 || len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	current := now.Unix() / totpPeriod
	matched, ok := int64(0), 0
	for step := current - 1; step <= current+1; step++ {
		if step > lastStep && subtle.ConstantTimeCompare([]byte(totpCode(secret, step)), []byte(code)) == 1 {
			matched, ok = step, 1
		}
	}
	return matched, ok == 1
}

func roleName(role string) string {
	switch role {
	case RoleAdmin:
		return "admin"
	case RoleReader:
		return "reader"
	}
	return "none"
}

func roleValue(name string) (string, error) {
	switch name {
	case "admin":
		return RoleAdmin, nil
	case "reader":
		return RoleReader, nil
	case "none":
		return "", nil
	}
	return "", errors.New("role must be admin, reader or none")
}
