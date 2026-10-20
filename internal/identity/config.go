// Package identity implements the optional subject-authorized identity broker.
// It has no self-registration, account linking or refresh tokens. Provider
// identities remain separate even when emails match. The optional "local"
// provider keeps operator-invited Covee accounts (passkeys, or a password
// with an authenticator code) in a private accounts file.
package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/go-jose/go-jose/v4"
)

const (
	GoogleIssuer = "https://accounts.google.com"
	AppleIssuer  = "https://appleid.apple.com"
	RoleAdmin    = "Covee.Admin"
	RoleReader   = "Covee.Reader"
)

type Config struct {
	Issuer         string           `json:"issuer"`
	Listen         string           `json:"listen"`
	TLSCertFile    string           `json:"tls_cert_file"`
	TLSKeyFile     string           `json:"tls_key_file"`
	SigningKeyFile string           `json:"signing_key_file"`
	Clients        []ClientConfig   `json:"clients"`
	Providers      []ProviderConfig `json:"providers"`
	Grants         []Grant          `json:"grants"`
}
type ClientConfig struct {
	ID          string `json:"id"`
	SecretFile  string `json:"secret_file"`
	RedirectURI string `json:"redirect_uri"`
	// ExtraRedirectURIs lets the console client return to its other origins,
	// such as its in-network address. Each is still matched exactly.
	ExtraRedirectURIs []string `json:"extra_redirect_uris,omitempty"`
	Kind              string   `json:"kind"`
}

// allowsRedirect reports whether uri is exactly one of the client's redirects.
func (c ClientConfig) allowsRedirect(uri string) bool {
	if uri == c.RedirectURI {
		return true
	}
	for _, extra := range c.ExtraRedirectURIs {
		if uri == extra {
			return true
		}
	}
	return false
}

type ProviderConfig struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	Issuer           string   `json:"issuer,omitempty"`
	ClientID         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file,omitempty"`
	AllowedGroupIDs  []string `json:"allowed_group_ids,omitempty"`
	TeamID           string   `json:"team_id,omitempty"`
	KeyID            string   `json:"key_id,omitempty"`
	PrivateKeyFile   string   `json:"private_key_file,omitempty"`
	// AccountsFile is set only for the "local" provider: Covee's own accounts.
	AccountsFile string `json:"accounts_file,omitempty"`
}
type Grant struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	Role     string `json:"role"`
	Enroll   bool   `json:"enroll"`
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var appleIDRE = regexp.MustCompile(`^[A-Z0-9]{10}$`)

func ReadConfig(path string) (Config, error) {
	var c Config
	b, err := privateFile(path, 1<<20)
	if err != nil {
		return c, errors.New("identity configuration must be a bounded private regular file")
	}
	if err := uniqueJSONKeys(b); err != nil {
		return c, errors.New("identity configuration has duplicate keys or excessive nesting")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid identity configuration JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("identity configuration contains trailing JSON")
	}
	return c, c.validate()
}

func (c Config) validate() error {
	u, err := httpsURL(c.Issuer)
	if err != nil || u.Path != "/identity" || strings.HasSuffix(c.Issuer, "/") {
		return errors.New("identity issuer must be an HTTPS origin followed by /identity")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return errors.New("identity listen must be host:port")
	}
	for _, path := range []string{c.TLSCertFile, c.TLSKeyFile, c.SigningKeyFile} {
		if !filepath.IsAbs(path) {
			return errors.New("identity TLS and signing key paths must be absolute")
		}
	}
	if len(c.Clients) == 0 || len(c.Clients) > 2 {
		return errors.New("identity needs one or two downstream clients")
	}
	ids, kinds := map[string]bool{}, map[string]bool{}
	for _, client := range c.Clients {
		if !textOK(client.ID, 1, 200) || ids[client.ID] || kinds[client.Kind] || (client.Kind != "enrollment" && client.Kind != "console") {
			return errors.New("invalid or duplicate identity client")
		}
		if _, err := httpsURL(client.RedirectURI); err != nil || !filepath.IsAbs(client.SecretFile) {
			return errors.New("identity clients need exact HTTPS redirects and absolute secret paths")
		}
		if len(client.ExtraRedirectURIs) > 0 && (client.Kind != "console" || len(client.ExtraRedirectURIs) > 2) {
			return errors.New("only the console client may have extra redirects, at most two")
		}
		for i, extra := range client.ExtraRedirectURIs {
			if _, err := httpsURL(extra); err != nil || extra == client.RedirectURI || (i == 1 && extra == client.ExtraRedirectURIs[0]) {
				return errors.New("identity client extra redirects must be distinct exact HTTPS URLs")
			}
		}
		ids[client.ID] = true
		kinds[client.Kind] = true
	}
	if len(c.Providers) == 0 || len(c.Providers) > 4 {
		return errors.New("identity needs one to four providers")
	}
	providers := map[string]bool{}
	for _, p := range c.Providers {
		if providers[p.ID] || p.Kind != p.ID {
			return errors.New("invalid or duplicate identity provider")
		}
		providers[p.ID] = true
		if p.ID == "local" {
			if !filepath.IsAbs(p.AccountsFile) || p.Issuer != "" || p.ClientID != "" || p.ClientSecretFile != "" || len(p.AllowedGroupIDs) > 0 || p.TeamID != "" || p.KeyID != "" || p.PrivateKeyFile != "" {
				return errors.New("local accounts need only an absolute accounts file")
			}
			continue
		}
		if !textOK(p.ClientID, 1, 200) || p.AccountsFile != "" {
			return errors.New("invalid or duplicate identity provider")
		}
		switch p.ID {
		case "entra":
			prefix := "https://login.microsoftonline.com/"
			tenant := strings.TrimSuffix(strings.TrimPrefix(p.Issuer, prefix), "/v2.0")
			if !strings.HasPrefix(p.Issuer, prefix) || p.Issuer != prefix+tenant+"/v2.0" || !uuidRE.MatchString(tenant) || !filepath.IsAbs(p.ClientSecretFile) || p.TeamID != "" || p.KeyID != "" || p.PrivateKeyFile != "" {
				return errors.New("Entra needs a tenant-specific v2 issuer and secret file")
			}
			seen := map[string]bool{}
			for _, g := range p.AllowedGroupIDs {
				if !uuidRE.MatchString(g) || seen[strings.ToLower(g)] {
					return errors.New("invalid or duplicate Entra enrollment group")
				}
				seen[strings.ToLower(g)] = true
			}
		case "google":
			if (p.Issuer != "" && p.Issuer != GoogleIssuer) || !filepath.IsAbs(p.ClientSecretFile) || len(p.AllowedGroupIDs) > 0 || p.TeamID != "" || p.KeyID != "" || p.PrivateKeyFile != "" {
				return errors.New("Google provider only accepts its fixed issuer and client secret")
			}
		case "apple":
			if (p.Issuer != "" && p.Issuer != AppleIssuer) || p.ClientSecretFile != "" || len(p.AllowedGroupIDs) > 0 || !appleIDRE.MatchString(p.TeamID) || !appleIDRE.MatchString(p.KeyID) || !filepath.IsAbs(p.PrivateKeyFile) {
				return errors.New("Apple needs its fixed issuer, team ID, key ID and private key file")
			}
		default:
			return errors.New("unknown identity provider")
		}
	}
	if len(c.Grants) > 10000 {
		return errors.New("too many identity grants")
	}
	seen := map[string]bool{}
	for _, g := range c.Grants {
		key := g.Provider + "\x00" + g.Subject
		if (g.Provider != "google" && g.Provider != "apple") || !providers[g.Provider] || !textOK(g.Subject, 1, 512) || (g.Role != "" && g.Role != RoleAdmin && g.Role != RoleReader) || seen[key] {
			return errors.New("invalid or duplicate subject grant")
		}
		seen[key] = true
	}
	return nil
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.RawPath != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(raw, "\r\n\t ") {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}
func uniqueJSONKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting exceeds limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON key")
				}
				seen[key] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func textOK(value string, min, max int) bool {
	if len(value) < min || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func privateFile(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("private file path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, errors.New("private file must be a bounded owner-only regular file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("private file owner mismatch")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("private file changed during open")
	}
	b, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("private file exceeds limit")
	}
	return b, nil
}
func readSecret(path string, min int) (string, error) {
	b, err := privateFile(path, 16<<10)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(b))
	if !textOK(value, min, 16<<10) {
		return "", errors.New("invalid secret file")
	}
	return value, nil
}
func readSigningKey(path string) (*rsa.PrivateKey, error) {
	b, err := privateFile(path, 32<<10)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid broker signing PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("broker signing key must be PKCS8 RSA")
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() < 2048 || rsaKey.N.BitLen() > 8192 {
		return nil, errors.New("broker signing RSA key must be 2048 to 8192 bits")
	}
	if err := rsaKey.Validate(); err != nil {
		return nil, err
	}
	return rsaKey, nil
}
func readAppleKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := privateFile(path, 16<<10)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid Apple signing PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Apple key must be PKCS8 EC")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("Apple key must be P-256")
	}
	return ec, nil
}
func keyID(key *rsa.PrivateKey) string {
	thumb, _ := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	return base64URL(thumb)
}
