// Package record keeps the CLI's notes about each network it built: the
// server, the DNS record, the sign-in app IDs and where each secret lives.
// A record never contains a secret value.
package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// SchemaVersion is the record format written by this CLI.
const SchemaVersion = 1

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// CheckName validates a network name: lowercase letters, digits and dashes.
func CheckName(name string) error {
	if !nameRE.MatchString(name) {
		return errors.New("use 2 to 32 lowercase letters, digits or dashes, starting with a letter")
	}
	return nil
}

// Network is everything the CLI needs to manage one network later.
type Network struct {
	SchemaVersion int       `json:"schema_version"`
	Organization  string    `json:"organization"`
	Name          string    `json:"name"`
	Created       time.Time `json:"created"`
	Updated       time.Time `json:"updated"`
	// Completed lists finished setup steps so an interrupted setup resumes.
	Completed []string `json:"completed,omitempty"`

	Hostname      string `json:"hostname"`
	PublicAddress string `json:"public_address,omitempty"`
	DNSBaseDomain string `json:"dns_base_domain,omitempty"`

	DNS DNS `json:"dns"`
	// ConsoleInNetwork serves the admin console inside the network, at
	// https://console.<DNSBaseDomain>, to devices in the network only.
	ConsoleInNetwork bool `json:"console_in_network,omitempty"`
	// Gateway runs the network's gateway device on the server; what goes
	// through it is chosen on the console's Gateway page.
	Gateway bool    `json:"gateway,omitempty"`
	Server  Server  `json:"server"`
	Secrets Secrets `json:"secrets"`
	// Providers lists the chosen sign-in methods: entra, google, apple.
	Providers []string `json:"providers"`
	SignIn    SignIn   `json:"sign_in"`

	Certificate *Certificate `json:"certificate,omitempty"`
	Runtime     string       `json:"runtime,omitempty"`
	Payload     string       `json:"payload_sha256,omitempty"`

	// BackupRecipient is the public age key backups are encrypted to; its
	// private identity lives only in the secrets store.
	BackupRecipient string   `json:"backup_recipient,omitempty"`
	Backups         []Backup `json:"backups,omitempty"`

	// RestoredFrom is set when setup started from a backup instead of an empty network.
	RestoredFrom *Restored `json:"restored_from,omitempty"`
}

// Backup is one encrypted snapshot of the network's runtime.
type Backup struct {
	Created time.Time `json:"created"`
	File    string    `json:"file"`
	Server  string    `json:"server_file"`
	SHA256  string    `json:"sha256"`
	Bytes   int64     `json:"bytes"`
	Files   int       `json:"files_verified"`
}

// DNS records the domain host.
type DNS struct {
	Host   string `json:"host"` // "route53", "cloudflare" or "manual"
	ZoneID string `json:"zone_id,omitempty"`
	Zone   string `json:"zone,omitempty"`
	// Token is where the Cloudflare API token lives.
	Token string `json:"token,omitempty"`
	// Dynamic is set when the public address can change (a home or office
	// connection); setup then installs the address updater.
	Dynamic bool        `json:"dynamic_address,omitempty"`
	Updater *DNSUpdater `json:"updater,omitempty"`
}

// DNSUpdater is the server's job that keeps the hostname pointing at the
// connection's public address, using its own narrowly limited AWS key.
type DNSUpdater struct {
	IAMUser     string    `json:"iam_user"`
	AccessKeyID string    `json:"access_key_id"`
	SecretName  string    `json:"secret"`
	Verify      bool      `json:"verify_before_change"`
	Installed   time.Time `json:"installed"`
}

// Server records how the CLI reaches the network server.
type Server struct {
	Kind        string   `json:"kind"` // "ssh" (existing server) or "proxmox" (VM created by setup)
	Address     string   `json:"address"`
	AdminUser   string   `json:"admin_user"`
	ServiceUser string   `json:"service_user"`
	SSHKey      string   `json:"ssh_key_secret"`
	HostKey     string   `json:"host_key,omitempty"`
	SSHSources  []string `json:"ssh_source_cidrs,omitempty"`
	Interface   string   `json:"interface,omitempty"`
	IPv4CIDR    string   `json:"ipv4_cidr,omitempty"`
	Proxmox     *Proxmox `json:"proxmox,omitempty"`
}

// Proxmox records the VM setup created and the host that runs it.
type Proxmox struct {
	Host           string   `json:"host"`
	User           string   `json:"user"`
	Node           string   `json:"node"`
	VMID           int      `json:"vmid"`
	Name           string   `json:"name"`
	Storage        string   `json:"storage"`
	SnippetStorage string   `json:"snippet_storage"`
	SnippetDir     string   `json:"snippet_directory"`
	Bridge         string   `json:"bridge"`
	Gateway        string   `json:"gateway"`
	DNSServers     []string `json:"dns_servers"`
	Cores          int      `json:"cores"`
	MemoryMiB      int      `json:"memory_mib"`
	DiskGiB        int      `json:"disk_gib"`
}

// Restored records the backup a network was rebuilt from.
type Restored struct {
	File       string    `json:"file"`
	SHA256     string    `json:"sha256"`
	SourceHost string    `json:"source_host"`
	Grants     int       `json:"grants"`
	At         time.Time `json:"restored_at,omitempty"`
}

// Secrets records the chosen secrets store. Values live only in the store,
// in the CLI's private local folder and on the server.
type Secrets struct {
	Store  string `json:"store"` // "ssm" or "local"
	Region string `json:"region,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

// SignIn records each enabled provider's public identifiers.
type SignIn struct {
	Entra  *Entra  `json:"entra,omitempty"`
	Google *Google `json:"google,omitempty"`
	Apple  *Apple  `json:"apple,omitempty"`
	Local  *Local  `json:"local,omitempty"`
}

// Local records that Covee accounts (passkeys or passwords kept by the
// network itself) are on, and who setup invited first.
type Local struct {
	FirstAdmin     string `json:"first_admin,omitempty"`
	FirstAdminName string `json:"first_admin_name,omitempty"`
}

type Entra struct {
	TenantID      string    `json:"tenant_id"`
	TenantName    string    `json:"tenant_name,omitempty"`
	ClientID      string    `json:"client_id"`
	AppObjectID   string    `json:"app_object_id"`
	GroupID       string    `json:"group_id"`
	GroupName     string    `json:"group_name,omitempty"`
	SecretName    string    `json:"secret"`
	SecretKeyID   string    `json:"secret_key_id,omitempty"`
	SecretExpires time.Time `json:"secret_expires"`
}

type Google struct {
	ClientID   string `json:"client_id"`
	SecretName string `json:"secret"`
}

type Apple struct {
	TeamID     string `json:"team_id"`
	ServicesID string `json:"services_id"`
	KeyID      string `json:"key_id"`
	SecretName string `json:"secret"`
}

// Certificate records the public certificate's validity.
type Certificate struct {
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	KeySecret  string    `json:"key_secret"`
	Staging    bool      `json:"staging,omitempty"`
	AccountKey string    `json:"account_key_secret,omitempty"`
}

// Done reports whether a setup step already finished.
func (n *Network) Done(step string) bool {
	for _, s := range n.Completed {
		if s == step {
			return true
		}
	}
	return false
}

// Mark records a finished step.
func (n *Network) Mark(step string) {
	if !n.Done(step) {
		n.Completed = append(n.Completed, step)
	}
}

// Unmark forgets finished steps so they run again.
func (n *Network) Unmark(steps ...string) {
	var keep []string
	for _, s := range n.Completed {
		drop := false
		for _, x := range steps {
			drop = drop || s == x
		}
		if !drop {
			keep = append(keep, s)
		}
	}
	n.Completed = keep
}

// Store reads and writes records in a private directory.
type Store struct{ Dir string }

// Home returns the CLI's private configuration directory.
func Home() (string, error) {
	if v := os.Getenv("COVEE_HOME"); v != "" {
		return v, nil
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "covee"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "covee"), nil
}

// Open returns the record store under home.
func Open(home string) (*Store, error) {
	dir := filepath.Join(home, "networks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name+".json") }

// ErrNotFound reports a network with no record.
var ErrNotFound = errors.New("no such network")

// Load reads one network record.
func (s *Store) Load(name string) (*Network, error) {
	if err := CheckName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w %q", ErrNotFound, name)
	}
	if err != nil {
		return nil, err
	}
	var n Network
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, fmt.Errorf("record for %q is unreadable: %w", name, err)
	}
	if n.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("record for %q uses format %d; this CLI reads format %d", name, n.SchemaVersion, SchemaVersion)
	}
	return &n, nil
}

// Save writes a record atomically.
func (s *Store) Save(n *Network) error {
	if err := CheckName(n.Name); err != nil {
		return err
	}
	n.SchemaVersion = SchemaVersion
	now := time.Now().UTC().Truncate(time.Second)
	if n.Created.IsZero() {
		n.Created = now
	}
	n.Updated = now
	b, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path(n.Name))
}

// List returns all records, sorted by name.
func (s *Store) List() ([]*Network, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []*Network
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		n, err := s.Load(name[:len(name)-len(".json")])
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
