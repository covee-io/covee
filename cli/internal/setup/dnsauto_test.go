package setup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"covee.io/cli/internal/prompt"
)

type memIAM struct {
	mu       sync.Mutex
	users    map[string]bool
	policies map[string]string
	keys     map[string][]string
	created  int
}

func newMemIAM() *memIAM {
	return &memIAM{users: map[string]bool{}, policies: map[string]string{}, keys: map[string][]string{}}
}

func missingUser() error {
	return &iamtypes.NoSuchEntityException{Message: aws.String("The user cannot be found.")}
}

func (m *memIAM) GetUser(_ context.Context, in *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.users[aws.ToString(in.UserName)] {
		return nil, missingUser()
	}
	return &iam.GetUserOutput{User: &iamtypes.User{UserName: in.UserName}}, nil
}

// iamTagValue is the pattern IAM requires of tag keys and values.
var iamTagValue = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)

func (m *memIAM) CreateUser(_ context.Context, in *iam.CreateUserInput, _ ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tag := range in.Tags {
		if !iamTagValue.MatchString(aws.ToString(tag.Key)) || !iamTagValue.MatchString(aws.ToString(tag.Value)) || len(aws.ToString(tag.Value)) > 256 {
			return nil, fmt.Errorf("ValidationError: tag %q=%q does not satisfy IAM's pattern", aws.ToString(tag.Key), aws.ToString(tag.Value))
		}
	}
	m.users[aws.ToString(in.UserName)] = true
	return &iam.CreateUserOutput{}, nil
}

func (m *memIAM) PutUserPolicy(_ context.Context, in *iam.PutUserPolicyInput, _ ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[aws.ToString(in.UserName)+"/"+aws.ToString(in.PolicyName)] = aws.ToString(in.PolicyDocument)
	return &iam.PutUserPolicyOutput{}, nil
}

func (m *memIAM) DeleteUserPolicy(_ context.Context, in *iam.DeleteUserPolicyInput, _ ...func(*iam.Options)) (*iam.DeleteUserPolicyOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, aws.ToString(in.UserName)+"/"+aws.ToString(in.PolicyName))
	return &iam.DeleteUserPolicyOutput{}, nil
}

func (m *memIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user := aws.ToString(in.UserName)
	if !m.users[user] {
		return nil, missingUser()
	}
	out := &iam.ListAccessKeysOutput{}
	for _, id := range m.keys[user] {
		out.AccessKeyMetadata = append(out.AccessKeyMetadata, iamtypes.AccessKeyMetadata{AccessKeyId: aws.String(id), Status: iamtypes.StatusTypeActive})
	}
	return out, nil
}

func (m *memIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.created++
	user := aws.ToString(in.UserName)
	if len(m.keys[user]) >= 2 {
		return nil, errors.New("LimitExceeded: cannot exceed quota for AccessKeysPerUser: 2")
	}
	id := fmt.Sprintf("AKIATESTKEY%09d", m.created)
	m.keys[user] = append(m.keys[user], id)
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{AccessKeyId: aws.String(id), SecretAccessKey: aws.String(fmt.Sprintf("secret-access-key-number-%d-0123456789", m.created))}}, nil
}

func (m *memIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user := aws.ToString(in.UserName)
	var kept []string
	for _, id := range m.keys[user] {
		if id != aws.ToString(in.AccessKeyId) {
			kept = append(kept, id)
		}
	}
	m.keys[user] = kept
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (m *memIAM) DeleteUser(_ context.Context, in *iam.DeleteUserInput, _ ...func(*iam.Options)) (*iam.DeleteUserOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, aws.ToString(in.UserName))
	return &iam.DeleteUserOutput{}, nil
}

// updaterArchive is a payload holding only the updater script.
func updaterArchive(script string) func() ([]byte, string, error) {
	return func() ([]byte, string, error) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: "scripts/dns_updater.py", Mode: 0o644, Size: int64(len(script)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(script))
		_ = tw.Close()
		_ = gz.Close()
		return buf.Bytes(), "0123456789abcdef0123456789abcdef", nil
	}
}

func setUpHome(t *testing.T, h *harness, extra map[string]string) {
	t.Helper()
	h.env.Ask = h.answers(extra)
	if err := Run(context.Background(), h.env, Options{Network: "home"}); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
}

func TestDNSAutoTurnsOnTheAddressUpdater(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	h.env.Archive = updaterArchive("# updater v1\n")
	h.env.Ask = h.answers(nil)
	if err := DNSAuto(ctx, h.env, "home"); err != nil {
		t.Fatalf("dns auto: %v\n%s", err, h.out)
	}

	// The IAM user may only change this one record.
	policy := h.iam.policies["covee-home-dns/covee-dns-updater"]
	for _, want := range []string{`"arn:aws:route53:::hostedzone/ZTEST"`, `"control.coveetest.io"`, `"UPSERT"`, `"route53:ListResourceRecordSets"`} {
		if !strings.Contains(policy, want) {
			t.Fatalf("policy lacks %s: %s", want, policy)
		}
	}
	// Its key is in Parameter Store and on the server, nowhere in the record.
	stored := h.ssm.values["/covee/home/dns-updater-key"]
	if !strings.Contains(stored, "AKIATESTKEY000000001") || h.file(t, updaterKeyFile) != stored {
		t.Fatalf("key not stored or not copied: %q", stored)
	}
	raw, _ := os.ReadFile(filepath.Join(h.env.Home, "networks", "home.json"))
	if strings.Contains(string(raw), "secret-access-key") {
		t.Fatal("the record contains the secret access key")
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(h.file(t, updaterConfig)), &config); err != nil {
		t.Fatal(err)
	}
	if config["hostname"] != "control.coveetest.io" || config["zone_id"] != "ZTEST" || config["verify"] != true || config["credentials"] != updaterKeyFile {
		t.Fatalf("updater config = %v", config)
	}
	if h.file(t, updaterScript) != "# updater v1\n" {
		t.Fatal("updater script not installed")
	}
	unit, _ := os.ReadFile(filepath.Join(h.state, "units", "covee-dns.service"))
	if !strings.Contains(string(unit), "ExecStart=/usr/bin/python3 "+updaterScript+" --config "+updaterConfig) || !strings.Contains(string(unit), "User=covee") {
		t.Fatalf("service unit = %s", unit)
	}
	if actions, _ := os.ReadFile(filepath.Join(h.state, "units", "actions")); !strings.Contains(string(actions), "dns-started") {
		t.Fatal("the updater did not run once")
	}
	n, _ := h.env.Records.Load("home")
	if u := n.DNS.Updater; u == nil || !n.DNS.Dynamic || u.IAMUser != "covee-home-dns" || u.AccessKeyID != "AKIATESTKEY000000001" || u.SecretName != "/covee/home/dns-updater-key" || !u.Verify {
		t.Fatalf("record = %+v %+v", n.DNS, n.DNS.Updater)
	}

	// Running it again keeps the working key.
	if err := DNSAuto(ctx, h.env, "home"); err != nil || h.iam.created != 1 {
		t.Fatalf("second run: %v, keys created %d", err, h.iam.created)
	}
	// A key that AWS no longer has is replaced, and the copies follow.
	h.iam.keys["covee-home-dns"] = nil
	if err := DNSAuto(ctx, h.env, "home"); err != nil || h.iam.created != 2 {
		t.Fatalf("replacement: %v, keys created %d", err, h.iam.created)
	}
	if stored := h.ssm.values["/covee/home/dns-updater-key"]; !strings.Contains(stored, "AKIATESTKEY000000002") || h.file(t, updaterKeyFile) != stored {
		t.Fatal("the replacement key was not stored and copied")
	}

	// `covee update` refreshes the script from its own Covee files.
	h.env.Archive = updaterArchive("# updater v2\n")
	if err := Update(ctx, h.env, "home"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if h.file(t, updaterScript) != "# updater v2\n" {
		t.Fatal("update did not refresh the updater script")
	}

	h.out.Reset()
	if err := Status(ctx, h.env, "home"); err != nil || !strings.Contains(h.out.String(), "Address updater: on, last check Mon 2026-10-12 23:55:00 UTC: success") {
		t.Fatalf("status: %v\n%s", err, h.out)
	}

	// Turning it off removes it from the server and deletes the IAM user.
	if err := DNSAutoOff(ctx, h.env, "home"); err != nil {
		t.Fatalf("off: %v", err)
	}
	off, _ := os.ReadFile(filepath.Join(h.state, "dns-off"))
	for _, path := range []string{updaterKeyFile, updaterConfig, updaterScript, "/etc/systemd/system/covee-dns.timer"} {
		if !strings.Contains(string(off), path) {
			t.Fatalf("off did not remove %s: %s", path, off)
		}
	}
	if h.iam.users["covee-home-dns"] || len(h.iam.keys["covee-home-dns"]) != 0 || h.iam.policies["covee-home-dns/covee-dns-updater"] != "" {
		t.Fatal("the IAM user, key or policy remains")
	}
	n, _ = h.env.Records.Load("home")
	if n.DNS.Updater != nil || n.DNS.Dynamic {
		t.Fatalf("record still has the updater: %+v", n.DNS)
	}
}

func TestSetupWithAChangingAddressInstallsTheUpdater(t *testing.T) {
	h := newHarness(t)
	h.env.Archive = updaterArchive("# updater\n")
	setUpHome(t, h, map[string]string{"dynamic_address": "yes"})
	n, _ := h.env.Records.Load("home")
	if !n.Done("dns-updater") || n.DNS.Updater == nil || !n.DNS.Dynamic {
		t.Fatalf("updater not set up: %v %+v", n.Completed, n.DNS)
	}
	if !strings.Contains(h.out.String(), "checks the public address every 5 minutes") {
		t.Fatalf("the summary does not mention the updater:\n%s", h.out)
	}
	if h.iam.created != 1 || h.file(t, updaterScript) != "# updater\n" {
		t.Fatal("the updater's key or script is missing")
	}
}

func TestDNSAutoAsksBeforeTakingOverADifferentAddress(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	h.env.Archive = updaterArchive("# updater\n")
	check := `{"action": "checked", "hostname": "control.coveetest.io", "public": "198.51.100.4", "record": ["203.0.113.9"], "serves": false}`
	if err := os.WriteFile(filepath.Join(h.state, "dns-check.json"), []byte(check), 0o600); err != nil {
		t.Fatal(err)
	}
	h.env.Ask = h.answers(nil)
	if err := DNSAuto(ctx, h.env, "home"); !errors.Is(err, prompt.ErrAborted) {
		t.Fatalf("expected a refusal by default, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.state, "units", "covee-dns.timer")); err == nil {
		t.Fatal("the timer was installed although the owner declined")
	}
	if n, _ := h.env.Records.Load("home"); n.DNS.Updater != nil {
		t.Fatal("declined updater recorded")
	}

	h.env.Ask = h.answers(map[string]string{"dns_updater_replace": "yes"})
	if err := DNSAuto(ctx, h.env, "home"); err != nil {
		t.Fatalf("accepted: %v", err)
	}
	var config map[string]any
	_ = json.Unmarshal([]byte(h.file(t, updaterConfig)), &config)
	n, _ := h.env.Records.Load("home")
	if config["verify"] != false || n.DNS.Updater.Verify {
		t.Fatalf("without a loop-back the updater must not test new addresses: %v", config)
	}
	if !strings.Contains(h.out.String(), "will not test a new address") {
		t.Fatalf("no explanation given:\n%s", h.out)
	}
}

func TestDNSAutoRetriesWhileANewKeyBecomesUsable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setUpHome(t, h, nil)
	h.env.Archive = updaterArchive("# updater\n")
	h.env.Ask = h.answers(nil)
	defer func(d time.Duration) { updaterRetryDelay = d }(updaterRetryDelay)
	updaterRetryDelay = time.Millisecond
	if err := os.WriteFile(filepath.Join(h.state, "fail-dns-check"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := DNSAuto(ctx, h.env, "home")
	if err == nil || !strings.Contains(err.Error(), "first check failed") {
		t.Fatalf("expected the check failure, got %v", err)
	}
	if log, _ := os.ReadFile(filepath.Join(h.state, "log")); strings.Count(string(log), "--check") != 8 {
		t.Fatalf("expected 8 attempts with a new key:\n%s", log)
	}
	// With the key now stored, a rerun does not create another one and does not wait.
	os.Remove(filepath.Join(h.state, "fail-dns-check"))
	if err := DNSAuto(ctx, h.env, "home"); err != nil || h.iam.created != 1 {
		t.Fatalf("rerun: %v, keys created %d", err, h.iam.created)
	}
}
