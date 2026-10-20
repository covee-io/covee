package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func copyConfig(t *testing.T, c Config) Config {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var clone Config
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
func TestConfigurationStrictness(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"HTTP issuer", func(c *Config) { c.Issuer = "http://control.example/identity" }},
		{"issuer wrong path", func(c *Config) { c.Issuer = "https://control.example" }},
		{"issuer escaped path", func(c *Config) { c.Issuer = "https://control.example/%69dentity" }},
		{"issuer query", func(c *Config) { c.Issuer += "?next=bad" }},
		{"relative key", func(c *Config) { c.SigningKeyFile = "key.pem" }},
		{"missing listen", func(c *Config) { c.Listen = "" }},
		{"no clients", func(c *Config) { c.Clients = nil }},
		{"duplicate clients", func(c *Config) { c.Clients[1].ID = c.Clients[0].ID }},
		{"duplicate kind", func(c *Config) { c.Clients[1].Kind = c.Clients[0].Kind }},
		{"unknown client kind", func(c *Config) { c.Clients[0].Kind = "admin" }},
		{"redirect credentials", func(c *Config) { c.Clients[0].RedirectURI = "https://user:pass@console.example/callback" }},
		{"redirect HTTP", func(c *Config) { c.Clients[0].RedirectURI = "http://console.example/callback" }},
		{"redirect query", func(c *Config) { c.Clients[0].RedirectURI += "?return=bad" }},
		{"no providers", func(c *Config) { c.Providers = nil }},
		{"duplicate provider", func(c *Config) { c.Providers[1] = c.Providers[0] }},
		{"provider mismatch", func(c *Config) { c.Providers[0].Kind = "apple" }},
		{"unknown provider", func(c *Config) { c.Providers[0].ID = "other"; c.Providers[0].Kind = "other" }},
		{"Google unknownissuer", func(c *Config) { c.Providers[0].Issuer = "https://attacker.example" }},
		{"Google groupauthorization", func(c *Config) { c.Providers[0].AllowedGroupIDs = []string{"11234567-89ab-cdef-0123-456789abcdef"} }},
		{"Apple staticsecret", func(c *Config) { c.Providers[1].ClientSecretFile = "/private/key" }},
		{"Apple invalidteam", func(c *Config) { c.Providers[1].TeamID = "bad" }},
		{"Apple unknownissuer", func(c *Config) { c.Providers[1].Issuer = "https://attacker.example" }},
		{"Entra commonissuer", func(c *Config) { c.Providers[2].Issuer = "https://login.microsoftonline.com/common/v2.0" }},
		{"Entra invalidgroup", func(c *Config) { c.Providers[2].AllowedGroupIDs = []string{"email@example.com"} }},
		{"Entra duplicategroup", func(c *Config) {
			c.Providers[2].AllowedGroupIDs = append(c.Providers[2].AllowedGroupIDs, c.Providers[2].AllowedGroupIDs[0])
		}},
		{"grant Entra", func(c *Config) { c.Grants[0].Provider = "entra" }},
		{"grant unknownprovider", func(c *Config) { c.Grants[0].Provider = "other" }},
		{"grant unknownrole", func(c *Config) { c.Grants[0].Role = "Admin" }},
		{"grant controlsubject", func(c *Config) { c.Grants[0].Subject = "bad\nsubject" }},
		{"grant duplicate", func(c *Config) { c.Grants = append(c.Grants, c.Grants[0]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := copyConfig(t, f.server.config)
			tc.mutate(&c)
			if c.validate() == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	c := copyConfig(t, f.server.config)
	c.Grants = nil
	if c.validate() != nil {
		t.Fatal("empty grants must deny all, not prevent startup")
	}
}

func TestReadConfigPrivateStrictJSON(t *testing.T) {
	f := newFixture(t)
	raw, err := json.Marshal(f.server.config)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := writePrivate(t, dir, "config.json", raw)
	if _, err := ReadConfig(path); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{string(raw) + ` {}`, strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`, strings.TrimSuffix(string(raw), "}") + `,"issuer":"https://attacker.example/identity"}`, strings.Replace(string(raw), `"enroll":true`, `"enroll":"true"`, 1), strings.Replace(string(raw), `"enroll":true`, `"enroll":true,"enroll":false`, 1)} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConfig(path); err == nil {
			t.Fatalf("accepted ambiguous JSON %s", body)
		}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(path); err == nil {
		t.Fatal("public config accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if _, err := ReadConfig(link); err == nil {
		t.Fatal("symlink config accepted")
	}
	if uniqueJSONKeys([]byte(strings.Repeat("[", 34)+"0"+strings.Repeat("]", 34))) == nil {
		t.Fatal("excessive nesting accepted")
	}
}

func TestSigningAndSecretFilesFailClosed(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	path := writePrivate(t, dir, "small", pkcs8(t, small))
	if _, err := readSigningKey(path); err == nil {
		t.Fatal("small RSA accepted")
	}
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path = writePrivate(t, dir, "ec", pkcs8(t, ec))
	if _, err := readSigningKey(path); err == nil {
		t.Fatal("EC broker key accepted")
	}
	if _, err := readAppleKey(path); err == nil {
		t.Fatal("P384 Apple key accepted")
	}
	path = writePrivate(t, dir, "secret", []byte("short"))
	if _, err := readSecret(path, 32); err == nil {
		t.Fatal("short downstream secret")
	}
	os.Chmod(path, 0644)
	if _, err := readSecret(path, 1); err == nil {
		t.Fatal("public secret")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if _, err := readSecret(link, 1); err == nil {
		t.Fatal("symlink secret")
	}
	c := copyConfig(t, f.server.config)
	c.SigningKeyFile = path
	if _, err := New(context.Background(), c); err == nil {
		t.Fatal("invalid key allowed")
	}
	c = copyConfig(t, f.server.config)
	c.TLSKeyFile = path
	if _, err := New(context.Background(), c); err == nil {
		t.Fatal("invalid TLS pair allowed")
	}
}

func TestHealthVerifiedLocalTLS(t *testing.T) {
	f := newFixture(t)
	c := copyConfig(t, f.server.config)
	u, _ := url.Parse(f.broker.URL)
	c.Listen = u.Host
	if err := CheckHealth(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Issuer = "https://wrong.example/identity"
	if err := CheckHealth(context.Background(), c); err == nil {
		t.Fatal("wrong public Host accepted by health")
	}
	c = copyConfig(t, f.server.config)
	c.Listen = "127.0.0.1:1"
	if err := CheckHealth(context.Background(), c); err == nil {
		t.Fatal("missing service healthy")
	}
}

func TestAnonymousStartRateLimitAndNoForwardedTrust(t *testing.T) {
	f := newFixture(t)
	sum := strings.Repeat("A", 43)
	q := url.Values{"client_id": {"console"}, "redirect_uri": {f.server.clients["console"].config.RedirectURI}, "response_type": {"code"}, "scope": {"openid"}, "nonce": {strings.Repeat("n", 20)}, "state": {strings.Repeat("s", 20)}, "code_challenge": {sum}, "code_challenge_method": {"S256"}}
	f.server.mu.Lock()
	f.server.startTokens = 0
	f.server.startUpdated = time.Now()
	f.server.mu.Unlock()
	r := f.request("GET", "/identity/authorize?"+q.Encode(), nil, nil, "")
	if r.StatusCode != 429 || r.Header.Get("Retry-After") != "1" {
		t.Fatal("anonymous starts unbounded", r.StatusCode)
	}
	r.Body.Close()
	f.server.mu.Lock()
	count := len(f.server.flows)
	f.server.startUpdated = time.Now().Add(-time.Second * 2)
	f.server.mu.Unlock()
	if count != 0 {
		t.Fatal("rate limited request created flow")
	}
	r = f.request("GET", "/identity/authorize?"+q.Encode(), nil, nil, "")
	if r.StatusCode != 200 {
		t.Fatal("rate limit did not refill", r.StatusCode)
	}
	r.Body.Close()
	request, _ := http.NewRequest("GET", f.broker.URL+"/identity/healthz", nil)
	request.Host = "wrong.example"
	request.Header.Set("Forwarded", "host="+strings.TrimPrefix(f.broker.URL, "https://"))
	request.Header.Set("X-Forwarded-Host", strings.TrimPrefix(f.broker.URL, "https://"))
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 400 {
		t.Fatal("forwarded host trusted")
	}
	response.Body.Close()
}

func TestDuplicateParametersAndNonTLSRejected(t *testing.T) {
	f := newFixture(t)
	flow := f.start("console", "google")
	params := url.Values{"state": {flow.state, flow.state}, "code": {"bad"}}
	r := f.request("GET", "/identity/callback/google?"+params.Encode(), nil, flow.cookie, "")
	if r.StatusCode != 400 {
		t.Fatal("duplicate state accepted")
	}
	r.Body.Close()
	issuedCode(t, f.callback(flow, "google", "social-person", nil))
	request, _ := http.NewRequest("GET", f.broker.URL+"/identity/healthz", nil)
	request.TLS = nil
	// Handler-level request with no TLS must fail even if Host is correct.
	recorder := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 400 {
		t.Fatal("plain HTTP accepted")
	}
}
