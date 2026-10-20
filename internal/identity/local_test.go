package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"golang.org/x/oauth2"
)

// localFixture serves the broker as https://example.com:<port> (a name in the
// httptest certificate), because a passkey relying party must be a DNS name.
type localFixture struct {
	t        *testing.T
	server   *Server
	broker   *httptest.Server
	origin   string
	accounts string
	client   *http.Client
}

func newLocalFixture(t *testing.T) *localFixture {
	t.Helper()
	f := &localFixture{t: t}
	var handler http.Handler
	f.broker = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(f.broker.Close)
	_, port, _ := net.SplitHostPort(f.broker.Listener.Addr().String())
	f.origin = "https://example.com:" + port
	dir := t.TempDir()
	f.accounts = filepath.Join(dir, "accounts.json")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secret := writePrivate(t, dir, "secret", []byte(strings.Repeat("x", 48)))
	signing := writePrivate(t, dir, "key", pkcs8(t, key))
	cert := writePrivate(t, dir, "tls-cert", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.broker.TLS.Certificates[0].Certificate[0]}))
	tlsKey := writePrivate(t, dir, "tls-key", pkcs8(t, f.broker.TLS.Certificates[0].PrivateKey))
	c := Config{Issuer: f.origin + "/identity", Listen: ":8446", TLSCertFile: cert, TLSKeyFile: tlsKey, SigningKeyFile: signing,
		Clients: []ClientConfig{{ID: "console", SecretFile: secret, RedirectURI: "https://console.example.test/auth/oidc/callback", Kind: "console"},
			{ID: "enrollment", SecretFile: secret, RedirectURI: "https://control.example.test/oidc/callback", Kind: "enrollment"}},
		Providers: []ProviderConfig{{ID: "local", Kind: "local", AccountsFile: f.accounts}}}
	f.server, err = New(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	f.server.local.burst, f.server.local.tokens = 1000, 1000
	handler = f.server.Handler()
	transport := f.broker.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	addr := f.broker.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	f.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f
}

func (f *localFixture) do(method, path, contentType string, body []byte, cookie *http.Cookie, origin string) *http.Response {
	f.t.Helper()
	r, err := http.NewRequest(method, f.origin+path, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	resp, err := f.client.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	return resp
}

func (f *localFixture) postJSON(path string, v any, cookie *http.Cookie) (*http.Response, map[string]any) {
	f.t.Helper()
	b, _ := json.Marshal(v)
	resp := f.do("POST", path, "application/json", b, cookie, f.origin)
	raw := readBody(f.t, resp)
	var out map[string]any
	_ = json.Unmarshal([]byte(raw), &out)
	return resp, out
}

func (f *localFixture) postForm(path string, form url.Values, cookie *http.Cookie) (*http.Response, string) {
	f.t.Helper()
	resp := f.do("POST", path, "application/x-www-form-urlencoded", []byte(form.Encode()), cookie, f.origin)
	return resp, readBody(f.t, resp)
}

func (f *localFixture) accountsCmd(args ...string) map[string]any {
	f.t.Helper()
	var out bytes.Buffer
	if code := RunAccounts(append([]string{args[0], "--file", f.accounts}, args[1:]...), &out); code != 0 {
		f.t.Fatalf("accounts %v: %s", args, out.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		f.t.Fatal(err)
	}
	return v
}

type localFlow struct {
	state, verifier string
	cookie          *http.Cookie
	page            string
}

// begin starts a downstream authorization and picks the Covee account option.
func (f *localFixture) begin(client string) localFlow {
	f.t.Helper()
	verifier := oauth2.GenerateVerifier()
	sum := sha256.Sum256([]byte(verifier))
	redirect := map[string]string{"console": "https://console.example.test/auth/oidc/callback", "enrollment": "https://control.example.test/oidc/callback"}[client]
	q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid profile"},
		"nonce": {strings.Repeat("downstream-nonce", 2)}, "state": {strings.Repeat("downstream-state", 2)}, "code_challenge": {base64URL(sum[:])}, "code_challenge_method": {"S256"}}
	resp := f.do("GET", "/identity/authorize?"+q.Encode(), "", nil, nil, "")
	body := readBody(f.t, resp)
	if !regexp.MustCompile(`value="local">(<svg[^>]*>.*?</svg>)?<span>Continue with a Covee account</span>`).MatchString(body) {
		f.t.Fatalf("chooser does not offer Covee accounts: %s", body)
	}
	state := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(body)[1]
	cookie := resp.Cookies()[0]
	resp, page := f.postForm("/identity/select", url.Values{"state": {state}, "provider": {"local"}}, cookie)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") != localCSP {
		f.t.Fatalf("local page %d %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}
	newState := regexp.MustCompile(`data-state="([^"]+)"`).FindStringSubmatch(page)
	if len(newState) != 2 || newState[1] == state {
		f.t.Fatalf("the local page must carry a new flow state: %s", page)
	}
	return localFlow{state: newState[1], verifier: verifier, cookie: cookie, page: page}
}

func (f *localFixture) password(flow localFlow, email, password, code string) (*http.Response, string) {
	return f.postForm("/identity/local/password", url.Values{"state": {flow.state}, "email": {email}, "password": {password}, "code": {code}}, flow.cookie)
}

// claims exchanges an issued code and returns the broker's ID token claims.
func (f *localFixture) claims(client string, flow localFlow, resp *http.Response) map[string]any {
	f.t.Helper()
	location, _ := url.Parse(resp.Header.Get("Location"))
	return f.exchangeCode(client, flow, location.Query().Get("code"))
}

func (f *localFixture) exchangeCode(client string, flow localFlow, code string) map[string]any {
	f.t.Helper()
	redirect := f.server.clients[client].config.RedirectURI
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "client_secret": {f.server.clients[client].secret}, "redirect_uri": {redirect}, "code": {code}, "code_verifier": {flow.verifier}}
	resp, body := f.postForm("/identity/token", form, nil)
	if resp.StatusCode != 200 {
		f.t.Fatalf("token %d %s", resp.StatusCode, body)
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal([]byte(body), &tokens)
	signed, err := jose.ParseSigned(tokens.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		f.t.Fatal(err)
	}
	payload, err := signed.Verify(&f.server.key.PublicKey)
	if err != nil {
		f.t.Fatal(err)
	}
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	return claims
}

func (f *localFixture) account(email string) Account {
	f.t.Helper()
	doc, err := NewAccountStore(f.accounts).Read()
	if err != nil {
		f.t.Fatal(err)
	}
	i := doc.byEmail(email)
	if i < 0 {
		f.t.Fatalf("no account %s", email)
	}
	return doc.Accounts[i]
}

func (f *localFixture) edit(email string, change func(*Account)) {
	f.t.Helper()
	if err := NewAccountStore(f.accounts).Update(func(doc *accountsDocument) error {
		change(&doc.Accounts[doc.byEmail(email)])
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func codeAt(secret string, step int64) string {
	raw, _ := base32NoPad.DecodeString(secret)
	return totpCode(raw, step)
}

// setupPassword completes an invite with a password and authenticator app.
func (f *localFixture) setupPassword(token, password string) (secret string, step int64) {
	f.t.Helper()
	resp, totp := f.postJSON("/identity/local/invite/totp", map[string]string{"token": token}, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(totp["otpauth_uri"].(string), "otpauth://totp/") || !strings.HasPrefix(fmt.Sprint(totp["qr_svg_data_uri"]), "data:image/svg+xml;base64,") {
		f.t.Fatalf("totp %d %v", resp.StatusCode, totp)
	}
	secret = totp["secret_base32"].(string)
	step = time.Now().Unix() / totpPeriod
	resp, out := f.postJSON("/identity/local/invite/password", map[string]string{"token": token, "password": password, "code": codeAt(secret, step)}, nil)
	if resp.StatusCode != 200 || out["ok"] != true {
		f.t.Fatalf("password setup %d %v", resp.StatusCode, out)
	}
	return secret, step
}

func TestLocalProviderConfiguration(t *testing.T) {
	f := newFixture(t)
	good := copyConfig(t, f.server.config)
	good.Providers = append(good.Providers, ProviderConfig{ID: "local", Kind: "local", AccountsFile: "/var/lib/covee-identity/accounts.json"})
	if err := good.validate(); err != nil {
		t.Fatalf("four providers with local accounts rejected: %v", err)
	}
	cases := map[string]func(*Config){
		"relative accounts file": func(c *Config) { c.Providers[3].AccountsFile = "accounts.json" },
		"local with client":      func(c *Config) { c.Providers[3].ClientID = "x" },
		"local with issuer":      func(c *Config) { c.Providers[3].Issuer = "https://example.com" },
		"local with secret":      func(c *Config) { c.Providers[3].ClientSecretFile = "/x" },
		"local with groups":      func(c *Config) { c.Providers[3].AllowedGroupIDs = []string{"11234567-89ab-cdef-0123-456789abcdef"} },
		"accounts on google":     func(c *Config) { c.Providers[0].AccountsFile = "/x" },
		"five providers":         func(c *Config) { c.Providers = append(c.Providers, c.Providers[3]) },
		"local grant":            func(c *Config) { c.Grants = append(c.Grants, Grant{Provider: "local", Subject: "x", Role: RoleAdmin}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := copyConfig(t, good)
			mutate(&c)
			if c.validate() == nil {
				t.Fatal("accepted invalid local provider configuration")
			}
		})
	}
	if _, err := newLocal("https://127.0.0.1:8443/identity", good.Providers[3]); err == nil {
		t.Fatal("passkeys need a DNS hostname, not an IP address")
	}
}

func TestAccountStoreIsAtomicAndLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	store := NewAccountStore(path)
	if doc, err := store.Read(); err != nil || len(doc.Accounts) != 0 {
		t.Fatalf("a missing file must mean no accounts: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out bytes.Buffer
			if RunAccounts([]string{"invite", "--file", path, "--email", fmt.Sprintf("p%d@example.com", i), "--name", "P", "--role", "reader", "--enroll", "false"}, &out) != 0 {
				t.Errorf("invite %d: %s", i, out.String())
			}
		}(i)
	}
	wg.Wait()
	doc, err := store.Read()
	if err != nil || len(doc.Accounts) != 40 {
		t.Fatalf("concurrent updates lost accounts: %d %v", len(doc.Accounts), err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("accounts file mode %v", info.Mode().Perm())
	}
	before, _ := os.ReadFile(path)
	if err := store.Update(func(*accountsDocument) error { return fmt.Errorf("no") }); err == nil {
		t.Fatal("a failed change must report its error")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("a failed change wrote the file")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".accounts-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
	os.Chmod(path, 0o644)
	if _, err := store.Read(); err == nil {
		t.Fatal("a readable-by-others accounts file must be refused")
	}
	os.Chmod(path, 0o600)
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := store.Read(); err == nil {
		t.Fatal("a corrupt accounts file must be refused")
	}
}

func TestAccountsCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	run := func(args ...string) (map[string]any, int) {
		var out bytes.Buffer
		code := RunAccounts(append([]string{args[0], "--file", path}, args[1:]...), &out)
		if strings.Count(strings.TrimSpace(out.String()), "\n") != 0 {
			t.Fatalf("output must be one JSON object: %q", out.String())
		}
		var v map[string]any
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatalf("not JSON: %q", out.String())
		}
		return v, code
	}
	invited, code := run("invite", "--email", " Alice@Example.COM ", "--name", "Alice", "--role", "admin", "--enroll", "true", "--expires", "72h")
	if code != 0 || invited["email"] != "alice@example.com" || len(invited["invite_token"].(string)) != 43 {
		t.Fatalf("invite = %v", invited)
	}
	expires, _ := time.Parse(time.RFC3339, invited["expires"].(string))
	if d := time.Until(expires); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("expiry %v", expires)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), invited["invite_token"].(string)) {
		t.Fatal("the invite token must be stored only as a hash")
	}
	for _, bad := range [][]string{
		{"invite", "--email", "alice@example.com", "--name", "A", "--role", "admin"},
		{"invite", "--email", "bob@example.com", "--name", "B", "--role", "none", "--enroll", "false"},
		{"invite", "--email", "bob@example.com", "--name", "B", "--role", "owner"},
		{"invite", "--email", "bob@example.com", "--name", "B", "--role", "admin", "--expires", "30m"},
		{"invite", "--email", "bob@example.com", "--name", "B", "--role", "admin", "--expires", "15d"},
		{"invite", "--email", "not-an-email", "--name", "B", "--role", "admin"},
		{"invite", "--email", "bob@example.com", "--name", "", "--role", "admin"},
		{"update", "--email", "alice@example.com"},
		{"update", "--email", "alice@example.com", "--role", "none", "--enroll", "false"},
		{"remove", "--email", "nobody@example.com"},
		{"reset", "--email", "nobody@example.com"},
		{"rename", "--email", "alice@example.com"},
	} {
		if out, code := run(bad...); code != 1 || out["error"] == "" {
			t.Errorf("%v accepted: %v", bad, out)
		}
	}
	if out, _ := run("invite", "--email", "bob@example.com", "--name", "Bob", "--role", "none", "--enroll", "true", "--expires", "7d"); out["email"] != "bob@example.com" {
		t.Fatalf("day expiry: %v", out)
	}
	updated, _ := run("update", "--email", "bob@example.com", "--role", "reader")
	if updated["role"] != "reader" || updated["enroll"] != true {
		t.Fatalf("update = %v", updated)
	}
	list, _ := run("list")
	accounts := list["accounts"].([]any)
	first := accounts[0].(map[string]any)
	if len(accounts) != 2 || first["email"] != "alice@example.com" || first["role"] != "admin" || first["invite_pending"] != true || first["passkeys"] != float64(0) || first["password"] != false || first["last_sign_in"] != nil {
		t.Fatalf("list = %v", list)
	}
	for _, entry := range accounts {
		for _, field := range []string{"id", "password_hash", "totp_secret", "invite", "token_sha256", "passkey_credentials"} {
			if _, ok := entry.(map[string]any)[field]; ok {
				t.Fatalf("list exposes %s", field)
			}
		}
	}
	reset, _ := run("reset", "--email", "alice@example.com")
	if reset["invite_token"] == invited["invite_token"] || reset["email"] != "alice@example.com" {
		t.Fatalf("reset = %v", reset)
	}
	if removed, _ := run("remove", "--email", "bob@example.com"); removed["removed"] != "bob@example.com" {
		t.Fatalf("remove = %v", removed)
	}
}

func TestInviteLifecycleAndPasswordSignIn(t *testing.T) {
	f := newLocalFixture(t)
	token := f.accountsCmd("invite", "--email", "alice@example.com", "--name", "Alice", "--role", "admin", "--enroll", "true")["invite_token"].(string)
	if resp, out := f.postJSON("/identity/local/invite/info", map[string]string{"token": "wrong" + token}, nil); resp.StatusCode != 400 || out["error"] != "invalid_invite" {
		t.Fatalf("wrong token: %d %v", resp.StatusCode, out)
	}
	resp, info := f.postJSON("/identity/local/invite/info", map[string]string{"token": token}, nil)
	if resp.StatusCode != 200 || info["email"] != "alice@example.com" || info["has_password"] != false {
		t.Fatalf("info %d %v", resp.StatusCode, info)
	}
	resp, totp := f.postJSON("/identity/local/invite/totp", map[string]string{"token": token}, nil)
	secret := totp["secret_base32"].(string)
	step := time.Now().Unix() / totpPeriod
	for _, weak := range []string{"short", "alice@example.com", strings.Repeat("x", 129)} {
		if resp, out := f.postJSON("/identity/local/invite/password", map[string]string{"token": token, "password": weak, "code": codeAt(secret, step)}, nil); resp.StatusCode != 400 || out["error"] != "weak_password" {
			t.Fatalf("weak password %q accepted: %v", weak, out)
		}
	}
	if resp, out := f.postJSON("/identity/local/invite/password", map[string]string{"token": token, "password": "correct horse battery", "code": "000000"}, nil); resp.StatusCode != 400 || out["error"] != "invalid_code" {
		t.Fatalf("wrong code accepted: %v", out)
	}
	resp, out := f.postJSON("/identity/local/invite/password", map[string]string{"token": token, "password": "correct horse battery", "code": codeAt(secret, step)}, nil)
	if resp.StatusCode != 200 || out["ok"] != true {
		t.Fatalf("password setup %d %v", resp.StatusCode, out)
	}
	if resp, _ := f.postJSON("/identity/local/invite/info", map[string]string{"token": token}, nil); resp.StatusCode != 400 {
		t.Fatal("an invite must be single use")
	}
	stored := f.account("alice@example.com")
	if !strings.HasPrefix(stored.PasswordHash, "$argon2id$v=19$m=19456,t=2,p=1$") || stored.TOTPSecret != secret || stored.Invite != nil {
		t.Fatalf("stored credentials: %+v", stored)
	}

	// The setup code was used at this step; sign-in must use the next one.
	flow := f.begin("console")
	if resp, page := f.password(flow, "alice@example.com", "correct horse battery", codeAt(secret, step)); resp.StatusCode != 401 || !strings.Contains(page, signInFailed) {
		t.Fatalf("a code reused from setup was accepted: %d", resp.StatusCode)
	}
	resp, _ = f.password(flow, "alice@example.com", "correct horse battery", codeAt(secret, step+1))
	if resp.StatusCode != 303 {
		t.Fatalf("sign-in %d", resp.StatusCode)
	}
	claims := f.claims("console", flow, resp)
	account := f.account("alice@example.com")
	if claims["upstream_issuer"] != f.origin+"/identity#local" || claims["upstream_sub"] != account.ID || fmt.Sprint(claims["roles"]) != "[Covee.Admin]" {
		t.Fatalf("claims = %v", claims)
	}
	if account.LastSignIn.IsZero() || account.TOTPLastStep != step+1 {
		t.Fatalf("sign-in not recorded: %+v", account)
	}

	// Uniform failures: unknown account, wrong password, replayed code.
	flow = f.begin("console")
	pages := []string{}
	for _, attempt := range [][3]string{{"nobody@example.com", "correct horse battery", codeAt(secret, step+1)}, {"alice@example.com", "wrong password!!", codeAt(secret, step+1)}, {"alice@example.com", "correct horse battery", codeAt(secret, step+1)}} {
		resp, page := f.password(flow, attempt[0], attempt[1], attempt[2])
		if resp.StatusCode != 401 {
			t.Fatalf("%v accepted", attempt)
		}
		pages = append(pages, regexp.MustCompile(`role="alert">([^<]+)<`).FindStringSubmatch(page)[1])
	}
	if pages[0] != pages[1] || pages[1] != pages[2] {
		t.Fatalf("failures must look the same: %v", pages)
	}

	// Five failures lock the account, even against a currently valid code.
	f.edit("alice@example.com", func(a *Account) { a.TOTPLastStep = 0 })
	current := time.Now().Unix() / totpPeriod
	for i := 0; i < 3; i++ {
		f.password(flow, "alice@example.com", "wrong password!!", codeAt(secret, current))
	}
	if !time.Now().Before(f.account("alice@example.com").LockedUntil) {
		t.Fatal("five failures must lock the account")
	}
	if resp, _ := f.password(flow, "alice@example.com", "correct horse battery", codeAt(secret, current)); resp.StatusCode != 401 {
		t.Fatal("a locked account signed in")
	}
	f.edit("alice@example.com", func(a *Account) { a.LockedUntil = time.Now().Add(-time.Second) })
	if resp, _ := f.password(flow, "alice@example.com", "correct horse battery", codeAt(secret, current)); resp.StatusCode != 303 {
		t.Fatal("the account did not unlock after its lock time")
	}
	if resp, _ := f.password(flow, "alice@example.com", "correct horse battery", codeAt(secret, current+1)); resp.StatusCode != 400 {
		t.Fatal("a finished flow must not be usable again")
	}

	// Expired invites are refused.
	token = f.accountsCmd("invite", "--email", "late@example.com", "--name", "Late", "--role", "reader", "--enroll", "false")["invite_token"].(string)
	f.edit("late@example.com", func(a *Account) { a.Invite.Expires = time.Now().Add(-time.Minute) })
	if resp, _ := f.postJSON("/identity/local/invite/info", map[string]string{"token": token}, nil); resp.StatusCode != 400 {
		t.Fatal("an expired invite was accepted")
	}
}

// softAuthenticator is a minimal platform authenticator for tests.
type softAuthenticator struct {
	key        *ecdsa.PrivateKey
	id, handle []byte
	count      uint32
	rpID       string
	origin     string
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *softAuthenticator) clientData(kind, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *softAuthenticator) create(t *testing.T, options map[string]any) map[string]any {
	t.Helper()
	pk := options["publicKey"].(map[string]any)
	if pk["rp"].(map[string]any)["id"] != a.rpID || pk["attestation"] != "none" || pk["authenticatorSelection"].(map[string]any)["residentKey"] != "required" || pk["authenticatorSelection"].(map[string]any)["userVerification"] != "required" {
		t.Fatalf("creation options = %v", pk)
	}
	a.handle, _ = base64.RawURLEncoding.DecodeString(pk["user"].(map[string]any)["id"].(string))
	a.id = randomBytes(32)
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve: 1, XCoord: a.key.PublicKey.X.FillBytes(make([]byte, 32)), YCoord: a.key.PublicKey.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte(a.rpID))
	auth := append(append([]byte{}, rp[:]...), 0x45, 0, 0, 0, 0) // UP, UV, AT
	auth = append(auth, make([]byte, 16)...)                     // AAGUID
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.id)))
	auth = append(append(auth, a.id...), cose...)
	attestation, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": b64u(a.id), "rawId": b64u(a.id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64u(a.clientData("webauthn.create", pk["challenge"].(string))), "attestationObject": b64u(attestation), "transports": []string{"internal"}}}
}

func (a *softAuthenticator) get(t *testing.T, options map[string]any) map[string]any {
	t.Helper()
	pk := options["publicKey"].(map[string]any)
	if pk["userVerification"] != "required" || pk["allowCredentials"] != nil {
		t.Fatalf("request options = %v", pk)
	}
	a.count++
	rp := sha256.Sum256([]byte(a.rpID))
	auth := binary.BigEndian.AppendUint32(append(append([]byte{}, rp[:]...), 0x05), a.count) // UP, UV
	client := a.clientData("webauthn.get", pk["challenge"].(string))
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": b64u(a.id), "rawId": b64u(a.id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64u(client), "authenticatorData": b64u(auth), "signature": b64u(sig), "userHandle": b64u(a.handle)}}
}

func TestPasskeyRegistrationAndDiscoverableSignIn(t *testing.T) {
	f := newLocalFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	auth := &softAuthenticator{key: key, rpID: "example.com", origin: f.origin}
	token := f.accountsCmd("invite", "--email", "dev@example.com", "--name", "Dev", "--role", "none", "--enroll", "true")["invite_token"].(string)
	resp, options := f.postJSON("/identity/local/invite/passkey/options", map[string]string{"token": token}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("creation options %d %v", resp.StatusCode, options)
	}
	params := fmt.Sprint(options["publicKey"].(map[string]any)["pubKeyCredParams"])
	for _, alg := range []string{"-7", "-8", "-257"} {
		if !strings.Contains(params, alg) {
			t.Fatalf("algorithm %s not offered: %s", alg, params)
		}
	}
	credential := auth.create(t, options)
	if resp, out := f.postJSON("/identity/local/invite/passkey/finish", map[string]any{"token": token, "credential": credential}, nil); resp.StatusCode != 200 || out["ok"] != true {
		t.Fatalf("registration %d %v", resp.StatusCode, out)
	}
	if resp, _ := f.postJSON("/identity/local/invite/passkey/finish", map[string]any{"token": token, "credential": credential}, nil); resp.StatusCode != 400 {
		t.Fatal("a used invite registered another passkey")
	}
	account := f.account("dev@example.com")
	if len(account.Passkeys) != 1 || !bytes.Equal(account.Passkeys[0].Credential.ID, auth.id) || account.Invite != nil {
		t.Fatalf("passkey not stored: %+v", account)
	}

	// Discoverable sign-in for device enrollment.
	flow := f.begin("enrollment")
	resp, request := f.postJSON("/identity/local/passkey/options", map[string]string{"state": flow.state}, flow.cookie)
	if resp.StatusCode != 200 {
		t.Fatalf("request options %d %v", resp.StatusCode, request)
	}
	assertion := auth.get(t, request)
	resp, out := f.postJSON("/identity/local/passkey/finish", map[string]any{"state": flow.state, "credential": assertion}, flow.cookie)
	if resp.StatusCode != 200 {
		t.Fatalf("passkey sign-in %d %v", resp.StatusCode, out)
	}
	location, _ := url.Parse(out["redirect"].(string))
	claims := f.exchangeCode("enrollment", flow, location.Query().Get("code"))
	if fmt.Sprint(claims["groups"]) != "[covee.enroll]" || claims["upstream_sub"] != account.ID || claims["upstream_issuer"] != f.origin+"/identity#local" {
		t.Fatalf("claims = %v", claims)
	}
	if got := f.account("dev@example.com").Passkeys[0]; got.Credential.Authenticator.SignCount != 1 || got.LastUsed.IsZero() {
		t.Fatalf("sign count not recorded: %+v", got)
	}
	// The flow is single use, and a replayed assertion fails.
	if resp, _ := f.postJSON("/identity/local/passkey/finish", map[string]any{"state": flow.state, "credential": assertion}, flow.cookie); resp.StatusCode != 400 {
		t.Fatal("a finished flow accepted another assertion")
	}

	// Same account, console flow: it has no console role, so it is denied.
	flow = f.begin("console")
	_, request = f.postJSON("/identity/local/passkey/options", map[string]string{"state": flow.state}, flow.cookie)
	resp, out = f.postJSON("/identity/local/passkey/finish", map[string]any{"state": flow.state, "credential": auth.get(t, request)}, flow.cookie)
	if resp.StatusCode != 403 || out["error"] != "access_denied" || out["subject"] != "dev@example.com" {
		t.Fatalf("denied passkey sign-in %d %v", resp.StatusCode, out)
	}
	// A forged signature is refused.
	flow = f.begin("enrollment")
	_, request = f.postJSON("/identity/local/passkey/options", map[string]string{"state": flow.state}, flow.cookie)
	forged := auth.get(t, request)
	forged["response"].(map[string]any)["signature"] = b64u(make([]byte, 70))
	if resp, _ := f.postJSON("/identity/local/passkey/finish", map[string]any{"state": flow.state, "credential": forged}, flow.cookie); resp.StatusCode != 400 {
		t.Fatal("a forged assertion was accepted")
	}
}

func TestLocalDeniedPageMatchesUpstream(t *testing.T) {
	f := newLocalFixture(t)
	token := f.accountsCmd("invite", "--email", "reader@example.com", "--name", "R", "--role", "none", "--enroll", "true")["invite_token"].(string)
	secret, step := f.setupPassword(token, "a long enough password")
	flow := f.begin("console")
	resp, page := f.password(flow, "reader@example.com", "a long enough password", codeAt(secret, step+1))
	if resp.StatusCode != 403 || !strings.Contains(page, "Waiting for approval") || !strings.Contains(page, "reader@example.com") || !strings.Contains(page, "Covee account") {
		t.Fatalf("denied page %d %s", resp.StatusCode, page)
	}
}

func TestLocalRoutesCheckOriginTypeAndCSP(t *testing.T) {
	f := newLocalFixture(t)
	resp := f.do("GET", "/identity/local/invite", "", nil, nil, "")
	body := readBody(t, resp)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") != localCSP || strings.Contains(body, "<script>") || !strings.Contains(body, `src="/identity/local/app.js"`) {
		t.Fatalf("invite page %d %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}
	if resp := f.do("GET", "/identity/local/invite?token=x", "", nil, nil, ""); resp.StatusCode != 400 {
		t.Fatal("invite tokens must never travel in a query")
	}
	resp = f.do("GET", "/identity/local/app.js", "", nil, nil, "")
	if script := readBody(t, resp); resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(script, "navigator.credentials.get") {
		t.Fatal("script not served")
	}
	body2 := []byte(`{"token":"x"}`)
	if resp := f.do("POST", "/identity/local/invite/info", "application/json", body2, nil, ""); resp.StatusCode != 403 {
		t.Fatal("a POST without Origin was accepted")
	}
	if resp := f.do("POST", "/identity/local/invite/info", "application/json", body2, nil, "https://attacker.example"); resp.StatusCode != 403 {
		t.Fatal("a cross-origin POST was accepted")
	}
	if resp := f.do("POST", "/identity/local/invite/info", "text/plain", body2, nil, f.origin); resp.StatusCode != 400 {
		t.Fatal("a non-JSON POST was accepted")
	}
	if resp := f.do("POST", "/identity/local/invite/info", "application/json", []byte(`{"token":"x","extra":1}`), nil, f.origin); resp.StatusCode != 400 {
		t.Fatal("unknown JSON fields were accepted")
	}
	if resp := f.do("POST", "/identity/local/invite/info", "application/json", bytes.Repeat([]byte(" "), 70<<10), nil, f.origin); resp.StatusCode != 400 {
		t.Fatal("an oversized body was accepted")
	}
	flow := f.begin("console")
	if resp := f.do("POST", "/identity/local/password", "application/x-www-form-urlencoded", []byte(url.Values{"state": {flow.state}}.Encode()), flow.cookie, "https://attacker.example"); resp.StatusCode != 403 {
		t.Fatal("a cross-origin password POST was accepted")
	}
	if resp, _ := f.postJSON("/identity/local/passkey/options", map[string]string{"state": flow.state}, nil); resp.StatusCode != 400 {
		t.Fatal("passkey options without the flow cookie were accepted")
	}
	resp = f.do("GET", "/identity/providers", "", nil, nil, "")
	if providers := readBody(t, resp); !strings.Contains(providers, `"id":"local"`) {
		t.Fatalf("providers = %s", providers)
	}
	// Other routes keep the original policy without scripts.
	resp = f.do("GET", "/identity/healthz", "", nil, nil, "")
	readBody(t, resp)
	if strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src") {
		t.Fatal("scripts allowed outside the local pages")
	}
	// The global bucket limits attempts.
	f.server.local.burst, f.server.local.tokens = 1, 0
	if resp, _ := f.postJSON("/identity/local/invite/info", map[string]string{"token": "x"}, nil); resp.StatusCode != 429 {
		t.Fatalf("rate limit not applied: %d", resp.StatusCode)
	}
}

func TestLocalRoutesAbsentWithoutLocalAccounts(t *testing.T) {
	f := newFixture(t)
	if r := f.request("GET", "/identity/local/invite", nil, nil, ""); r.StatusCode != 404 {
		t.Fatal("local routes must not exist when local accounts are off")
	}
	if strings.Contains(readBody(t, f.request("GET", "/identity/providers", nil, nil, "")), "local") {
		t.Fatal("providers list Covee accounts when they are off")
	}
}

func TestTOTPAndPasswordPrimitives(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 seed, 8-digit vectors truncated to 6 digits.
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(secret, unix/30); got != want {
			t.Errorf("TOTP at %d = %s, want %s", unix, got, want)
		}
	}
	encoded := base32NoPad.EncodeToString(secret)
	now := time.Unix(1234567890, 0)
	if step, ok := totpMatch(encoded, "005924", now, 0); !ok || step != 1234567890/30 {
		t.Fatal("current code rejected")
	}
	if _, ok := totpMatch(encoded, "005924", now, 1234567890/30); ok {
		t.Fatal("a used step was accepted again")
	}
	if _, ok := totpMatch(encoded, totpCode(secret, 1234567890/30+2), now, 0); ok {
		t.Fatal("a code two steps away was accepted")
	}
	for _, bad := range []string{"12345", "abcdef", "1234567"} {
		if _, ok := totpMatch(encoded, bad, now, 0); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	hash := hashPassword("correct horse battery")
	if !verifyPassword(hash, "correct horse battery") || verifyPassword(hash, "correct horse batterY") {
		t.Fatal("password verification")
	}
	if verifyPassword(strings.Replace(hash, "m=19456", "m=4194304", 1), "correct horse battery") {
		t.Fatal("tampered memory parameters must be refused")
	}
	if hashPassword("correct horse battery") == hash {
		t.Fatal("hashes must be salted")
	}
}

func TestPasswordHashingIsBounded(t *testing.T) {
	l := &localProvider{slots: make(chan struct{}, 2)}
	block := make(chan struct{})
	for i := 0; i < 2; i++ {
		go l.hash(func() { <-block })
	}
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := l.hash(func() {}); err != errBusy || time.Since(start) < 2*time.Second {
		t.Fatalf("a third concurrent hash must wait, then give up: %v", err)
	}
	close(block)
}
