package management

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "a-very-long-test-admin-token-with-entropy"
const testAPIKey = "headscale-api-secret-never-in-browser"

func newTestServer(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	up := httptest.NewServer(handler)
	t.Cleanup(up.Close)
	s, err := New(Config{Listen: "127.0.0.1:8088", PublicURL: "http://127.0.0.1:8088", AdminToken: testToken, HeadscaleURL: up.URL, HeadscaleAPIKey: testAPIKey, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func request(s *Server, method, path, body string, headers map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:10000"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func bearer() map[string]string { return map[string]string{"Authorization": "Bearer " + testToken} }
func login(t *testing.T, s *Server) (*http.Cookie, string) {
	t.Helper()
	w := request(s, "POST", "/api/login", `{"token":"`+testToken+`"}`, map[string]string{"Origin": s.config.PublicURL}, nil)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0], out.CSRFToken
}
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("got status %d, want %d: %s", w.Code, status, w.Body.String())
	}
}

func TestAuthenticationCSRFAndLogout(t *testing.T) {
	var calls atomic.Int32
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testAPIKey {
			t.Error("upstream credential missing")
		}
		io.WriteString(w, `{"user":{"id":"1","name":"alice"}}`)
	})
	assertStatus(t, request(s, "GET", "/healthz", "", nil, nil), 200)
	assertStatus(t, request(s, "GET", "/api/session", "", nil, nil), 401)
	assertStatus(t, request(s, "POST", "/api/login", `{"token":"`+testToken+`"}`, nil, nil), 403)
	cookie, csrf := login(t, s)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Secure || cookie.MaxAge != int(sessionDuration.Seconds()) {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	assertStatus(t, request(s, "GET", "/api/session", "", nil, cookie), 200)
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"alice"}`, map[string]string{"Origin": s.config.PublicURL}, cookie), 403)
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"alice"}`, map[string]string{"Origin": "https://attacker.example", "X-CSRF-Token": csrf}, cookie), 403)
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"alice"}`, map[string]string{"X-CSRF-Token": csrf}, cookie), 403)
	if calls.Load() != 0 {
		t.Fatal("unauthorized mutation reached Headscale")
	}
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"alice"}`, map[string]string{"Origin": s.config.PublicURL, "X-CSRF-Token": csrf}, cookie), 201)
	assertStatus(t, request(s, "GET", "/api/session", "", map[string]string{"Authorization": "Bearer wrong"}, cookie), 401)
	assertStatus(t, request(s, "POST", "/api/logout", `{}`, map[string]string{"Origin": s.config.PublicURL, "X-CSRF-Token": csrf}, cookie), 200)
	assertStatus(t, request(s, "GET", "/api/session", "", nil, cookie), 401)
	assertStatus(t, request(s, "POST", "/api/users", `{"name":"cli"}`, bearer(), nil), 201)
}

func TestSessionExpiryRotationAndRateLimit(t *testing.T) {
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("unexpected upstream request") })
	cookie, _ := login(t, s)
	w := request(s, "POST", "/api/login", `{"token":"`+testToken+`"}`, map[string]string{"Origin": s.config.PublicURL}, cookie)
	assertStatus(t, w, 200)
	assertStatus(t, request(s, "GET", "/api/session", "", nil, cookie), 401)
	rotated := w.Result().Cookies()[0]
	s.sessionMu.Lock()
	sess := s.sessions[rotated.Value]
	sess.expires = time.Now().Add(-time.Second)
	s.sessions[rotated.Value] = sess
	s.sessionMu.Unlock()
	assertStatus(t, request(s, "GET", "/api/session", "", nil, rotated), 401)
	for i := 0; i < 8; i++ {
		assertStatus(t, request(s, "POST", "/api/login", `{"token":"bad"}`, map[string]string{"Origin": s.config.PublicURL}, nil), 401)
	}
	assertStatus(t, request(s, "POST", "/api/login", `{"token":"bad"}`, map[string]string{"Origin": s.config.PublicURL}, nil), 429)
}

type failingAudit struct {
	auditFile
	failWrite  bool
	syncs      int
	failSyncAt int
}

func (f *failingAudit) Write(b []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("disk failed")
	}
	return f.auditFile.Write(b)
}
func (f *failingAudit) Sync() error {
	f.syncs++
	if f.syncs == f.failSyncAt {
		return errors.New("fsync failed")
	}
	return f.auditFile.Sync()
}

func TestAuditFailsClosedBeforeMutation(t *testing.T) {
	for _, failWrite := range []bool{true, false} {
		t.Run(map[bool]string{true: "write", false: "fsync"}[failWrite], func(t *testing.T) {
			var calls atomic.Int32
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, `{}`) })
			s.audit.file = &failingAudit{auditFile: s.audit.file, failWrite: failWrite, failSyncAt: 1}
			w := request(s, "DELETE", "/api/users/1", "", bearer(), nil)
			assertStatus(t, w, 503)
			if !strings.Contains(w.Body.String(), "audit_unavailable") || calls.Load() != 0 {
				t.Fatal("mutation must fail before sending upstream")
			}
		})
	}
}
func TestAuditFailureAfterMutationReportsUncertainty(t *testing.T) {
	var calls atomic.Int32
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, `{}`) })
	s.audit.file = &failingAudit{auditFile: s.audit.file, failSyncAt: 2}
	w := request(s, "DELETE", "/api/users/1", "", bearer(), nil)
	assertStatus(t, w, 503)
	if calls.Load() != 1 || !strings.Contains(w.Body.String(), "may have completed") {
		t.Fatal("post-mutation durability failure was misreported")
	}
	w = request(s, "DELETE", "/api/users/2", "", bearer(), nil)
	assertStatus(t, w, 503)
	if calls.Load() != 1 {
		t.Fatal("failed audit must remain closed")
	}
}

func TestEnrollmentSecretsOnlyAppearOnCreation(t *testing.T) {
	var expireID string
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/preauthkey":
			io.WriteString(w, `{"pre_auth_keys":[{"id":7,"user":{"id":"2"},"key":"existing-secret","acl_tags":["tag:server"]},{"id":"8","user":{"id":3},"key":"other-user-secret"}]}`)
		case "GET /api/v1/policy":
			io.WriteString(w, `{"policy":"{\"tagOwners\":{\"tag:server\":[]}}"}`)
		case "POST /api/v1/preauthkey":
			io.WriteString(w, `{"preAuthKey":{"id":"9","user":{"id":"2"},"key":"fresh-once-secret","aclTags":["tag:server"]}}`)
		case "POST /api/v1/preauthkey/expire":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			expireID = in["id"]
			if _, ok := in["key"]; ok {
				t.Error("expiration should send ID only")
			}
			io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	w := request(s, "GET", "/api/keys?userId=2", "", bearer(), nil)
	assertStatus(t, w, 200)
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), `"8"`) || !strings.Contains(w.Body.String(), "tag:server") {
		t.Fatalf("leaked or unfiltered list: %s", w.Body.String())
	}
	assertStatus(t, request(s, "POST", "/api/keys/7/expire", `{"userId":"3"}`, bearer(), nil), 404)
	if expireID != "" {
		t.Fatal("wrong owner's key expired")
	}
	w = request(s, "POST", "/api/keys", `{"userId":"2","tags":["tag:server"]}`, bearer(), nil)
	assertStatus(t, w, 201)
	if !strings.Contains(w.Body.String(), `"secret":"fresh-once-secret"`) {
		t.Fatal("fresh secret was not returned")
	}
	assertStatus(t, request(s, "POST", "/api/keys/7/expire", `{"userId":"2"}`, bearer(), nil), 200)
	if expireID != "7" {
		t.Fatal("wrong expiration ID")
	}
	w = request(s, "GET", "/api/audit", "", bearer(), nil)
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), testAPIKey) || strings.Contains(w.Body.String(), testToken) {
		t.Fatal("audit leaked a secret")
	}
	data, err := os.ReadFile(filepath.Join(s.config.DataDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("secret")) {
		t.Fatal("persistent audit leaked secret")
	}
	info, _ := os.Stat(filepath.Join(s.config.DataDir, "audit.jsonl"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe audit file permissions")
	}
	info, _ = os.Stat(s.config.DataDir)
	if info.Mode().Perm() != 0700 {
		t.Fatal("unsafe audit directory permissions")
	}
	replay, err := openAudit(s.config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.close()
	if len(replay.latest()) != 4 {
		t.Fatalf("durable audit replay missing events: %d", len(replay.latest()))
	}
}

func TestPolicyOptimismValidationAndSanitizedFailures(t *testing.T) {
	policy := `{"grants":[]}`
	var checks, sets int
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/policy":
			json.NewEncoder(w).Encode(map[string]string{"policy": policy, "updated_at": "2026-10-10T00:00:00Z"})
		case "POST /api/v1/policy/check":
			checks++
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["policy"] == "invalid" {
				w.WriteHeader(400)
				io.WriteString(w, testAPIKey+" "+testToken+" invalid policy raw body")
				return
			}
			io.WriteString(w, `{}`)
		case "PUT /api/v1/policy":
			sets++
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			policy = in["policy"]
			json.NewEncoder(w).Encode(map[string]string{"policy": policy})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	update := func(p, rev string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]string{"policy": p, "revision": rev})
		return request(s, "PUT", "/api/policy", string(raw), bearer(), nil)
	}
	w := update("invalid", strings.Repeat("a", 64))
	assertStatus(t, w, 409)
	if checks != 0 || sets != 0 {
		t.Fatal("conflicting policy was sent upstream")
	}
	w = update("invalid", revision(policy))
	assertStatus(t, w, 400)
	if sets != 0 || strings.Contains(w.Body.String(), testAPIKey) || strings.Contains(w.Body.String(), "raw body") {
		t.Fatal("invalid policy applied or raw error leaked")
	}
	old := revision(policy)
	w = update(`{"grants":[{}]}`, old)
	assertStatus(t, w, 200)
	if checks != 2 || sets != 1 || !strings.Contains(w.Body.String(), revision(policy)) {
		t.Fatal("policy update failed")
	}
	w = update(`{}`, old)
	assertStatus(t, w, 409)
	data, _ := os.ReadFile(filepath.Join(s.config.DataDir, "audit.jsonl"))
	if bytes.Contains(data, []byte("grants")) {
		t.Fatal("audit leaked raw policy")
	}
}

func TestConcurrentPolicyWritersCannotOverwriteSameRevision(t *testing.T) {
	policy := "initial"
	var sets atomic.Int32
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(map[string]string{"policy": policy})
		case "POST":
			io.WriteString(w, `{}`)
		case "PUT":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			policy = in["policy"]
			sets.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"policy": policy})
		}
	})
	start := make(chan struct{})
	results := make(chan int, 2)
	var workers sync.WaitGroup
	for _, newPolicy := range []string{"first", "second"} {
		workers.Add(1)
		go func(p string) {
			defer workers.Done()
			<-start
			raw, _ := json.Marshal(map[string]string{"policy": p, "revision": revision("initial")})
			results <- request(s, "PUT", "/api/policy", string(raw), bearer(), nil).Code
		}(newPolicy)
	}
	close(start)
	workers.Wait()
	close(results)
	counts := map[int]int{}
	for code := range results {
		counts[code]++
	}
	if sets.Load() != 1 || counts[200] != 1 || counts[409] != 1 {
		t.Fatalf("same revision was not serialized: sets=%d statuses=%v", sets.Load(), counts)
	}
}

func TestUpstreamTLSCustomCAAndRedirectCredentialBoundary(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"users":[]}`) }))
	defer tlsServer.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	config := Config{Listen: "127.0.0.1:8088", PublicURL: "http://127.0.0.1:8088", AdminToken: testToken, HeadscaleURL: tlsServer.URL, HeadscaleAPIKey: testAPIKey, HeadscaleCAFile: caPath, DataDir: t.TempDir()}
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertStatus(t, request(s, "GET", "/api/users", "", bearer(), nil), 200)
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); io.WriteString(w, `{"users":[]}`) }))
	defer destination.Close()
	redirect := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	})
	assertStatus(t, request(redirect, "GET", "/api/users", "", bearer(), nil), 502)
	if leaked.Load() != 0 {
		t.Fatal("upstream client followed a redirect with the Headscale credential")
	}
}

func TestDeviceDTOOmitsControlPlaneSecrets(t *testing.T) {
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"nodes":[{"id":"5","name":"laptop","givenName":"work-laptop","machineKey":"machine-secret","nodeKey":"node-secret","discoKey":"disco-secret","preAuthKey":{"id":"8","key":"enrollment-secret"},"user":{"id":"2"},"ipAddresses":["100.64.0.5"],"online":true}]}`)
	})
	w := request(s, "GET", "/api/devices", "", bearer(), nil)
	assertStatus(t, w, 200)
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "Key") || !strings.Contains(w.Body.String(), "100.64.0.5") {
		t.Fatalf("unsafe device DTO: %s", w.Body.String())
	}
}

func TestUpstreamTypeErrorsAndResponseBound(t *testing.T) {
	for name, body := range map[string]string{"badID": `{"users":[{"id":"invalid"}]}`, "badBoolean": `{"nodes":[{"id":"1","online":"yes"}]}`, "badArray": `{"users":"not a list"}`, "missingID": `{"users":[{"name":"alice"}]}`, "oversize": `{"ignored":"` + strings.Repeat("a", maxUpstreamResponse) + `"}`} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
			path := "/api/users"
			if name == "badBoolean" {
				path = "/api/devices"
			}
			w := request(s, "GET", path, "", bearer(), nil)
			assertStatus(t, w, 502)
		})
	}
}

func TestRequestBoundsHeadersAndSecureCookie(t *testing.T) {
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("invalid input reached upstream") })
	w := request(s, "POST", "/api/users", `{"name":"`+strings.Repeat("x", maxRequestBody)+`"}`, bearer(), nil)
	assertStatus(t, w, 413)
	w = request(s, "POST", "/api/users", `{"name":"alice","unexpected":true}`, bearer(), nil)
	assertStatus(t, w, 400)
	w = request(s, "GET", "/healthz", "", nil, nil)
	if w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
	s.config.PublicURL = "https://admin.example.test"
	cookie, _ := login(t, s)
	if !cookie.Secure || !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Fatal("HTTPS session cookie must be secure and host-scoped")
	}
}

func TestConfigRefusesUnsafeDefaults(t *testing.T) {
	base := Config{Listen: "127.0.0.1:8088", PublicURL: "http://127.0.0.1:8088", AdminToken: testToken, HeadscaleURL: "https://control.example.test", HeadscaleAPIKey: testAPIKey, DataDir: t.TempDir()}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){"remoteHTTP": func(c *Config) { c.HeadscaleURL = "http://control.example.test" }, "publicHTTP": func(c *Config) { c.PublicURL = "http://admin.example.test" }, "credentials": func(c *Config) { c.HeadscaleURL = "https://user:pass@control.example.test" }, "publicPath": func(c *Config) { c.PublicURL += "/" }, "weakToken": func(c *Config) { c.AdminToken = "short" }} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if c.validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	base.AllowHTTP = true
	base.HeadscaleURL = "http://lab-headscale:8080"
	base.PublicURL = "http://lab-admin:8088"
	if err := base.validate(); err != nil {
		t.Fatal("explicit isolated lab override rejected:", err)
	}
}

func TestAuditRejectsCorruptionAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(`{"incomplete":`), 0600); err != nil {
		t.Fatal(err)
	}
	if a, err := openAudit(dir); err == nil {
		a.close()
		t.Fatal("corrupt audit log was silently accepted")
	}
	other := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "audit.jsonl"), filepath.Join(other, "audit.jsonl")); err != nil {
		t.Fatal(err)
	}
	if a, err := openAudit(other); err == nil {
		a.close()
		t.Fatal("symlink audit path accepted")
	}
}

func TestAuditRejectsCompleteUnterminatedRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(`{"id":"event","time":"2026-10-10T00:00:00Z","action":"user.delete","target":"1","outcome":"intent","requestId":"request"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if a, err := openAudit(dir); err == nil {
		a.close()
		t.Fatal("unterminated JSONL record must block mutations until repaired")
	}
}

func TestSuccessfulMutationWithMissingResultIsUncertain(t *testing.T) {
	for _, test := range []struct{ name, path, method, body, upstream string }{
		{"user", "/api/users", "POST", `{"name":"alice"}`, `{}`},
		{"key", "/api/keys", "POST", `{"userId":"1"}`, `{"preAuthKey":{"id":"1","user":{"id":"1"}}}`},
		{"rename", "/api/devices/1", "PATCH", `{"name":"renamed"}`, `{}`},
		{"expire", "/api/devices/1/expire", "POST", `{}`, `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, test.upstream) })
			w := request(s, test.method, test.path, test.body, bearer(), nil)
			assertStatus(t, w, 502)
			if !strings.Contains(w.Body.String(), "upstream_uncertain") || s.audit.latest()[0].Outcome != "uncertain" {
				t.Fatal("2xx upstream result omission must report possible mutation")
			}
		})
	}
}
