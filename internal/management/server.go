package management

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"covee.io/internal/console"
)

const sessionDuration = 8 * time.Hour
const maxRequestBody = 1 << 20

type session struct {
	csrf    string
	expires time.Time
	actor   Actor
}
type loginAttempts struct {
	count int
	until time.Time
}

// Server is a management HTTP handler. It never serves Headscale credentials.
// A single process owns an audit directory and serializes its policy writes.
type Server struct {
	config    Config
	upstream  *upstream
	audit     *auditLog
	handler   http.Handler
	sessionMu sync.Mutex
	sessions  map[string]session
	attempts  map[string]loginAttempts
	policyMu  sync.Mutex
	oidc      *oidcAuthenticator
	gateway   *gatewayService // nil when the network has no gateway
}

func New(c Config) (*Server, error) {
	return newServer(c, nil)
}

// oidcClient is injectable only within the package for a TLS test provider.
func newServer(c Config, oidcClient *http.Client) (*Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	u, err := newUpstream(c)
	if err != nil {
		return nil, err
	}
	var auth *oidcAuthenticator
	if c.mode() == "oidc" {
		auth, err = newOIDC(c, oidcClient)
		if err != nil {
			u.client.CloseIdleConnections()
			return nil, err
		}
	}
	a, err := openAudit(c.DataDir)
	if err != nil {
		u.client.CloseIdleConnections()
		if auth != nil {
			auth.client.CloseIdleConnections()
		}
		return nil, err
	}
	gw, err := newGateway(c)
	if err != nil {
		u.client.CloseIdleConnections()
		a.close()
		return nil, err
	}
	s := &Server{config: c, upstream: u, audit: a, sessions: map[string]session{}, attempts: map[string]loginAttempts{}, oidc: auth, gateway: gw}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /auth/config", func(w http.ResponseWriter, r *http.Request) {
		settings := map[string]string{"mode": c.mode()}
		if c.mode() == "oidc" && c.OIDCLabel != "" {
			settings["signinLabel"] = c.OIDCLabel
		}
		respond(w, 200, settings)
	})
	mux.HandleFunc("POST /auth/oidc/login", s.oidcLogin)
	mux.HandleFunc("GET /auth/oidc/callback", s.oidcCallback)
	mux.HandleFunc("POST /api/login", s.login)
	mux.Handle("/api/", s.authenticate(http.HandlerFunc(s.api)))
	mux.Handle("/", console.Handler())
	s.handler = mux
	if gw != nil {
		gw.start(s)
	}
	return s, nil
}
func (s *Server) Close() error {
	s.gateway.stop()
	s.upstream.client.CloseIdleConnections()
	if s.oidc != nil {
		s.oidc.client.CloseIdleConnections()
	}
	return s.audit.close()
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// As for the console page: under no-referrer Safari sends the console's
	// same-origin requests with "Origin: null", which the check below refuses.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(s.config.PublicURL, "https://") {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	if origin := r.Header.Get("Origin"); origin != "" && !s.sameOrigin(r) {
		fail(w, 403, "origin_rejected", "Request origin is not allowed")
		return
	}
	if r.Method == "OPTIONS" {
		fail(w, 405, "method_not_allowed", "Cross-origin requests are not supported")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	s.handler.ServeHTTP(w, r)
}
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func sameSecret(a, b string) bool {
	ah, bh := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

// hostOrigin is the configured origin this request was addressed to.
func (s *Server) hostOrigin(r *http.Request) (string, bool) {
	for _, origin := range append([]string{s.config.PublicURL}, s.config.AdditionalOrigins...) {
		if u, err := url.Parse(origin); err == nil && strings.EqualFold(r.Host, u.Host) {
			return origin, true
		}
	}
	return "", false
}

// sameOrigin reports whether the request's Origin is the configured origin it
// was addressed to (the public URL when its Host names none of them), so one
// console origin never accepts another's requests.
func (s *Server) sameOrigin(r *http.Request) bool {
	origin, ok := s.hostOrigin(r)
	if !ok {
		origin = s.config.PublicURL
	}
	return r.Header.Get("Origin") == origin
}

func (s *Server) cookieName() string {
	if strings.HasPrefix(s.config.PublicURL, "https://") {
		return "__Host-covee_session"
	}
	return "covee_session"
}
func (s *Server) cookie(w http.ResponseWriter, value string, expiry time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.config.PublicURL, "https://"), SameSite: http.SameSiteStrictMode, Expires: expiry, MaxAge: maxAge})
}

func (s *Server) allowLogin(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	now := time.Now()
	for k, v := range s.attempts {
		if now.After(v.until) {
			delete(s.attempts, k)
		}
	}
	a, ok := s.attempts[host]
	if !ok {
		if len(s.attempts) >= 1024 {
			return false
		}
		a.until = now.Add(time.Minute)
	}
	a.count++
	s.attempts[host] = a
	return a.count <= 10
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.config.mode() != "token" {
		fail(w, 404, "not_found", "Token login is disabled")
		return
	}
	if !s.sameOrigin(r) {
		fail(w, 403, "origin_rejected", "Request origin is not allowed")
		return
	}
	if !s.allowLogin(r) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "rate_limited", "Too many login attempts; try again in one minute")
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !sameSecret(in.Token, s.config.AdminToken) {
		fail(w, 401, "unauthorized", "Invalid administrator token")
		return
	}
	sess, ok := s.issueSession(w, r, localActor(), time.Now().Add(sessionDuration))
	if !ok {
		return
	}
	respond(w, 200, sessionResponse(sess))
}

func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, actor Actor, expires time.Time) (session, bool) {
	s.sessionMu.Lock()
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= 1024 {
		s.sessionMu.Unlock()
		fail(w, 503, "session_capacity", "Session capacity reached")
		return session{}, false
	}
	if old, err := r.Cookie(s.cookieName()); err == nil {
		delete(s.sessions, old.Value)
	}
	token := randomToken()
	sess := session{csrf: randomToken(), expires: expires, actor: actor}
	s.sessions[token] = sess
	s.sessionMu.Unlock()
	s.cookie(w, token, sess.expires, max(1, int(math.Ceil(time.Until(sess.expires).Seconds()))))
	return sess, true
}
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header := r.Header.Get("Authorization"); header != "" {
			if s.config.mode() != "token" || !strings.HasPrefix(header, "Bearer ") || !sameSecret(strings.TrimPrefix(header, "Bearer "), s.config.AdminToken) {
				fail(w, 401, "unauthorized", "Authentication required")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, session{actor: localActor()})))
			return
		}
		cookie, err := r.Cookie(s.cookieName())
		if err != nil {
			fail(w, 401, "unauthorized", "Authentication required")
			return
		}
		s.sessionMu.Lock()
		sess, ok := s.sessions[cookie.Value]
		if ok && time.Now().After(sess.expires) {
			delete(s.sessions, cookie.Value)
			ok = false
		}
		s.sessionMu.Unlock()
		if !ok {
			fail(w, 401, "unauthorized", "Authentication required")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && (!s.sameOrigin(r) || !sameSecret(r.Header.Get("X-CSRF-Token"), sess.csrf)) {
			fail(w, 403, "csrf_rejected", "A valid same-origin CSRF token is required")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.URL.Path != "/api/logout" && sess.actor.Role != roleAdmin {
			fail(w, 403, "forbidden", "Your role permits viewing only")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, sess)))
	})
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(w, 415, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			fail(w, 413, "body_too_large", "Request body is too large")
		} else {
			fail(w, 400, "invalid_json", "Request body must contain one valid JSON object")
		}
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		fail(w, 400, "invalid_json", "Request body must contain one valid JSON object")
		return false
	}
	return true
}
func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, map[string]string{"error": message, "code": code})
}
func upstreamFail(w http.ResponseWriter, err error) {
	status, code, message := upstreamCode(err)
	fail(w, status, code, message)
}
func revision(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])
}

// mutate journals an intent durably before invoking Headscale. A missing result
// after a process crash is deliberately visible as an unresolved intent.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, action, target string, fn func() (any, error), status int) {
	id := randomToken()
	w.Header().Set("X-Request-ID", id)
	actor := requestSession(r).actor
	if err := s.audit.append(action, target, "intent", id, actor); err != nil {
		fail(w, 503, "audit_unavailable", "Audit persistence is unavailable; operation was not sent to Headscale")
		return
	}
	result, err := fn()
	outcome := "success"
	if err != nil {
		outcome = "failed"
		var ue *upstreamError
		if errors.As(err, &ue) && ue.uncertain {
			outcome = "uncertain"
		}
	}
	if auditErr := s.audit.append(action, target, outcome, id, actor); auditErr != nil {
		fail(w, 503, "audit_result_failed", "Audit result persistence failed; the operation may have completed. Inspect current state before retrying.")
		return
	}
	if err != nil {
		upstreamFail(w, err)
		return
	}
	respond(w, status, result)
}
