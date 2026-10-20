package identity

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"rsc.io/qr"
)

//go:embed assets/local.js
var localScript []byte

const localCSP = "default-src 'none'; script-src 'self'; connect-src 'self'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

var (
	errDenied = errors.New("access denied")
	errBusy   = errors.New("temporarily unavailable")
)

// localProvider holds Covee's own accounts. It keeps no account state in
// memory: every operation re-reads the accounts file.
type localProvider struct {
	store   *AccountStore
	web     *webauthn.WebAuthn
	host    string
	slots   chan struct{} // bounds concurrent argon2id hashing (memory)
	dummy   string        // hash checked for unknown accounts, so timing does not reveal them
	mu      sync.Mutex
	burst   float64 // bucket size; one attempt is restored per second
	tokens  float64
	updated time.Time
}

func newLocal(issuer string, p ProviderConfig) (*localProvider, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return nil, errors.New("local accounts need the identity issuer to use a DNS hostname")
	}
	web, err := webauthn.New(&webauthn.Config{
		RPID: host, RPDisplayName: "Covee", RPOrigins: []string{u.Scheme + "://" + u.Host},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(), UserVerification: protocol.VerificationRequired},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute},
		},
	})
	if err != nil {
		return nil, errors.New("local account passkey settings are invalid")
	}
	return &localProvider{store: NewAccountStore(p.AccountsFile), web: web, host: host, slots: make(chan struct{}, 2),
		dummy: hashPassword(string(randomBytes(24))), burst: 16, tokens: 16, updated: time.Now()}, nil
}

// allow is a global bucket for sign-in and setup attempts.
func (l *localProvider) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens = min(l.burst, l.tokens+now.Sub(l.updated).Seconds())
	l.updated = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// hash runs one argon2id operation; at most two run at once.
func (l *localProvider) hash(work func()) error {
	select {
	case l.slots <- struct{}{}:
	case <-time.After(3 * time.Second):
		return errBusy
	}
	defer func() { <-l.slots }()
	work()
	return nil
}

type webUser struct{ a *Account }

func (u webUser) WebAuthnID() []byte {
	id, _ := base64.RawURLEncoding.DecodeString(u.a.ID)
	return id
}
func (u webUser) WebAuthnName() string        { return u.a.Email }
func (u webUser) WebAuthnDisplayName() string { return u.a.Name }
func (u webUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.a.Passkeys))
	for _, p := range u.a.Passkeys {
		out = append(out, p.Credential)
	}
	return out
}

var credentialParams = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

// issue is the shared end of every sign-in: it applies the flow's role or
// enrollment requirement, then issues a one-minute code for the downstream
// client. namespace and upstreamSubject together form the stable identity.
func (s *Server) issue(pending flow, namespace, upstreamSubject, role string, enroll bool) (string, error) {
	if (pending.kind == "console" && role == "") || (pending.kind == "enrollment" && !enroll) {
		return "", errDenied
	}
	hash := sha256.Sum256([]byte(namespace + "\x00" + upstreamSubject))
	subject := hex.EncodeToString(hash[:])
	claims := identityClaims{Subject: subject, Username: "u" + subject, Name: "Covee user", UpstreamIssuer: namespace, UpstreamSubject: upstreamSubject}
	if pending.kind == "console" {
		claims.Roles = []string{role}
	} else {
		claims.Groups = []string{"covee.enroll"}
	}
	now := time.Now()
	value := random()
	s.mu.Lock()
	s.clean(now)
	if len(s.codes) >= 2048 {
		s.mu.Unlock()
		return "", errBusy
	}
	s.codes[value] = code{authorization: pending.authorization, claims: claims, expires: now.Add(time.Minute)}
	s.mu.Unlock()
	target, _ := url.Parse(pending.redirect)
	q := target.Query()
	q.Set("code", value)
	q.Set("state", pending.authorization.state)
	target.RawQuery = q.Encode()
	return target.String(), nil
}

// finishHTML answers an issue() result as a browser navigation.
func (s *Server) finishHTML(w http.ResponseWriter, r *http.Request, target string, err error, provider, subject string) {
	switch {
	case errors.Is(err, errDenied):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(403)
		deniedPage.Execute(w, pageData{Title: "Waiting for approval", Host: s.host(), Provider: provider, Subject: subject})
	case err != nil:
		deny(w, 503, "temporarily_unavailable")
	default:
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
}

func (s *Server) localNamespace() string { return s.config.Issuer + "#local" }

// localFlow returns the browser's pending local sign-in, checking its binding.
// When consume is set the flow is removed so it cannot be used twice.
func (s *Server) localFlow(r *http.Request, state string, consume bool) (flow, bool) {
	cookie, err := r.Cookie(flowCookie)
	if err != nil || !textOK(state, 16, 256) {
		return flow{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.flows[state]
	if !ok || !time.Now().Before(pending.expires) || pending.provider != "local" || !same(cookie.Value, pending.binding) {
		return flow{}, false
	}
	if consume {
		delete(s.flows, state)
	}
	return pending, true
}

// readJSON accepts a same-origin JSON POST of at most 64 KiB into v.
func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Header.Get("Origin") != s.origin() {
		deny(w, 403, "origin_rejected")
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" {
		deny(w, 400, "invalid_request")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		deny(w, 400, "invalid_request")
		return false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		deny(w, 400, "invalid_request")
		return false
	}
	return true
}

func (s *Server) localHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", localCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *Server) serveLocal(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/identity/local/app.js" && r.Method == "GET":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write(localScript)
	case path == "/identity/local/invite" && r.Method == "GET":
		if r.URL.RawQuery != "" {
			deny(w, 400, "invalid_request")
			return
		}
		s.localHeaders(w)
		invitePage.Execute(w, pageData{Title: "Set up your account", Host: s.host()})
	case path == "/identity/local/invite/info" && r.Method == "POST":
		s.inviteInfo(w, r)
	case path == "/identity/local/invite/passkey/options" && r.Method == "POST":
		s.invitePasskeyOptions(w, r)
	case path == "/identity/local/invite/passkey/finish" && r.Method == "POST":
		s.invitePasskeyFinish(w, r)
	case path == "/identity/local/invite/totp" && r.Method == "POST":
		s.inviteTOTP(w, r)
	case path == "/identity/local/invite/password" && r.Method == "POST":
		s.invitePassword(w, r)
	case path == "/identity/local/passkey/options" && r.Method == "POST":
		s.passkeyOptions(w, r)
	case path == "/identity/local/passkey/finish" && r.Method == "POST":
		s.passkeyFinish(w, r)
	case path == "/identity/local/password" && r.Method == "POST":
		s.passwordSignIn(w, r)
	default:
		deny(w, 404, "not_found")
	}
}

// renderLocalSignIn shows the local sign-in page for a pending flow.
func (s *Server) renderLocalSignIn(w http.ResponseWriter, status int, state, message string) {
	s.localHeaders(w)
	w.WriteHeader(status)
	localSignIn.Execute(w, pageData{Title: "Sign in", Host: s.host(), State: state, Error: message})
}

const signInFailed = "Sign-in failed. Check your email address, password and code, then try again."

func (s *Server) passwordSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.origin() {
		deny(w, 403, "origin_rejected")
		return
	}
	form, err := parseForm(w, r)
	if err != nil {
		deny(w, 400, "invalid_request")
		return
	}
	state := single(form, "state")
	if _, ok := s.localFlow(r, state, false); !ok {
		deny(w, 400, "invalid_request")
		return
	}
	if !s.local.allow() {
		w.Header().Set("Retry-After", "2")
		deny(w, 429, "rate_limited")
		return
	}
	email, _ := normalizeEmail(single(form, "email"))
	password, code := single(form, "password"), single(form, "code")
	now := time.Now()
	doc, err := s.local.store.Read()
	if err != nil {
		deny(w, 503, "temporarily_unavailable")
		return
	}
	i := -1
	if email != "" {
		i = doc.byEmail(email)
	}
	var account Account
	stored := s.local.dummy
	usable := i >= 0 && !now.Before(doc.Accounts[i].LockedUntil) && doc.Accounts[i].PasswordHash != "" && doc.Accounts[i].TOTPSecret != ""
	if usable {
		account = doc.Accounts[i]
		stored = account.PasswordHash
	}
	// Unknown, locked and password-less accounts take the same time as real ones.
	passwordOK := false
	if s.local.hash(func() { passwordOK = verifyPassword(stored, password) }) != nil {
		w.Header().Set("Retry-After", "2")
		deny(w, 429, "rate_limited")
		return
	}
	step, codeOK := int64(0), false
	if usable {
		step, codeOK = totpMatch(account.TOTPSecret, code, now, account.TOTPLastStep)
	}
	success := usable && passwordOK && codeOK
	if i < 0 {
		s.renderLocalSignIn(w, 401, state, signInFailed)
		return
	}
	err = s.local.store.Update(func(doc *accountsDocument) error {
		j := doc.byEmail(email)
		if j < 0 {
			success = false
			return nil
		}
		a := &doc.Accounts[j]
		if success && (a.ID != account.ID || a.TOTPLastStep >= step || a.PasswordHash != account.PasswordHash) {
			success = false // changed or the code was used meanwhile
		}
		if success {
			a.TOTPLastStep, a.Failures, a.LastSignIn = step, 0, now.UTC().Truncate(time.Second)
			account = *a
			return nil
		}
		if now.Before(a.LockedUntil) {
			return nil
		}
		a.Failures++
		if a.Failures >= lockAfter {
			a.Failures, a.LockedUntil = 0, now.Add(lockFor).UTC()
		}
		return nil
	})
	if err != nil {
		deny(w, 503, "temporarily_unavailable")
		return
	}
	if !success {
		s.renderLocalSignIn(w, 401, state, signInFailed)
		return
	}
	pending, ok := s.localFlow(r, state, true)
	if !ok {
		deny(w, 400, "invalid_request")
		return
	}
	s.cookie(w, "", time.Unix(1, 0), http.SameSiteLaxMode, -1)
	target, err := s.issue(pending, s.localNamespace(), account.ID, account.Role, account.Enroll)
	s.finishHTML(w, r, target, err, "Covee account", account.Email)
}

func (s *Server) passkeyOptions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State string `json:"state"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	if _, ok := s.localFlow(r, req.State, false); !ok {
		deny(w, 400, "invalid_request")
		return
	}
	if !s.local.allow() {
		w.Header().Set("Retry-After", "2")
		deny(w, 429, "rate_limited")
		return
	}
	assertion, session, err := s.local.web.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		deny(w, 503, "temporarily_unavailable")
		return
	}
	s.mu.Lock()
	pending, ok := s.flows[req.State]
	if ok {
		pending.login = session
		s.flows[req.State] = pending
	}
	s.mu.Unlock()
	if !ok {
		deny(w, 400, "invalid_request")
		return
	}
	reply(w, 200, assertion)
}

func (s *Server) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State      string          `json:"state"`
		Credential json.RawMessage `json:"credential"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	// One attempt per challenge: the flow is consumed whatever happens next.
	pending, ok := s.localFlow(r, req.State, true)
	if !ok || pending.login == nil {
		deny(w, 400, "authentication_failed")
		return
	}
	s.cookie(w, "", time.Unix(1, 0), http.SameSiteLaxMode, -1)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		deny(w, 400, "authentication_failed")
		return
	}
	doc, err := s.local.store.Read()
	if err != nil {
		deny(w, 503, "temporarily_unavailable")
		return
	}
	var account *Account
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		i := doc.byID(base64.RawURLEncoding.EncodeToString(userHandle))
		if i < 0 {
			return nil, errors.New("unknown account")
		}
		a := doc.Accounts[i]
		account = &a
		return webUser{&a}, nil
	}
	_, credential, err := s.local.web.ValidatePasskeyLogin(handler, *pending.login, parsed)
	if err != nil || account == nil || credential.Authenticator.CloneWarning {
		deny(w, 400, "authentication_failed")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	err = s.local.store.Update(func(doc *accountsDocument) error {
		i := doc.byID(account.ID)
		if i < 0 {
			return errors.New("account removed")
		}
		a := &doc.Accounts[i]
		for k := range a.Passkeys {
			if bytes.Equal(a.Passkeys[k].Credential.ID, credential.ID) {
				a.Passkeys[k].Credential.Authenticator.SignCount = credential.Authenticator.SignCount
				a.Passkeys[k].Credential.Flags = credential.Flags
				a.Passkeys[k].LastUsed = now
				a.LastSignIn = now
				*account = *a
				return nil
			}
		}
		return errors.New("passkey removed")
	})
	if err != nil {
		deny(w, 400, "authentication_failed")
		return
	}
	target, err := s.issue(pending, s.localNamespace(), account.ID, account.Role, account.Enroll)
	switch {
	case errors.Is(err, errDenied):
		reply(w, 403, map[string]string{"error": "access_denied", "provider": "Covee account", "subject": account.Email})
	case err != nil:
		deny(w, 503, "temporarily_unavailable")
	default:
		reply(w, 200, map[string]string{"redirect": target})
	}
}

type inviteRequest struct {
	Token string `json:"token"`
}

const invalidInvite = "invalid_invite"

func (s *Server) inviteInfo(w http.ResponseWriter, r *http.Request) {
	var req inviteRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	if !s.local.allow() {
		deny(w, 429, "rate_limited")
		return
	}
	doc, err := s.local.store.Read()
	if err != nil {
		deny(w, 503, "temporarily_unavailable")
		return
	}
	i := doc.byInvite(req.Token, time.Now())
	if i < 0 {
		deny(w, 400, invalidInvite)
		return
	}
	a := doc.Accounts[i]
	reply(w, 200, map[string]any{"email": a.Email, "name": a.Name, "has_passkey": len(a.Passkeys) > 0, "has_password": a.PasswordHash != ""})
}

func (s *Server) invitePasskeyOptions(w http.ResponseWriter, r *http.Request) {
	var req inviteRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	if !s.local.allow() {
		deny(w, 429, "rate_limited")
		return
	}
	var creation *protocol.CredentialCreation
	err := s.local.store.Update(func(doc *accountsDocument) error {
		i := doc.byInvite(req.Token, time.Now())
		if i < 0 {
			return errors.New(invalidInvite)
		}
		a := &doc.Accounts[i]
		var exclude []protocol.CredentialDescriptor
		for _, p := range a.Passkeys {
			exclude = append(exclude, p.Credential.Descriptor())
		}
		var session *webauthn.SessionData
		var err error
		creation, session, err = s.local.web.BeginRegistration(webUser{a},
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(), UserVerification: protocol.VerificationRequired}),
			webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
			webauthn.WithCredentialParameters(credentialParams),
			webauthn.WithExclusions(exclude))
		if err != nil {
			return err
		}
		a.Invite.Registration = session
		return nil
	})
	if err != nil {
		deny(w, 400, invalidInvite)
		return
	}
	reply(w, 200, creation)
}

func (s *Server) invitePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token      string          `json:"token"`
		Credential json.RawMessage `json:"credential"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	if !s.local.allow() {
		deny(w, 429, "rate_limited")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		deny(w, 400, "registration_failed")
		return
	}
	now := time.Now()
	err = s.local.store.Update(func(doc *accountsDocument) error {
		i := doc.byInvite(req.Token, now)
		if i < 0 {
			return errors.New(invalidInvite)
		}
		a := &doc.Accounts[i]
		if a.Invite.Registration == nil {
			return errors.New("registration_failed")
		}
		credential, err := s.local.web.CreateCredential(webUser{a}, *a.Invite.Registration, parsed)
		if err != nil {
			return errors.New("registration_failed")
		}
		for _, other := range doc.Accounts {
			for _, p := range other.Passkeys {
				if bytes.Equal(p.Credential.ID, credential.ID) {
					return errors.New("registration_failed")
				}
			}
		}
		a.Passkeys = append(a.Passkeys, Passkey{Credential: *credential, Created: now.UTC().Truncate(time.Second)})
		a.Invite = nil
		return nil
	})
	if err != nil {
		code := "registration_failed"
		if err.Error() == invalidInvite {
			code = invalidInvite
		}
		deny(w, 400, code)
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (s *Server) inviteTOTP(w http.ResponseWriter, r *http.Request) {
	var req inviteRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	if !s.local.allow() {
		deny(w, 429, "rate_limited")
		return
	}
	secret, email := newTOTPSecret(), ""
	err := s.local.store.Update(func(doc *accountsDocument) error {
		i := doc.byInvite(req.Token, time.Now())
		if i < 0 {
			return errors.New(invalidInvite)
		}
		doc.Accounts[i].Invite.PendingTOTP = secret
		email = doc.Accounts[i].Email
		return nil
	})
	if err != nil {
		deny(w, 400, invalidInvite)
		return
	}
	issuer := "Covee " + s.local.host
	uri := (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + email,
		RawQuery: url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()}).String()
	result := map[string]string{"secret_base32": secret, "otpauth_uri": uri}
	if svg, err := qrSVG(uri); err == nil {
		result["qr_svg_data_uri"] = svg
	}
	reply(w, 200, result)
}

func (s *Server) invitePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	if !s.local.allow() {
		deny(w, 429, "rate_limited")
		return
	}
	now := time.Now()
	doc, err := s.local.store.Read()
	if err != nil {
		deny(w, 503, "temporarily_unavailable")
		return
	}
	i := doc.byInvite(req.Token, now)
	if i < 0 || doc.Accounts[i].Invite.PendingTOTP == "" {
		deny(w, 400, invalidInvite)
		return
	}
	account := doc.Accounts[i]
	if err := checkPassword(req.Password, account.Email); err != nil {
		reply(w, 400, map[string]string{"error": "weak_password", "message": err.Error()})
		return
	}
	step, ok := totpMatch(account.Invite.PendingTOTP, req.Code, now, 0)
	if !ok {
		deny(w, 400, "invalid_code")
		return
	}
	var hashed string
	if s.local.hash(func() { hashed = hashPassword(req.Password) }) != nil {
		w.Header().Set("Retry-After", "2")
		deny(w, 429, "rate_limited")
		return
	}
	err = s.local.store.Update(func(doc *accountsDocument) error {
		j := doc.byInvite(req.Token, now)
		if j < 0 || doc.Accounts[j].ID != account.ID || doc.Accounts[j].Invite.PendingTOTP != account.Invite.PendingTOTP {
			return errors.New(invalidInvite)
		}
		a := &doc.Accounts[j]
		a.PasswordHash, a.TOTPSecret, a.TOTPLastStep = hashed, a.Invite.PendingTOTP, step
		a.Failures, a.LockedUntil, a.Invite = 0, time.Time{}, nil
		return nil
	})
	if err != nil {
		deny(w, 400, invalidInvite)
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

// qrSVG renders text as a QR code SVG data URI.
func qrSVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	quiet := 4
	size := c.Size + 2*quiet
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, size, size, size, size)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.String())), nil
}
