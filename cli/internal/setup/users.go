package setup

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/remote"
)

var emailRE = regexp.MustCompile(`^[^@\s\x00-\x1f]{1,64}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,}$`)

func checkEmail(v string) error {
	if len(v) > 254 || !emailRE.MatchString(strings.ToLower(v)) {
		return errors.New("type an email address such as alice@example.com")
	}
	return nil
}

func checkDisplayName(v string) error {
	if v == "" || len(v) > 100 || strings.IndexFunc(v, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return errors.New("use 1 to 100 printable characters")
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// localAccounts runs one account action through the network's sign-in service.
func (s *session) localAccounts(ctx context.Context, args string) (map[string]any, error) {
	if s.n.SignIn.Local == nil {
		return nil, fmt.Errorf("Covee accounts are off for %s; turn them on with `covee auth add %s accounts`", s.n.Name, s.n.Name)
	}
	out, err := s.server(true).covee.Output(ctx, "cd "+serverSource+" && python3 scripts/deploy.py local-accounts --directory "+remote.Quote(s.n.Runtime)+" "+args, nil)
	var reply map[string]any
	if jerr := lastJSON(out, &reply); jerr == nil && err == nil {
		return reply, nil
	}
	// The deployment tool reports refusals on standard error as "ERROR: ...".
	if err != nil {
		msg := err.Error()
		if i := strings.Index(msg, "ERROR: "); i >= 0 {
			msg = strings.TrimSpace(msg[i+len("ERROR: "):])
		}
		return nil, errors.New(msg)
	}
	return nil, errors.New("the network returned an unreadable answer")
}

func (s *session) inviteLink(reply map[string]any, who string) error {
	token, _ := reply["invite_token"].(string)
	if token == "" {
		return errors.New("the network did not return an invite")
	}
	expires, _ := reply["expires"].(string)
	when := expires
	if t, err := time.Parse(time.RFC3339, expires); err == nil {
		when = t.Local().Format("Mon 2 Jan 15:04")
	}
	s.say("Invite for %s (works once, until %s):\n\n  https://%s/identity/local/invite#%s\n", who, when, s.n.Hostname, token)
	s.say("Opening it sets up a passkey (Face ID, Touch ID or Windows Hello), or a password with an")
	s.say("authenticator app. Send the link privately: anyone holding it can claim the account until then.")
	return nil
}

func roleArg(role string) (string, error) {
	switch role {
	case "admin", "reader", "none":
		return role, nil
	}
	return "", errors.New("role must be admin, reader or none")
}

// UsersInvite creates a Covee account and prints its one-time invite link.
func UsersInvite(ctx context.Context, env *Env, name, email, display, role string, enroll bool, expires string) error {
	if err := checkEmail(email); err != nil {
		return err
	}
	if err := checkDisplayName(display); err != nil {
		return err
	}
	role, err := roleArg(role)
	if err != nil {
		return err
	}
	if role == "none" && !enroll {
		return errors.New("give the account console access, device access, or both")
	}
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	args := fmt.Sprintf("--action invite --email %s --name %s --role %s --enroll %t --expires %s", remote.Quote(strings.ToLower(email)), remote.Quote(display), role, enroll, remote.Quote(expires))
	reply, err := s.localAccounts(ctx, args)
	if err != nil {
		return err
	}
	return s.inviteLink(reply, display)
}

// UsersReset removes an account's passkeys and password and issues a new invite.
func UsersReset(ctx context.Context, env *Env, name, email, expires string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	ok, err := env.Ask.Confirm("reset_account", fmt.Sprintf("Remove every passkey and the password of %s and send a new invite", email), false)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	reply, err := s.localAccounts(ctx, "--action reset --email "+remote.Quote(strings.ToLower(email))+" --expires "+remote.Quote(expires))
	if err != nil {
		return err
	}
	return s.inviteLink(reply, email)
}

// UsersUpdate changes an account's console role or device access.
func UsersUpdate(ctx context.Context, env *Env, name, email, role string, enroll *bool) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	args := "--action update --email " + remote.Quote(strings.ToLower(email))
	if role != "" {
		if role, err = roleArg(role); err != nil {
			return err
		}
		args += " --role " + role
	}
	if enroll != nil {
		args += fmt.Sprintf(" --enroll %t", *enroll)
	}
	reply, err := s.localAccounts(ctx, args)
	if err != nil {
		return err
	}
	s.say("Updated %s: role %v, may add devices: %v.", email, describeRole(reply["role"]), reply["enroll"])
	return nil
}

// UsersRemove deletes a Covee account after confirmation.
func UsersRemove(ctx context.Context, env *Env, name, email string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	ok, err := env.Ask.Confirm("remove_account", fmt.Sprintf("Delete the Covee account %s from %s", email, s.n.Name), false)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	if _, err := s.localAccounts(ctx, "--action remove --email "+remote.Quote(strings.ToLower(email))); err != nil {
		return err
	}
	s.say("Deleted %s. Devices it already added stay until you remove them in the console.", email)
	return nil
}

// describeRole accepts both the short names the accounts command prints and
// the role values stored in grants.
func describeRole(v any) string {
	switch v {
	case "Covee.Admin", "admin":
		return "admin"
	case "Covee.Reader", "reader":
		return "reader"
	}
	return "none"
}

// UsersList shows everyone who can sign in to a network.
func UsersList(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	if s.n.SignIn.Local != nil {
		reply, err := s.localAccounts(ctx, "--action list")
		if err != nil {
			return err
		}
		accounts, _ := reply["accounts"].([]any)
		s.say("Covee accounts (%d):", len(accounts))
		for _, a := range accounts {
			m, _ := a.(map[string]any)
			var how []string
			if n, _ := m["passkeys"].(float64); n > 0 {
				how = append(how, fmt.Sprintf("%d passkey(s)", int(n)))
			}
			if m["password"] == true {
				how = append(how, "password + code")
			}
			if m["invite_pending"] == true {
				how = append(how, "invite not used yet")
			}
			if m["locked"] == true {
				how = append(how, "locked after failed attempts")
			}
			s.say("  %-30s %-20s role %-6s devices %-5v %s", m["email"], m["name"], describeRole(m["role"]), m["enroll"], strings.Join(how, ", "))
		}
	}
	if s.n.SignIn.Google != nil || s.n.SignIn.Apple != nil {
		grants, err := s.server(true).readGrants(ctx, s.n.Runtime)
		if err != nil {
			return err
		}
		s.say("Approved Google and Apple accounts (%d):", len(grants))
		for _, g := range grants {
			s.say("  %-7v %-40v role %-6s devices %v", g["provider"], g["subject"], describeRole(g["role"]), g["enroll"])
		}
	}
	if e := s.n.SignIn.Entra; e != nil {
		s.say("Microsoft: managed in %s: the Covee Admin and Covee Reader roles, and the %s for devices.", nonEmpty(e.TenantName, "your tenant"), groupLabel(e))
	}
	return nil
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// stepLocalAdmin creates the first Covee account for the person running setup.
func (s *session) stepLocalAdmin(ctx context.Context) error {
	l := s.n.SignIn.Local
	args := fmt.Sprintf("--action invite --email %s --name %s --role admin --enroll true --expires 72h", remote.Quote(l.FirstAdmin), remote.Quote(l.FirstAdminName))
	reply, err := s.localAccounts(ctx, args)
	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			s.say("  Your account exists already; use `covee users reset %s --email %s` for a new invite.", s.n.Name, l.FirstAdmin)
			return nil
		}
		return err
	}
	return s.inviteLink(reply, l.FirstAdminName)
}
