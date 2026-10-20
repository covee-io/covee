package identity

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// RunAccounts implements `covee-identity accounts <action> [flags]` for the
// operator tooling. It prints exactly one JSON object and returns the exit code.
func RunAccounts(args []string, stdout io.Writer) int {
	result, err := runAccounts(args, time.Now())
	enc := json.NewEncoder(stdout)
	if err != nil {
		enc.Encode(map[string]string{"error": err.Error()})
		return 1
	}
	enc.Encode(result)
	return 0
}

func parseLifetime(v string) (time.Duration, error) {
	var d time.Duration
	var err error
	if strings.HasSuffix(v, "d") {
		var days int
		days, err = strconv.Atoi(strings.TrimSuffix(v, "d"))
		d = time.Duration(days) * 24 * time.Hour
	} else {
		d, err = time.ParseDuration(v)
	}
	if err != nil || d < time.Hour || d > 14*24*time.Hour {
		return 0, errors.New("expires must be between 1h and 14d, such as 72h or 7d")
	}
	return d, nil
}

func parseBool(v string) (bool, error) {
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errors.New("enroll must be true or false")
}

func runAccounts(args []string, now time.Time) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("usage: accounts invite|reset|update|remove|list [flags]")
	}
	action := args[0]
	fs := flag.NewFlagSet("accounts "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", DefaultAccountsFile, "accounts file")
	email := fs.String("email", "", "account email address")
	name := fs.String("name", "", "display name")
	role := fs.String("role", "", "admin, reader or none")
	enroll := fs.String("enroll", "", "true or false")
	expires := fs.String("expires", "72h", "invite lifetime, 1h to 14d")
	if err := fs.Parse(args[1:]); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	if fs.NArg() != 0 {
		return nil, errors.New("unexpected arguments")
	}
	store := NewAccountStore(*file)
	if action == "list" {
		doc, err := store.Read()
		if err != nil {
			return nil, err
		}
		type entry struct {
			Email         string     `json:"email"`
			Name          string     `json:"name"`
			Role          string     `json:"role"`
			Enroll        bool       `json:"enroll"`
			Passkeys      int        `json:"passkeys"`
			Password      bool       `json:"password"`
			InvitePending bool       `json:"invite_pending"`
			Locked        bool       `json:"locked"`
			Created       time.Time  `json:"created"`
			LastSignIn    *time.Time `json:"last_sign_in"`
		}
		list := []entry{}
		for _, a := range doc.Accounts {
			e := entry{Email: a.Email, Name: a.Name, Role: roleName(a.Role), Enroll: a.Enroll, Passkeys: len(a.Passkeys), Password: a.PasswordHash != "",
				InvitePending: a.Invite != nil && now.Before(a.Invite.Expires), Locked: now.Before(a.LockedUntil), Created: a.Created}
			if !a.LastSignIn.IsZero() {
				last := a.LastSignIn
				e.LastSignIn = &last
			}
			list = append(list, e)
		}
		return map[string]any{"accounts": list}, nil
	}
	address, err := normalizeEmail(*email)
	if err != nil {
		return nil, err
	}
	switch action {
	case "invite":
		if !textOK(strings.TrimSpace(*name), 1, 100) {
			return nil, errors.New("name must be 1 to 100 characters")
		}
		r, err := roleValue(*role)
		if err != nil {
			return nil, err
		}
		if *enroll == "" {
			*enroll = "true"
		}
		e, err := parseBool(*enroll)
		if err != nil {
			return nil, err
		}
		if r == "" && !e {
			return nil, errors.New("an account needs a console role, permission to add devices, or both")
		}
		lifetime, err := parseLifetime(*expires)
		if err != nil {
			return nil, err
		}
		token, invite := newInvite(now, lifetime)
		err = store.Update(func(doc *accountsDocument) error {
			if doc.byEmail(address) >= 0 {
				return errors.New("an account with this email address already exists")
			}
			doc.Accounts = append(doc.Accounts, Account{ID: newAccountID(), Email: address, Name: strings.TrimSpace(*name), Role: r, Enroll: e,
				Created: now.UTC().Truncate(time.Second), Invite: invite})
			return nil
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"email": address, "invite_token": token, "expires": invite.Expires.Format(time.RFC3339)}, nil
	case "reset":
		lifetime, err := parseLifetime(*expires)
		if err != nil {
			return nil, err
		}
		token, invite := newInvite(now, lifetime)
		err = store.Update(func(doc *accountsDocument) error {
			i := doc.byEmail(address)
			if i < 0 {
				return errors.New("no account with this email address")
			}
			a := &doc.Accounts[i]
			a.Passkeys, a.PasswordHash, a.TOTPSecret, a.TOTPLastStep = nil, "", "", 0
			a.Failures, a.LockedUntil, a.Invite = 0, time.Time{}, invite
			return nil
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"email": address, "invite_token": token, "expires": invite.Expires.Format(time.RFC3339)}, nil
	case "update":
		if *role == "" && *enroll == "" {
			return nil, errors.New("give --role, --enroll or both")
		}
		var result map[string]any
		err = store.Update(func(doc *accountsDocument) error {
			i := doc.byEmail(address)
			if i < 0 {
				return errors.New("no account with this email address")
			}
			a := doc.Accounts[i]
			if *role != "" {
				r, err := roleValue(*role)
				if err != nil {
					return err
				}
				a.Role = r
			}
			if *enroll != "" {
				e, err := parseBool(*enroll)
				if err != nil {
					return err
				}
				a.Enroll = e
			}
			if a.Role == "" && !a.Enroll {
				return errors.New("an account needs a console role, permission to add devices, or both")
			}
			doc.Accounts[i] = a
			result = map[string]any{"email": address, "role": roleName(a.Role), "enroll": a.Enroll}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return result, nil
	case "remove":
		err = store.Update(func(doc *accountsDocument) error {
			i := doc.byEmail(address)
			if i < 0 {
				return errors.New("no account with this email address")
			}
			doc.Accounts = append(doc.Accounts[:i], doc.Accounts[i+1:]...)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"removed": address}, nil
	}
	return nil, fmt.Errorf("unknown accounts action %q", action)
}
