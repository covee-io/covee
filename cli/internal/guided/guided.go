// Package guided walks the admin through the sign-in registrations that cannot
// be created automatically: Google and Apple offer no API for them. It shows
// exactly what to enter, then collects and checks the resulting values.
package guided

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"covee.io/cli/internal/prompt"
)

var (
	googleClientRE = regexp.MustCompile(`^[0-9]{6,20}-[a-z0-9]{10,64}\.apps\.googleusercontent\.com$`)
	appleIDRE      = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	servicesIDRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,154}$`)
)

// Open shows a web page in the default browser, best effort.
func Open(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return
	}
	_ = cmd.Start()
}

// CallbackURL is the broker's return address for a provider.
func CallbackURL(host, provider string) string {
	return "https://" + host + "/identity/callback/" + provider
}

// GoogleResult is a Google OAuth web client. Secret is private.
type GoogleResult struct {
	ClientID string
	Secret   string
}

// Google guides creation of a Google OAuth web client for host. When reuse is
// set, the admin only adds this network's redirect URI to that client.
func Google(ask prompt.Asker, open func(string), host, network, reuse string) (*GoogleResult, error) {
	redirect := CallbackURL(host, "google")
	if reuse != "" {
		ask.Say(`
Google sign-in: this organization already has the Google client
  %s
In the Google Cloud console, open that client and add this to
"Authorized redirect URIs", then save:
  %s`, reuse, redirect)
		open("https://console.cloud.google.com/auth/clients")
		ok, err := ask.Confirm("google_reuse_done", "Added", true)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, prompt.ErrAborted
		}
		return &GoogleResult{ClientID: reuse}, nil
	}
	ask.Say(`
Google sign-in needs a Google Cloud "OAuth client" that you create (Google
offers no way to create one automatically). Covee asks Google only for the
person's ID and name, never email or other data.

  1. In the page that opens, choose or create a Google Cloud project.
  2. If Google asks you to set up "branding" first: app name Covee, your
     support email, audience External. Add no scopes.
  3. Create client → Application type: Web application
       Name: Covee %s
       Authorized redirect URIs: %s
  4. Create, then copy the client ID and client secret.`, network, redirect)
	open("https://console.cloud.google.com/auth/clients")
	id, err := ask.Text("google_client_id", "Google client ID", "", func(v string) error {
		if !googleClientRE.MatchString(v) {
			return errors.New("a Google client ID looks like 1234567890-abc123.apps.googleusercontent.com")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	secret, err := ask.Secret("google_client_secret", "Google client secret", func(v string) error {
		if len(v) < 20 || len(v) > 200 || strings.ContainsAny(v, " \t") {
			return errors.New("that does not look like a Google client secret")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &GoogleResult{ClientID: id, Secret: secret}, nil
}

// AppleResult is a Sign in with Apple registration. KeyPEM is private.
type AppleResult struct {
	TeamID     string
	ServicesID string
	KeyID      string
	KeyPEM     []byte
}

// Apple guides the Sign in with Apple registration for host.
func Apple(ask prompt.Asker, open func(string), host string) (*AppleResult, error) {
	ask.Say(`
Apple sign-in needs three things in your Apple Developer account (Apple
offers no way to create them automatically):

  1. An App ID with "Sign in with Apple" enabled as a primary App ID
     (reuse one you have, or create one such as com.yourorg.covee).
  2. A Services ID (for example com.yourorg.covee.signin) with
     "Sign in with Apple" enabled and configured:
       Primary App ID: the App ID above
       Domains and subdomains: %s
       Return URLs: %s
  3. A key with "Sign in with Apple" enabled for that primary App ID.
     Download its .p8 file (Apple allows only one download).`, host, CallbackURL(host, "apple"))
	open("https://developer.apple.com/account/resources/identifiers/list/serviceId")
	team, err := ask.Text("apple_team_id", "Apple Team ID (10 characters, top right of the developer site)", "", checkAppleID)
	if err != nil {
		return nil, err
	}
	services, err := ask.Text("apple_services_id", "Services ID", "", func(v string) error {
		if !servicesIDRE.MatchString(v) || !strings.Contains(v, ".") {
			return errors.New("a Services ID looks like com.yourorg.covee.signin")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	keyID, err := ask.Text("apple_key_id", "Key ID (10 characters)", "", checkAppleID)
	if err != nil {
		return nil, err
	}
	var key []byte
	_, err = ask.Text("apple_key_file", "Path to the downloaded .p8 key file", "", func(v string) error {
		path := expand(v)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read %s", path)
		}
		if err := CheckAppleKey(data); err != nil {
			return err
		}
		if base := filepath.Base(path); strings.HasPrefix(base, "AuthKey_") && !strings.Contains(base, keyID) {
			return fmt.Errorf("this file is for a different key than %s", keyID)
		}
		key = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &AppleResult{TeamID: team, ServicesID: services, KeyID: keyID, KeyPEM: key}, nil
}

// GoogleAddRedirect asks the admin to add a network's new return address to its
// existing Google client.
func GoogleAddRedirect(ask prompt.Asker, open func(string), clientID, redirect string) error {
	ask.Say(`
Google sign-in: in the Google Cloud console, open the OAuth client
  %s
and add this to "Authorized redirect URIs" (keep the ones already there), then save:
  %s`, clientID, redirect)
	open("https://console.cloud.google.com/auth/clients")
	return confirmed(ask.Confirm("google_redirect_done", "Added", true))
}

// AppleAddRedirect asks the admin to add a network's new name and return
// address to its Sign in with Apple Services ID.
func AppleAddRedirect(ask prompt.Asker, open func(string), servicesID, host, redirect string) error {
	ask.Say(`
Apple sign-in: in your Apple Developer account, open Identifiers → Services IDs →
  %s
→ Sign in with Apple → Configure. Click + and add (keep the ones already there):
  Domains and subdomains: %s
  Return URLs: %s
then Next, Done, Continue and Save.`, servicesID, host, redirect)
	open("https://developer.apple.com/account/resources/identifiers/list/serviceId")
	return confirmed(ask.Confirm("apple_redirect_done", "Added", true))
}

func confirmed(ok bool, err error) error {
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	return nil
}

// GoogleAccepts asks Google whether a client accepts a return address: Google
// sends an unregistered one to its error page instead of the sign-in page.
func GoogleAccepts(ctx context.Context, client *http.Client, clientID, redirect string) (bool, error) {
	resp, err := authorize(ctx, client, "https://accounts.google.com/o/oauth2/v2/auth?"+url.Values{
		"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}}.Encode())
	if err != nil {
		return false, err
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode/100 != 3 || err != nil || location.Host == "" {
		return false, fmt.Errorf("Google answered unexpectedly (HTTP %d)", resp.StatusCode)
	}
	return !strings.Contains(location.Path, "/oauth/error"), nil
}

// AppleAccepts asks Apple whether a Services ID accepts a return address: Apple
// shows an error page instead of the sign-in page for an unregistered one.
func AppleAccepts(ctx context.Context, client *http.Client, servicesID, redirect string) (bool, error) {
	resp, err := authorize(ctx, client, "https://appleid.apple.com/auth/authorize?"+url.Values{
		"client_id": {servicesID}, "redirect_uri": {redirect}, "response_type": {"code"}, "response_mode": {"query"}}.Encode())
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Apple answered unexpectedly (HTTP %d)", resp.StatusCode)
	}
	return !bytes.Contains(resp.body, []byte(`"errorCode":"invalid_`)), nil
}

type answer struct {
	*http.Response
	body []byte
}

// authorize fetches a sign-in page without following redirects.
func authorize(ctx context.Context, client *http.Client, address string) (*answer, error) {
	c := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if client != nil {
		c.Transport = client.Transport
	}
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return &answer{resp, body}, nil
}

func checkAppleID(v string) error {
	if !appleIDRE.MatchString(v) {
		return errors.New("use the 10 capital letters and digits Apple shows")
	}
	return nil
}

// CheckAppleKey verifies a Sign in with Apple key: a PKCS#8 P-256 private key.
func CheckAppleKey(data []byte) error {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) > 0 {
		return errors.New("this is not an Apple .p8 key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("this is not an Apple .p8 key file")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return errors.New("Sign in with Apple keys use the P-256 curve; this key does not")
	}
	return nil
}

func expand(path string) string {
	path = strings.Trim(strings.TrimSpace(path), `"'`)
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
