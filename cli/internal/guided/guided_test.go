package guided

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"covee.io/cli/internal/prompt"
)

func pkcs8(t *testing.T, key any) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestCheckAppleKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := CheckAppleKey(pkcs8(t, p256)); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	for name, data := range map[string][]byte{"P-384": pkcs8(t, p384), "RSA": pkcs8(t, rsaKey), "text": []byte("hello"),
		"two blocks": append(pkcs8(t, p256), pkcs8(t, p256)...)} {
		if err := CheckAppleKey(data); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestGoogleCollectsAndChecksValues(t *testing.T) {
	var opened []string
	ask := &prompt.Scripted{Answers: map[string]string{
		"google_client_id":     "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com",
		"google_client_secret": "GOCSPX-abcdefghijklmnopqrstuvwx",
	}}
	res, err := Google(ask, func(u string) { opened = append(opened, u) }, "control.covee.io", "home", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Secret != "GOCSPX-abcdefghijklmnopqrstuvwx" || len(opened) != 1 {
		t.Fatalf("unexpected %+v %v", res, opened)
	}
	ask.Answers["google_client_id"] = "not-a-client"
	if _, err := Google(ask, func(string) {}, "control.covee.io", "home", ""); err == nil {
		t.Fatal("bad client ID accepted")
	}
	reused, err := Google(&prompt.Scripted{Answers: map[string]string{}}, func(string) {}, "vpn.covee.io", "office", "123456-abcdefghij.apps.googleusercontent.com")
	if err != nil || reused.ClientID != "123456-abcdefghij.apps.googleusercontent.com" {
		t.Fatalf("reuse = %+v, %v", reused, err)
	}
}

func TestAppleCollectsAndChecksTheKeyFile(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	path := filepath.Join(dir, "AuthKey_ABCDE12345.p8")
	if err := os.WriteFile(path, pkcs8(t, p256), 0o600); err != nil {
		t.Fatal(err)
	}
	answers := map[string]string{"apple_team_id": "87LFD98HJU", "apple_services_id": "io.covee.signin", "apple_key_id": "ABCDE12345", "apple_key_file": path}
	res, err := Apple(&prompt.Scripted{Answers: answers}, func(string) {}, "control.covee.io")
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyID != "ABCDE12345" || len(res.KeyPEM) == 0 {
		t.Fatalf("unexpected %+v", res)
	}
	answers["apple_key_id"] = "AAAAAAAAAA"
	if _, err := Apple(&prompt.Scripted{Answers: answers}, func(string) {}, "control.covee.io"); err == nil {
		t.Fatal("a key file for a different key ID was accepted")
	}
	answers["apple_key_id"], answers["apple_team_id"] = "ABCDE12345", "short"
	if _, err := Apple(&prompt.Scripted{Answers: answers}, func(string) {}, "control.covee.io"); err == nil {
		t.Fatal("bad team ID accepted")
	}
}
