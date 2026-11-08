package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestWildcardIsProvedAtItsBaseName(t *testing.T) {
	for _, tc := range []struct {
		z    acme.Authorization
		want string
	}{
		{acme.Authorization{Identifier: acme.AuthzID{Type: "dns", Value: "control.covee.io"}}, "_acme-challenge.control.covee.io"},
		// RFC 8555 7.1.4: a wildcard's authorization names the base domain and sets wildcard.
		{acme.Authorization{Identifier: acme.AuthzID{Type: "dns", Value: "mesh.covee.io"}, Wildcard: true}, "_acme-challenge.mesh.covee.io"},
		{acme.Authorization{Identifier: acme.AuthzID{Type: "dns", Value: "*.mesh.covee.io"}, Wildcard: true}, "_acme-challenge.mesh.covee.io"},
	} {
		if got := challengeName(&tc.z); got != tc.want {
			t.Errorf("challengeName(%q) = %q, want %q", tc.z.Identifier.Value, got, tc.want)
		}
	}
}

func TestIssuedWildcardIsCheckedWithANameItCovers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "control.covee.io"},
		DNSNames: []string{"control.covee.io", "*.mesh.covee.io"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"control.covee.io", "*.mesh.covee.io"} {
		if err := leaf.VerifyHostname(probeName(name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A certificate that only names the console does not pass for the wildcard.
	der, _ = x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"control.covee.io", "console.mesh.covee.io"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}}, &key.PublicKey, key)
	leaf, _ = x509.ParseCertificate(der)
	if err := leaf.VerifyHostname(probeName("*.mesh.covee.io")); err == nil {
		t.Error("a certificate without the wildcard passed for it")
	}
}
