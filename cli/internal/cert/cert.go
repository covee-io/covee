// Package cert obtains the network's public TLS certificate from an ACME
// certificate authority (Let's Encrypt) by proving control of the domain with
// a DNS TXT record. The server therefore needs no open port for issuance.
package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"covee.io/cli/internal/dns"
)

const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Result is an issued certificate. KeyPEM is private.
type Result struct {
	FullChainPEM []byte
	KeyPEM       []byte
	NotAfter     time.Time
	Issuer       string
}

// Issuer obtains certificates through one ACME directory.
type Issuer struct {
	DirectoryURL string
	// AccountKeyPEM reuses an existing ACME account key. When empty a new key
	// is created and returned by Obtain for safekeeping.
	AccountKeyPEM []byte
	DNS           dns.Provider
	Say           func(format string, args ...any)
	// Client replaces the ACME client (tests point it at a local server).
	Client *acme.Client
}

// TermsURL returns the certificate authority's current subscriber agreement,
// which the person must accept before an account is registered.
func TermsURL(ctx context.Context, directory string) (string, error) {
	c := &acme.Client{DirectoryURL: directory}
	d, err := c.Discover(ctx)
	if err != nil {
		return "", fmt.Errorf("reaching the certificate authority: %w", err)
	}
	return d.Terms, nil
}

func (i *Issuer) say(format string, args ...any) {
	if i.Say != nil {
		i.Say(format, args...)
	}
}

// Obtain issues a certificate for host and any further names, such as the
// in-network console. It returns the certificate and the ACME account key
// (new or reused).
func (i *Issuer) Obtain(ctx context.Context, host string, also ...string) (*Result, []byte, error) {
	names := append([]string{host}, also...)
	accountKey, accountPEM, err := loadOrCreateKey(i.AccountKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	client := i.Client
	if client == nil {
		client = &acme.Client{DirectoryURL: i.DirectoryURL}
	}
	client.Key = accountKey
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, nil, fmt.Errorf("registering with the certificate authority: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, nil, fmt.Errorf("requesting a certificate for %s: %w", strings.Join(names, ", "), err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := i.authorize(ctx, client, authzURL); err != nil {
			return nil, nil, err
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, fmt.Errorf("waiting for the certificate order: %w", err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}, DNSNames: names}, certKey)
	if err != nil {
		return nil, nil, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("finishing the certificate: %w", err)
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("the certificate authority returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, err
	}
	for _, name := range names {
		if err := leaf.VerifyHostname(name); err != nil {
			return nil, nil, fmt.Errorf("issued certificate does not cover %s: %w", name, err)
		}
	}
	var full []byte
	for _, der := range chain {
		full = append(full, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return nil, nil, err
	}
	return &Result{
		FullChainPEM: full,
		KeyPEM:       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		NotAfter:     leaf.NotAfter,
		Issuer:       leaf.Issuer.CommonName,
	}, accountPEM, nil
}

func (i *Issuer) authorize(ctx context.Context, client *acme.Client, url string) error {
	z, err := client.GetAuthorization(ctx, url)
	if err != nil {
		return fmt.Errorf("reading the domain check: %w", err)
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "dns-01" {
			chal = c
		}
	}
	if chal == nil {
		return errors.New("the certificate authority offered no DNS domain check")
	}
	value, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	name := "_acme-challenge." + z.Identifier.Value
	i.say("  Proving control of %s with a temporary DNS record...", z.Identifier.Value)
	if err := i.DNS.SetTXT(ctx, name, value); err != nil {
		return err
	}
	defer func() {
		// Best effort with a fresh context: cleanup must not depend on the caller's.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := i.DNS.RemoveTXT(cleanup, name, value); err != nil {
			i.say("  Could not remove the temporary record %s; delete it by hand: %v", name, err)
		}
	}()
	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("starting the domain check: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("the domain check failed: %w", err)
	}
	return nil
}

func loadOrCreateKey(existing []byte) (crypto.Signer, []byte, error) {
	if len(existing) > 0 {
		block, _ := pem.Decode(existing)
		if block == nil {
			return nil, nil, errors.New("stored ACME account key is not PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("stored ACME account key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, nil, errors.New("stored ACME account key cannot sign")
		}
		return signer, existing, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
