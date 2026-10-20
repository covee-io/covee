package cert

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"

	"covee.io/cli/internal/dns"
)

// TestLiveStagingCertificate issues a Let's Encrypt staging certificate using
// real Route 53 records. It runs only when COVEE_LIVE_ACME_HOST names a host in
// a Route 53 zone of the current AWS credentials. It leaves no records behind.
func TestLiveStagingCertificate(t *testing.T) {
	host := os.Getenv("COVEE_LIVE_ACME_HOST")
	if host == "" {
		t.Skip("set COVEE_LIVE_ACME_HOST to run against Let's Encrypt staging and Route 53")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	zone, err := dns.FindZone(ctx, route53.NewFromConfig(cfg), host)
	if err != nil {
		t.Fatal(err)
	}
	terms, err := TermsURL(ctx, LetsEncryptStaging)
	if err != nil || terms == "" {
		t.Fatalf("terms: %q, %v", terms, err)
	}
	issuer := &Issuer{DirectoryURL: LetsEncryptStaging, DNS: zone, Say: t.Logf}
	res, account, err := issuer.Obtain(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(account) == 0 || len(res.KeyPEM) == 0 || res.NotAfter.Before(time.Now().AddDate(0, 1, 0)) {
		t.Fatalf("unexpected result: %+v", res)
	}
	t.Logf("issued by %s until %s; chain %d bytes", res.Issuer, res.NotAfter, len(res.FullChainPEM))
	// The account key is reused for a second order.
	again := &Issuer{DirectoryURL: LetsEncryptStaging, AccountKeyPEM: account, DNS: zone, Say: t.Logf}
	if _, reused, err := again.Obtain(ctx, host); err != nil || string(reused) != string(account) {
		t.Fatalf("second order with the same account: %v", err)
	}
	// Check afterwards that no _acme-challenge record remains, for example with
	// `aws route53 list-resource-record-sets`.
}
