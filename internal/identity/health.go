package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// CheckHealth verifies the selected local listener with its configured leaf
// certificate pinned as a root. The HTTP Host remains the public issuer host;
// TLS uses the leaf's internal service SAN, never InsecureSkipVerify.
func CheckHealth(ctx context.Context, c Config) error {
	if err := c.validate(); err != nil {
		return err
	}
	raw, err := os.ReadFile(c.TLSCertFile)
	if err != nil {
		return errors.New("identity health certificate unavailable")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("identity health certificate invalid")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("identity health certificate invalid")
	}
	serverName := ""
	if len(leaf.DNSNames) > 0 {
		serverName = leaf.DNSNames[0]
	} else if len(leaf.IPAddresses) > 0 {
		serverName = leaf.IPAddresses[0].String()
	}
	if serverName == "" {
		return errors.New("identity health certificate needs a SAN")
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(c.Listen)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	target := net.JoinHostPort(host, port)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	issuer, _ := url.Parse(c.Issuer)
	request, err := http.NewRequestWithContext(ctx, "GET", c.Issuer+"/healthz", nil)
	if err != nil {
		return err
	}
	request.Host = issuer.Host
	response, err := client.Do(request)
	if err != nil {
		return errors.New("identity health TLS request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("identity health endpoint unavailable")
	}
	return nil
}
