package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"covee.io/internal/management"
)

func TestManagementServerServesVerifiedTLSAndRejectsOldProtocol(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(fixture.Close)
	certificate := fixture.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	config := management.Config{Listen: "127.0.0.1:0", TLSCertFile: certPath, TLSKeyFile: keyPath}
	server := managementHTTPServer(config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("management request was not encrypted")
		}
		io.WriteString(w, "secure")
	}))
	server.ErrorLog = log.New(io.Discard, "", 0)
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, config.TLSCertFile, config.TLSKeyFile) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	client := fixture.Client()
	client.Timeout = 3 * time.Second
	response, err := client.Get("https://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "secure" {
		t.Fatal("TLS management response failed")
	}
	old := client.Transport.(*http.Transport).Clone()
	old.TLSClientConfig = old.TLSClientConfig.Clone()
	old.TLSClientConfig.MinVersion = tls.VersionTLS10
	old.TLSClientConfig.MaxVersion = tls.VersionTLS11
	defer old.CloseIdleConnections()
	legacy := &http.Client{Transport: old, Timeout: 3 * time.Second}
	if res, err := legacy.Get("https://" + listener.Addr().String() + "/healthz"); err == nil {
		res.Body.Close()
		t.Fatal("management accepted TLS older than 1.2")
	}
}
