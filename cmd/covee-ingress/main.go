package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"covee.io/internal/ingress"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	c, err := ingress.ConfigFromEnv()
	if err != nil {
		return err
	}
	g, err := ingress.New(c)
	if err != nil {
		return err
	}
	defer g.Close()
	controlCert, err := tls.LoadX509KeyPair(c.ControlCertFile, c.ControlKeyFile)
	if err != nil {
		return errors.New("control TLS certificate/key could not be loaded")
	}
	adminCert, err := tls.LoadX509KeyPair(c.AdminCertFile, c.AdminKeyFile)
	if err != nil {
		return errors.New("administration TLS certificate/key could not be loaded")
	}
	server := func(addr string, handler http.Handler, certificate tls.Certificate) *http.Server {
		return &http.Server{
			Addr: addr, Handler: handler,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{certificate}},
			TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			MaxHeaderBytes: 16 << 10,
			// No WriteTimeout: upgraded control/DERP streams are long-lived.
			ErrorLog: log.New(io.Discard, "", 0),
		}
	}
	control := server(c.ControlListen, g.ControlHandler(), controlCert)
	admin := server(c.AdminListen, g.AdminHandler(), adminCert)
	controlRaw, err := net.Listen("tcp", c.ControlListen)
	if err != nil {
		return errors.New("control ingress listener could not bind")
	}
	controlListener := ingress.LimitListener(controlRaw, 256)
	defer controlListener.Close()
	adminRaw, err := net.Listen("tcp", c.AdminListen)
	if err != nil {
		return errors.New("administration ingress listener could not bind")
	}
	adminListener := ingress.LimitListener(adminRaw, 32)
	defer adminListener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 3)
	// The in-network console uses the public certificate, which then also
	// names the console host.
	var mesh *http.Server
	if handler := g.MeshHandler(); handler != nil {
		mesh = server(c.MeshListen, handler, controlCert)
		meshRaw, err := net.Listen("tcp", c.MeshListen)
		if err != nil {
			return errors.New("in-network console listener could not bind")
		}
		meshListener := ingress.LimitListener(meshRaw, 32)
		defer meshListener.Close()
		go func() { done <- mesh.ServeTLS(meshListener, "", "") }()
	}
	go func() { done <- control.ServeTLS(controlListener, "", "") }()
	go func() { done <- admin.ServeTLS(adminListener, "", "") }()
	log.Print("Covee ingress starting control and private administration TLS listeners")
	select {
	case err := <-done:
		control.Close()
		admin.Close()
		if mesh != nil {
			mesh.Close()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("ingress listener stopped unexpectedly")
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		control.Shutdown(shutdown)
		admin.Shutdown(shutdown)
		if mesh != nil {
			mesh.Shutdown(shutdown)
		}
	}
	return nil
}
