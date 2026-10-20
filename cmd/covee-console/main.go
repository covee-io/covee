package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"covee.io/internal/management"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	config, err := management.ConfigFromEnv()
	if err != nil {
		return err
	}
	app, err := management.New(config)
	if err != nil {
		return err
	}
	defer app.Close()
	server := managementHTTPServer(config, app)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		if config.TLSCertFile != "" {
			done <- server.ListenAndServeTLS(config.TLSCertFile, config.TLSKeyFile)
			return
		}
		done <- server.ListenAndServe()
	}()
	log.Printf("Covee management listening at %s", config.Listen)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func managementHTTPServer(config management.Config, handler http.Handler) *http.Server {
	return &http.Server{Addr: config.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}
