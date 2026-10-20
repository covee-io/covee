package main

import (
	"context"
	"flag"
	"log"
	"os"

	"covee.io/internal/identity"
)

func main() {
	// Operator account administration, run inside the container with
	// `docker compose exec identity /covee-identity accounts ...`.
	if len(os.Args) > 1 && os.Args[1] == "accounts" {
		os.Exit(identity.RunAccounts(os.Args[2:], os.Stdout))
	}
	path := flag.String("config", os.Getenv("COVEE_IDENTITY_CONFIG"), "absolute path to the private identity JSON configuration")
	health := flag.Bool("health", false, "check the configured local TLS identity listener")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Print("unexpected identity command arguments")
		os.Exit(1)
	}
	config, err := identity.ReadConfig(*path)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	if *health {
		if err := identity.CheckHealth(context.Background(), config); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	server, err := identity.New(context.Background(), config)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	defer server.Close()
	log.Print("Covee identity broker starting TLS listener")
	if err := server.ListenAndServe(); err != nil {
		log.Print("identity listener stopped")
		os.Exit(1)
	}
}
