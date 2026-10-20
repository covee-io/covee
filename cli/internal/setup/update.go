package setup

import (
	"context"
	"fmt"

	"covee.io/cli/internal/payload"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/remote"
)

// Update installs this CLI's Covee files on a running network, rebuilds the
// services and restarts them. Devices reconnect on their own within a minute.
func Update(ctx context.Context, env *Env, name string) error {
	s, err := opened(ctx, env, name)
	if err != nil {
		return err
	}
	archive := env.Archive
	if archive == nil {
		archive = payload.Archive
	}
	if s.archive, s.digest, err = archive(); err != nil {
		return err
	}
	if s.n.Payload == s.digest {
		s.say("Network %s already runs the Covee files of this CLI (%s); checking its scheduled jobs.", s.n.Name, s.digest[:12])
		return s.ensureMaintenance(ctx, s.server(true))
	}
	ok, err := env.Ask.Confirm("update", fmt.Sprintf("Update %s from Covee files %s to %s? The services are rebuilt (several minutes) and then restarted; devices reconnect within a minute", s.n.Name, short(s.n.Payload), s.digest[:12]), true)
	if err != nil {
		return err
	}
	if !ok {
		return prompt.ErrAborted
	}
	srv := s.server(true)
	s.say("[1/4] Install the Covee files")
	if err := srv.installSource(ctx); err != nil {
		return err
	}
	s.say("[2/4] Build the Covee services")
	if err := srv.deploy(ctx, "build --with-identity"); err != nil {
		return fmt.Errorf("the build failed; the network keeps running the previous services: %w", srv.buildFailure(ctx, err))
	}
	s.say("[3/4] Restart the network with the new services")
	if err := srv.deploy(ctx, "validate --directory "+remote.Quote(s.n.Runtime)); err != nil {
		return err
	}
	if err := srv.deploy(ctx, "up --directory "+remote.Quote(s.n.Runtime)); err != nil {
		return err
	}
	if err := s.ensureMaintenance(ctx, srv); err != nil {
		return err
	}
	s.say("[4/4] Check the network")
	want := "https://" + s.n.Hostname + "/identity"
	issuer, err := srv.localIssuer(ctx, s.n.Hostname)
	if err != nil || issuer != want {
		return fmt.Errorf("the network did not answer correctly after the restart (%v); check it with `covee status %s`", err, s.n.Name)
	}
	s.n.Payload = s.digest
	if err := env.Records.Save(s.n); err != nil {
		return err
	}
	if err := s.syncConfig(ctx, srv); err != nil {
		return err
	}
	s.say("Network %s now runs Covee files %s.", s.n.Name, s.digest[:12])
	return nil
}

func short(digest string) string {
	if len(digest) >= 12 {
		return digest[:12]
	}
	if digest == "" {
		return "(unknown)"
	}
	return digest
}
