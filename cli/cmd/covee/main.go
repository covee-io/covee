// Command covee builds and manages Covee networks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"covee.io/cli/internal/dns"
	"covee.io/cli/internal/entra"
	"covee.io/cli/internal/guided"
	"covee.io/cli/internal/prompt"
	"covee.io/cli/internal/record"
	"covee.io/cli/internal/secrets"
	"covee.io/cli/internal/setup"
)

var version = "0.1.0-dev"

const usage = `covee builds and manages self-contained Covee networks.

Usage:
  covee setup [network]          create a network, or continue an interrupted setup
  covee list                     show the networks this computer manages
  covee status <network>         show services and upcoming expiry dates
  covee console <network> [--in-network]
                                 open the private admin console; --in-network also serves
                                 it to devices in the network at https://console.<mesh domain>
  covee grant <network> --provider google|apple --subject ID [--role admin|reader|none] [--no-devices]
                                 approve a Google or Apple account
  covee auth add <network> microsoft|google|apple|accounts
                                 turn on a sign-in method (devices stay connected)
  covee auth remove <network> microsoft|google|apple|accounts
                                 turn off a sign-in method
  covee users list <network>     everyone who can sign in
  covee users invite <network> --email E --name N [--role admin|reader|none] [--no-devices] [--expires 72h]
  covee users update <network> --email E [--role admin|reader|none] [--devices|--no-devices]
  covee users reset <network> --email E [--expires 72h]
  covee users remove <network> --email E
                                 manage Covee accounts (passkey, or password with a code)
  covee device token <network> [--tag server] [--expires 24h] [--reusable] [--ephemeral]
                                 create a key that adds a Linux machine without signing in
  covee gateway <network> [--off]
                                 let devices reach places only the server can, such as private
                                 cloud networks; choose what on the console's Gateway page
  covee update <network>         install this CLI's Covee files on a network and restart it
  covee cert renew <network>     renew the public and internal certificates (restarts once)
  covee dns auto <network> [--off]
                                 keep the hostname pointing at a home connection's changing
                                 public address (the server checks every 5 minutes)
  covee backup <network>         take an encrypted backup, download it and verify it
  covee rename <network> --hostname H [--mesh-domain D]
                                 move a network to a new public hostname (such as one on your own
                                 domain) and device name suffix; devices keep their sign-in
  covee version

Settings and private keys are kept in ~/.config/covee (or $COVEE_HOME).
For automated runs, COVEE_ANSWERS names a JSON file of answers by question ID
(the same as setup --answers); no browser pages are opened then.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		if errors.Is(err, prompt.ErrAborted) {
			fmt.Fprintln(os.Stderr, "Stopped. Nothing further was changed.")
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, usage)
		return nil
	}
	command, rest := args[0], args[1:]
	if command == "version" {
		fmt.Fprintln(out, "covee", version)
		return nil
	}
	home, err := record.Home()
	if err != nil {
		return err
	}
	records, err := record.Open(home)
	if err != nil {
		return err
	}
	env := &setup.Env{
		Ask:     prompt.NewTerminal(),
		Out:     out,
		Home:    home,
		Records: records,
		AWS: func(ctx context.Context, region string) (aws.Config, error) {
			return config.LoadDefaultConfig(ctx, config.WithRegion(region))
		},
		Caller: func(ctx context.Context, cfg aws.Config) (string, error) {
			id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s in account %s", aws.ToString(id.Arn), aws.ToString(id.Account)), nil
		},
		NewRoute53: func(cfg aws.Config) dns.Route53API { return route53.NewFromConfig(cfg) },
		NewSSM:     func(cfg aws.Config) secrets.SSMAPI { return ssm.NewFromConfig(cfg) },
		NewIAM:     func(cfg aws.Config) dns.IAMAPI { return iam.NewFromConfig(cfg) },
		EntraToken: entra.AzureCLI,
		Open:       guided.Open,
	}
	if err := os.MkdirAll(filepath.Join(home, "secrets"), 0o700); err != nil {
		return err
	}
	if path := os.Getenv("COVEE_ANSWERS"); path != "" {
		if err := useAnswers(env, path, out); err != nil {
			return err
		}
	}
	switch command {
	case "setup":
		fs := flag.NewFlagSet("setup", flag.ContinueOnError)
		staging := fs.Bool("staging", false, "use Let's Encrypt's test service (certificate not trusted; for testing)")
		answers := fs.String("answers", "", "JSON file of answers by question ID (for automated runs)")
		if err := fs.Parse(reorder(rest)); err != nil {
			return err
		}
		if *answers != "" {
			if err := useAnswers(env, *answers, out); err != nil {
				return err
			}
		}
		return setup.Run(ctx, env, setup.Options{Network: fs.Arg(0), Staging: *staging})
	case "list":
		return setup.List(env)
	case "status":
		if len(rest) != 1 {
			return errors.New("usage: covee status <network>")
		}
		return setup.Status(ctx, env, rest[0])
	case "console":
		fs := flag.NewFlagSet("console", flag.ContinueOnError)
		inNetwork := fs.Bool("in-network", false, "also serve the console to devices in the network")
		if err := fs.Parse(reorder(rest)); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: covee console <network> [--in-network]")
		}
		if *inNetwork {
			return setup.ConsoleInNetwork(ctx, env, fs.Arg(0))
		}
		return setup.Console(ctx, env, fs.Arg(0))
	case "auth":
		if len(rest) != 3 || (rest[0] != "add" && rest[0] != "remove") {
			return errors.New("usage: covee auth add|remove <network> microsoft|google|apple|accounts")
		}
		if rest[0] == "add" {
			return setup.AuthAdd(ctx, env, rest[1], rest[2])
		}
		return setup.AuthRemove(ctx, env, rest[1], rest[2])
	case "device":
		if len(rest) < 2 || rest[0] != "token" {
			return errors.New("usage: covee device token <network> [--tag server] [--expires 24h] [--reusable] [--ephemeral]")
		}
		fs := flag.NewFlagSet("device token", flag.ContinueOnError)
		var tags multi
		fs.Var(&tags, "tag", "tag for the device, repeatable (default server)")
		expires := fs.String("expires", "24h", "how long the key works: 30m, 24h, 7d (at most 90d)")
		reusable := fs.Bool("reusable", false, "allow several devices to use the key")
		ephemeral := fs.Bool("ephemeral", false, "remove the devices when they go offline")
		if err := fs.Parse(reorder(rest[1:])); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: covee device token <network> [--tag server] [--expires 24h] [--reusable] [--ephemeral]")
		}
		return setup.DeviceToken(ctx, env, fs.Arg(0), tags, *expires, *reusable, *ephemeral)
	case "backup":
		if len(rest) != 1 {
			return errors.New("usage: covee backup <network>")
		}
		return setup.Backup(ctx, env, rest[0])
	case "cert":
		if len(rest) != 2 || rest[0] != "renew" {
			return errors.New("usage: covee cert renew <network>")
		}
		return setup.CertRenew(ctx, env, rest[1])
	case "users":
		return users(ctx, env, rest)
	case "dns":
		const dnsUsage = "usage: covee dns auto <network> [--off]"
		if len(rest) < 2 || rest[0] != "auto" {
			return errors.New(dnsUsage)
		}
		fs := flag.NewFlagSet("dns auto", flag.ContinueOnError)
		off := fs.Bool("off", false, "stop updating the record and delete the updater's AWS user")
		if err := fs.Parse(reorder(rest[1:])); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New(dnsUsage)
		}
		if *off {
			return setup.DNSAutoOff(ctx, env, fs.Arg(0))
		}
		return setup.DNSAuto(ctx, env, fs.Arg(0))
	case "gateway":
		fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
		off := fs.Bool("off", false, "turn the gateway off")
		if err := fs.Parse(reorder(rest)); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: covee gateway <network> [--off]")
		}
		return setup.Gateway(ctx, env, fs.Arg(0), *off)
	case "update":
		if len(rest) != 1 {
			return errors.New("usage: covee update <network>")
		}
		return setup.Update(ctx, env, rest[0])
	case "rename":
		const renameUsage = "usage: covee rename <network> --hostname H [--mesh-domain D]"
		fs := flag.NewFlagSet("rename", flag.ContinueOnError)
		hostname := fs.String("hostname", "", "the new public hostname, such as control.example.org")
		meshDomain := fs.String("mesh-domain", "", "the new name suffix of devices in the network (default mesh.<your domain>)")
		if err := fs.Parse(reorder(rest)); err != nil {
			return err
		}
		if fs.NArg() != 1 || *hostname == "" {
			return errors.New(renameUsage)
		}
		return setup.Rename(ctx, env, fs.Arg(0), *hostname, *meshDomain)
	case "grant":
		fs := flag.NewFlagSet("grant", flag.ContinueOnError)
		provider := fs.String("provider", "", "google or apple")
		subject := fs.String("subject", "", "the ID shown on the \"not approved\" page")
		role := fs.String("role", "admin", "console role: admin, reader or none")
		noDevices := fs.Bool("no-devices", false, "do not allow this account to add devices")
		if err := fs.Parse(reorder(rest)); err != nil {
			return err
		}
		if fs.NArg() != 1 || *provider == "" || *subject == "" {
			return errors.New("usage: covee grant <network> --provider google|apple --subject ID [--role admin|reader|none] [--no-devices]")
		}
		return setup.Grant(ctx, env, fs.Arg(0), *provider, *subject, *role, !*noDevices)
	}
	return fmt.Errorf("unknown command %q; run `covee help`", command)
}

// reorder moves flags before positional arguments so `covee grant home
// --provider google` works as well as the flag-first form.
func reorder(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			if !containsEq(a) && i+1 < len(args) && !isBool(a) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func containsEq(a string) bool {
	for _, c := range a {
		if c == '=' {
			return true
		}
	}
	return false
}

func isBool(a string) bool {
	switch a {
	case "--staging", "-staging", "--no-devices", "-no-devices", "--reusable", "-reusable", "--ephemeral", "-ephemeral", "--devices", "-devices", "--off", "-off", "--in-network", "-in-network":
		return true
	}
	return false
}

// multi collects a repeatable string flag.
type multi []string

func (m *multi) String() string     { return fmt.Sprint([]string(*m)) }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// useAnswers switches to scripted answers for automated runs.
func useAnswers(env *setup.Env, path string, out io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	scripted := &prompt.Scripted{Out: out}
	if err := json.Unmarshal(data, &scripted.Answers); err != nil {
		return fmt.Errorf("answers file: %w", err)
	}
	env.Ask = scripted
	env.Open = func(string) {}
	return nil
}

func users(ctx context.Context, env *setup.Env, args []string) error {
	const usage = "usage: covee users list|invite|update|reset|remove <network> [--email E] ..."
	if len(args) < 2 {
		return errors.New(usage)
	}
	action := args[0]
	fs := flag.NewFlagSet("users "+action, flag.ContinueOnError)
	email := fs.String("email", "", "the account's email address")
	name := fs.String("name", "", "invite: the person's name")
	role := fs.String("role", "", "admin, reader or none")
	noDevices := fs.Bool("no-devices", false, "the account may not add devices")
	devices := fs.Bool("devices", false, "update: the account may add devices")
	expires := fs.String("expires", "72h", "invite/reset: how long the link works (1h to 336h)")
	if err := fs.Parse(reorder(args[1:])); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New(usage)
	}
	network := fs.Arg(0)
	needEmail := func() error {
		if *email == "" {
			return errors.New("--email is required")
		}
		return nil
	}
	switch action {
	case "list":
		return setup.UsersList(ctx, env, network)
	case "invite":
		if err := needEmail(); err != nil {
			return err
		}
		if *name == "" {
			return errors.New("--name is required")
		}
		r := *role
		if r == "" {
			r = "none"
		}
		return setup.UsersInvite(ctx, env, network, *email, *name, r, !*noDevices, *expires)
	case "update":
		if err := needEmail(); err != nil {
			return err
		}
		var enroll *bool
		if *devices && *noDevices {
			return errors.New("choose --devices or --no-devices, not both")
		}
		if *devices || *noDevices {
			v := *devices
			enroll = &v
		}
		if *role == "" && enroll == nil {
			return errors.New("nothing to change: give --role, --devices or --no-devices")
		}
		return setup.UsersUpdate(ctx, env, network, *email, *role, enroll)
	case "reset":
		if err := needEmail(); err != nil {
			return err
		}
		return setup.UsersReset(ctx, env, network, *email, *expires)
	case "remove":
		if err := needEmail(); err != nil {
			return err
		}
		return setup.UsersRemove(ctx, env, network, *email)
	}
	return errors.New(usage)
}
