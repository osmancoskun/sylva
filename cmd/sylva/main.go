// Command sylva is the CLI client for interacting with the Sylva secret manager.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/transport"
)

func main() {
	envFile := flag.String("env", ".env", "path to environment configuration file")
	serverOverride := flag.String("server", "", "override base URL of the sylvad server")
	timeoutOverride := flag.Duration("timeout", 0, "override request timeout duration")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sylva [flags] <command> [subcommand]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  ping                 Check connectivity and status of the sylvad server\n")
		fmt.Fprintf(os.Stderr, "  version              Print client version information\n")
		fmt.Fprintf(os.Stderr, "  init                 Initialize the vault salt on the server\n")
		fmt.Fprintf(os.Stderr, "  unlock               Unlock the session agent / OS keyring\n")
		fmt.Fprintf(os.Stderr, "  lock                 Wipe the session agent / OS keyring\n")
		fmt.Fprintf(os.Stderr, "  agent                Run the local session agent (foreground)\n")
		fmt.Fprintf(os.Stderr, "  set [<id> [<password>] [<type>]]\n")
		fmt.Fprintf(os.Stderr, "                       Store a secret (interactive if args are omitted)\n")
		fmt.Fprintf(os.Stderr, "  get <id> [<type>]    Copy a secret to the clipboard\n")
		fmt.Fprintf(os.Stderr, "  list [<type>]        List stored secret identifiers\n")
		fmt.Fprintf(os.Stderr, "  update <id> [<password>] [<type>]\n")
		fmt.Fprintf(os.Stderr, "                       Replace an existing secret\n")
		fmt.Fprintf(os.Stderr, "  delete <id> [<type>] Remove an existing secret\n")
		fmt.Fprintf(os.Stderr, "  enable mtls|tailscale\n")
		fmt.Fprintf(os.Stderr, "                       Persist a transport feature in .sylva/config\n")
		fmt.Fprintf(os.Stderr, "  disable mtls|tailscale\n")
		fmt.Fprintf(os.Stderr, "                       Turn a persisted transport feature off\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	cmd := "ping"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd == "enable" || cmd == "disable" {
		if err := runFeatureToggle(cmd == "enable", args[1:]); err != nil {
			fatal(err)
		}
		return
	}

	cfg, err := config.LoadClientConfig(*envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	if *serverOverride != "" {
		cfg.ServerURL = *serverOverride
	}
	if *timeoutOverride > 0 {
		cfg.Timeout = *timeoutOverride
	}

	switch cmd {
	case "ping", "status":
		if err := runPing(cfg); err != nil {
			fatal(err)
		}
	case "version":
		fmt.Printf("sylva client v%s\n", cfg.Version)
	case "init":
		if err := runInit(cfg); err != nil {
			fatal(err)
		}
	case "unlock":
		if err := runUnlock(cfg); err != nil {
			fatal(err)
		}
	case "lock":
		if err := runLock(cfg); err != nil {
			fatal(err)
		}
	case "agent":
		if err := runAgent(cfg); err != nil {
			fatal(err)
		}
	case "set":
		if err := runSet(cfg, args[1:]); err != nil {
			fatal(err)
		}
	case "get", "cp", "copy":
		if err := runGet(cfg, args[1:]); err != nil {
			fatal(err)
		}
	case "list", "ls":
		if err := runList(cfg, args[1:]); err != nil {
			fatal(err)
		}
	case "update":
		if err := runUpdate(cfg, args[1:]); err != nil {
			fatal(err)
		}
	case "delete", "rm", "remove":
		if err := runDelete(cfg, args[1:]); err != nil {
			fatal(err)
		}
	default:
		if strings.Contains(cmd, ".") {
			if err := runGet(cfg, args); err != nil {
				fatal(err)
			}
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", cmd)
		flag.Usage()
		os.Exit(1)
	}
}

func runPing(cfg config.ClientConfig) error {
	client, err := transport.NewClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	start := time.Now()
	status, err := client.Ping(ctx)
	if err != nil {
		return err
	}
	rtt := time.Since(start).Round(time.Microsecond)

	fmt.Printf("Connected to %s (%s)\n", status.Service, cfg.ServerURL)
	fmt.Printf("  Status:    %s\n", status.Status)
	fmt.Printf("  Version:   %s\n", status.Version)
	fmt.Printf("  mTLS:      %t\n", status.MTLS)
	fmt.Printf("  Tailscale: %t\n", status.Tailscale)
	fmt.Printf("  Latency:   %s\n", rtt)
	return nil
}

func runInit(cfg config.ClientConfig) error {
	v, err := sylva.Open(cfg)
	if err != nil {
		return err
	}
	defer v.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	salt, err := v.Init(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Vault initialized (%d-byte Argon2id salt is stored on the server)\n", len(salt))
	return nil
}

func splitFlagsAndArgs(args []string) (positionals, flags []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && !isBoolFlag(arg) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return positionals, flags
}

func isBoolFlag(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	name, _, _ = strings.Cut(name, "=")
	switch name {
	case "inherit", "cascade", "yes":
		return true
	default:
		return false
	}
}

func runFeatureToggle(enable bool, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: sylva enable|disable mtls|tailscale")
	}
	feature := strings.ToLower(args[0])
	if enable && feature == "mtls" {
		missing := []string{}
		for _, p := range []string{
			config.DefaultCACertPath,
			config.DefaultServerCertPath,
			config.DefaultServerKeyPath,
			config.DefaultClientCertPath,
			config.DefaultClientKeyPath,
		} {
			if _, err := os.Stat(p); err != nil {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("mTLS certs missing (%s); create them first, see docs/mtls.md", strings.Join(missing, ", "))
		}
	}
	if enable && feature == "tailscale" {
		if err := os.MkdirAll(config.DefaultTailscaleStateDir, 0o700); err != nil {
			return err
		}
	}
	if err := config.SetLocalFeature(feature, enable); err != nil {
		return err
	}
	state := "disabled"
	if enable {
		state = "enabled"
	}
	fmt.Printf("%s %s in %s; restart sylvad\n", feature, state, config.LocalConfigPath())
	return nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
