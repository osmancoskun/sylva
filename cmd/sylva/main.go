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
	"github.com/osman/sylva/internal/vault"
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
		fmt.Fprintf(os.Stderr, "  login set <domain>   Store login credentials (use --inherit or --separate)\n")
		fmt.Fprintf(os.Stderr, "  login get <domain>   Resolve login credentials\n")
		fmt.Fprintf(os.Stderr, "  cp <domain>          Copy a login password to the clipboard\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

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

	args := flag.Args()
	cmd := "ping"
	if len(args) > 0 {
		cmd = args[0]
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
	case "login":
		if err := runLogin(cfg, args[1:]); err != nil {
			fatal(err)
		}
	case "cp", "copy":
		if err := runCopy(cfg, args[1:]); err != nil {
			fatal(err)
		}
	default:
		if strings.Contains(cmd, ".") {
			if err := runCopy(cfg, args); err != nil {
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
	client := transport.NewClient(cfg)

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

func runLogin(cfg config.ClientConfig, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("login requires a subcommand: set or get")
	}

	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	switch args[0] {
	case "set":
		return runLoginSet(ctx, v, args[1:])
	case "get":
		return runLoginGet(ctx, v, args[1:])
	default:
		return fmt.Errorf("unknown login subcommand %q", args[0])
	}
}

func runCopy(cfg config.ClientConfig, args []string) error {
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	cascade := fs.Bool("cascade", false, "walk up the domain tree when the exact domain is not stored")
	domain, flagArgs := splitDomainAndFlags(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if domain == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: sylva cp [flags] <domain>")
	}

	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	res, err := v.LoginGet(ctx, domain, *cascade)
	if err != nil {
		return err
	}
	if res.Item == nil || res.Item.Login == nil {
		return fmt.Errorf("resolved login for %s has no password", domain)
	}
	return copyToClipboard(cfg, string(vault.SecretTypeLogin), domain, res.Item.Login.Password)
}

func runLoginSet(ctx context.Context, v *sylva.Vault, args []string) error {
	fs := flag.NewFlagSet("login set", flag.ContinueOnError)
	username := fs.String("username", "", "account username")
	password := fs.String("password", "", "account password (required unless --inherit)")
	inherit := fs.Bool("inherit", false, "inherit credentials from the nearest parent domain")
	separate := fs.Bool("separate", false, "store a separate password even if a parent domain exists")
	domain, flagArgs := splitDomainAndFlags(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if domain == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: sylva login set [flags] <domain>")
	}

	res, err := v.LoginSet(ctx, domain, *username, *password, *inherit, *separate)
	if err != nil {
		return err
	}
	if res.Inherited {
		fmt.Printf("Stored %s (inherits from %s)\n", res.RequestedDomain, res.ResolvedDomain)
		return nil
	}
	fmt.Printf("Stored %s\n", res.RequestedDomain)
	return nil
}

func runLoginGet(ctx context.Context, v *sylva.Vault, args []string) error {
	fs := flag.NewFlagSet("login get", flag.ContinueOnError)
	cascade := fs.Bool("cascade", false, "walk up the domain tree when the exact domain is not stored")
	reveal := fs.Bool("reveal", false, "print the password instead of hiding it")
	domain, flagArgs := splitDomainAndFlags(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if domain == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: sylva login get [flags] <domain>")
	}

	res, err := v.LoginGet(ctx, domain, *cascade)
	if err != nil {
		return err
	}

	fmt.Printf("Domain:    %s\n", res.RequestedDomain)
	fmt.Printf("Resolved:  %s\n", res.ResolvedDomain)
	fmt.Printf("Inherited: %t\n", res.Inherited)
	fmt.Printf("Username:  %s\n", res.Item.Login.Username)
	if *reveal {
		fmt.Printf("Password:  %s\n", res.Item.Login.Password)
	} else {
		fmt.Printf("Password:  (hidden; pass --reveal to print)\n")
	}
	return nil
}

func splitDomainAndFlags(args []string) (string, []string) {
	var domain string
	var flags []string
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
		if domain == "" {
			domain = arg
			continue
		}
		flags = append(flags, arg)
	}
	return domain, flags
}

func isBoolFlag(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	name, _, _ = strings.Cut(name, "=")
	switch name {
	case "inherit", "separate", "cascade", "reveal":
		return true
	default:
		return false
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
