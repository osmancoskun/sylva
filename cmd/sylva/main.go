// Command sylva is the CLI client for interacting with the Sylva secret manager.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/transport"
)

func main() {
	envFile := flag.String("env", ".env", "path to environment configuration file")
	serverOverride := flag.String("server", "", "override base URL of the sylvad server")
	timeoutOverride := flag.Duration("timeout", 0, "override request timeout duration")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sylva [flags] <command>\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  ping      Check connectivity and status of the sylvad server\n")
		fmt.Fprintf(os.Stderr, "  version   Print client version information\n\n")
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
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("sylva client v%s\n", cfg.Version)
	default:
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
