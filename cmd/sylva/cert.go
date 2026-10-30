package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/osman/sylva/internal/certificates"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/transport"
)

func runCert(envFile string, args []string) error {
	if len(args) == 1 && args[0] == "add-tailscale" {
		name, err := discoverTailscaleName(envFile)
		if err != nil {
			return err
		}
		changed, err := certificates.AddServerName(filepath.Dir(config.DefaultCACertPath), name)
		if err != nil {
			return err
		}
		if !changed {
			fmt.Printf("Server certificate already covers %s\n", name)
			return nil
		}
		fmt.Printf("Added %s to server.pem; restart sylvad (recreate the Docker container if used). Keep ca.key offline.\n", name)
		return nil
	}
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: sylva cert init [--add-tailscale] [--host DNS-or-IP] | sylva cert add-tailscale")
	}
	fs := flag.NewFlagSet("cert init", flag.ContinueOnError)
	addTailscale := fs.Bool("add-tailscale", false, "include the running local sylvad node's MagicDNS name")
	var hosts []string
	fs.Func("host", "additional server DNS name or IP (repeatable)", func(host string) error {
		hosts = append(hosts, host)
		return nil
	})
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: sylva cert init [--add-tailscale] [--host DNS-or-IP]")
	}
	if *addTailscale {
		name, err := discoverTailscaleName(envFile)
		if err != nil {
			return err
		}
		hosts = append(hosts, name)
	}
	dir := filepath.Dir(config.DefaultCACertPath)
	if err := certificates.Init(dir, hosts); err != nil {
		return err
	}
	fmt.Printf("Created CA, server and client certificates in %s\n", dir)
	fmt.Println("Keep ca.key offline. Next: sylva enable mtls, then restart sylvad.")
	return nil
}

func discoverTailscaleName(envFile string) (string, error) {
	cfg, err := config.LoadClientConfig(envFile)
	if err != nil {
		return "", err
	}
	// Embedded tsnet also serves loopback. Query only the local Sylva daemon;
	// never inspect the host tailscaled or start a second tsnet using its state.
	cfg.ServerURL = cfg.Scheme + "://" + net.JoinHostPort("127.0.0.1", cfg.Port)
	client, err := transport.NewClient(cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	status, err := client.Ping(ctx)
	if err != nil {
		return "", fmt.Errorf("read local Sylva Tailscale identity: %w; enable tailscale, start sylvad and wait for it to join", err)
	}
	name := strings.TrimSpace(status.TailscaleDNSName)
	if !status.Tailscale || name == "" {
		return "", fmt.Errorf("local sylvad has no joined Tailscale DNS identity; enable tailscale, start sylvad and wait for it to join (upgrade sylvad if needed)")
	}
	return name, nil
}
