// Command sylvad runs the Sylva self-hosted server daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/transport"
)

func main() {
	envFile := flag.String("env", ".env", "path to environment configuration file")
	addrOverride := flag.String("addr", "", "override listen address (host:port)")
	mtlsOverride := flag.Bool("mtls", false, "force enable mutual TLS (mTLS) authentication")
	tailscaleOverride := flag.Bool("tailscale", false, "force enable Tailscale integration")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	if *addrOverride != "" {
		cfg.ListenAddr = *addrOverride
	}
	if *mtlsOverride {
		cfg.EnableMTLS = true
	}
	if *tailscaleOverride {
		cfg.EnableTailscale = true
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := transport.NewServer(cfg, logger)
	if err := srv.Start(ctx); err != nil {
		logger.Error("server exited with error", slog.Any("error", err))
		os.Exit(1)
	}
}
