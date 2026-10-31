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
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
)

func main() {
	envFile := flag.String("env", ".env", "path to environment configuration file")
	addrOverride := flag.String("addr", "", "override listen address (host:port)")
	printVersion := flag.Bool("version", false, "print server version information")
	flag.Parse()
	if *printVersion {
		version := config.BuildVersion
		if version == "" {
			version = "0.1.0-dev"
		}
		fmt.Printf("sylvad v%s\n", version)
		return
	}

	cfg, err := config.LoadServerConfig(*envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	if *addrOverride != "" {
		cfg.ListenAddr = *addrOverride
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	store, err := storage.OpenSQLite(cfg.DBPath, cfg.SQLiteBusyTimeout)
	if err != nil {
		logger.Error("failed to open sqlite store", slog.Any("error", err))
		os.Exit(1)
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := transport.NewServer(cfg, store, logger)
	if err := srv.Start(ctx); err != nil {
		logger.Error("server exited with error", slog.Any("error", err))
		os.Exit(1)
	}
}
