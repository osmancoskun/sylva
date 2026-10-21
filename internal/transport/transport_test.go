package transport_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/transport"
)

func TestClientServerPingFromEnv(t *testing.T) {
	envPath := filepath.Join("..", "..", ".env.example")

	srvCfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatalf("failed to load server config from %s: %v", envPath, err)
	}
	// Bind to an ephemeral port on the configured host for isolated testing.
	srvCfg.ListenAddr = net.JoinHostPort(srvCfg.Host, "0")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := transport.NewServer(srvCfg, logger)

	ln, err := net.Listen("tcp", srvCfg.ListenAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, ln)
	}()

	clientCfg, err := config.LoadClientConfig(envPath)
	if err != nil {
		t.Fatalf("failed to load client config from %s: %v", envPath, err)
	}
	clientCfg.ServerURL = fmt.Sprintf("%s://%s", clientCfg.Scheme, ln.Addr().String())

	client := transport.NewClient(clientCfg)

	status, err := client.Ping(ctx)
	if err != nil {
		t.Fatalf("expected ping to succeed, got error: %v", err)
	}

	if status.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", status.Status)
	}
	if status.Service != srvCfg.ServiceName {
		t.Errorf("expected service %q, got %q", srvCfg.ServiceName, status.Service)
	}
	if status.Version != srvCfg.Version {
		t.Errorf("expected version %q, got %q", srvCfg.Version, status.Version)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server returned unexpected error on shutdown: %v", err)
	}
}
