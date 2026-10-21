package transport_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/leakcheck"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func startTestServer(t *testing.T) (config.ServerConfig, config.ClientConfig, *transport.Client, context.CancelFunc) {
	t.Helper()
	envPath := filepath.Join("..", "..", ".env.example")

	srvCfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatalf("failed to load server config: %v", err)
	}
	srvCfg.ListenAddr = net.JoinHostPort(srvCfg.Host, "0")
	srvCfg.DBPath = filepath.Join(t.TempDir(), "sylvad.db")

	store, err := storage.OpenSQLite(srvCfg.DBPath, srvCfg.SQLiteBusyTimeout)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := transport.NewServer(srvCfg, store, logger)

	ln, err := net.Listen("tcp", srvCfg.ListenAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-errCh; err != nil {
			t.Errorf("server shutdown error: %v", err)
		}
	})

	clientCfg, err := config.LoadClientConfig(envPath)
	if err != nil {
		t.Fatalf("failed to load client config: %v", err)
	}
	clientCfg.ServerURL = fmt.Sprintf("%s://%s", clientCfg.Scheme, ln.Addr().String())
	clientCfg.CachePath = filepath.Join(t.TempDir(), "cache.db")

	httpClient := transport.NewClient(clientCfg)
	t.Cleanup(httpClient.Close)
	return srvCfg, clientCfg, httpClient, cancel
}

func TestClientServerPingFromEnv(t *testing.T) {
	srvCfg, _, client, cancel := startTestServer(t)
	defer cancel()

	status, err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("expected ping to succeed, got error: %v", err)
	}
	if status.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", status.Status)
	}
	if status.Service != srvCfg.ServiceName {
		t.Errorf("expected service %q, got %q", srvCfg.ServiceName, status.Service)
	}
}

func TestVaultSaltAndRecordRoundTrip(t *testing.T) {
	srvCfg, clientCfg, client, cancel := startTestServer(t)
	defer cancel()
	ctx := context.Background()

	if _, err := client.GetSalt(ctx); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 before init, got %v", err)
	}

	cryptoCfg, err := config.LoadCryptoConfig(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("load crypto config: %v", err)
	}
	salt, err := crypto.GenerateSalt(cryptoCfg.KDFSaltLen)
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if err := client.PutSalt(ctx, salt); err != nil {
		t.Fatalf("put salt: %v", err)
	}
	gotSalt, err := client.GetSalt(ctx)
	if err != nil {
		t.Fatalf("get salt: %v", err)
	}
	if string(gotSalt) != string(salt) {
		t.Fatalf("salt mismatch")
	}

	masterKey, err := crypto.DeriveKey([]byte("transport-test-pass"), salt, cryptoCfg)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.ZeroBytes(masterKey)

	item := &vault.SecretItem{
		ID:         "login-1",
		Type:       vault.SecretTypeLogin,
		Identifier: "company.com",
		Login: &vault.LoginPayload{
			Domain:   "company.com",
			Username: "osman",
			Password: "root-secret",
		},
	}
	sealed, err := vault.Seal(masterKey, item, clientCfg.RecordInitialVersion)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	stored, err := client.PutRecord(ctx, sealed)
	if err != nil {
		t.Fatalf("put record: %v", err)
	}

	fetched, err := client.GetRecordByBlindIndex(ctx, stored.BlindIndex)
	if err != nil {
		t.Fatalf("get by blind index: %v", err)
	}
	unsealed, err := vault.Unseal(masterKey, fetched)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if unsealed.Login.Password != "root-secret" {
		t.Fatalf("password mismatch %q", unsealed.Login.Password)
	}

	listed, err := client.ListRecords(ctx, vault.SecretTypeLogin)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected 1 record, got %d", len(listed))
	}

	if err := client.DeleteRecord(ctx, stored.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err = client.GetRecord(ctx, stored.ID); err == nil {
		t.Fatalf("expected get after delete to fail")
	}
	if srvCfg.RecordInitialVersion <= 0 {
		t.Fatalf("expected positive SYLVA_RECORD_INITIAL_VERSION from env")
	}
}
