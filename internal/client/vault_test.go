package client_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/leakcheck"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func TestLoginSetGetInheritanceThroughServer(t *testing.T) {
	envPath := filepath.Join("..", "..", ".env.example")
	srvCfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	clientCfg, err := config.LoadClientConfig(envPath)
	if err != nil {
		t.Fatalf("load client config: %v", err)
	}

	srvCfg.ListenAddr = net.JoinHostPort(srvCfg.Host, "0")
	srvCfg.DBPath = filepath.Join(t.TempDir(), "sylvad.db")
	store, err := storage.OpenSQLite(srvCfg.DBPath, srvCfg.SQLiteBusyTimeout)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := transport.NewServer(srvCfg, store, logger)
	ln, err := net.Listen("tcp", srvCfg.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, ln) }()
	defer func() {
		cancel()
		<-errCh
	}()

	clientCfg.ServerURL = fmt.Sprintf("%s://%s", clientCfg.Scheme, ln.Addr().String())
	clientCfg.CachePath = filepath.Join(t.TempDir(), "cache.db")
	clientCfg.MasterPassphrase = "client-integration-passphrase"

	v, err := sylva.Open(clientCfg)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	defer v.Close()

	if err := v.Unlock(ctx, clientCfg.MasterPassphrase); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if _, err := v.LoginSet(ctx, "company.com", "osman", "company-secret", false, false); err != nil {
		t.Fatalf("set company.com: %v", err)
	}

	_, err = v.LoginSet(ctx, "mail.company.com", "", "", false, false)
	if !errors.Is(err, sylva.ErrParentExists) {
		t.Fatalf("expected ErrParentExists, got %v", err)
	}

	if _, err := v.LoginSet(ctx, "company.com", "osman", "other-secret", false, false); !errors.Is(err, sylva.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}

	if _, err := v.LoginSet(ctx, "mail.company.com", "", "", true, false); err != nil {
		t.Fatalf("set mail.company.com inherit: %v", err)
	}

	if _, err := v.LoginSet(ctx, "mail.company.com", "", "", true, false); !errors.Is(err, sylva.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists on duplicate child, got %v", err)
	}

	res, err := v.LoginGet(ctx, "mail.company.com", false)
	if err != nil {
		t.Fatalf("get mail.company.com: %v", err)
	}
	if !res.Inherited || res.Item.Login.Password != "company-secret" {
		t.Fatalf("expected inherited password, got %+v", res)
	}

	cascaded, err := v.LoginGet(ctx, "dev.mail.company.com", true)
	if err != nil {
		t.Fatalf("cascade get: %v", err)
	}
	if cascaded.Item.Login.Password != "company-secret" {
		t.Fatalf("expected cascaded password, got %q", cascaded.Item.Login.Password)
	}

	kind, secret, err := v.GetValue(ctx, "mail.company.com", vault.SecretTypeLogin, false, "")
	if err != nil {
		t.Fatalf("get login value: %v", err)
	}
	if kind != vault.SecretTypeLogin || secret != "company-secret" {
		t.Fatalf("get login value: kind=%q secret=%q", kind, secret)
	}

	if err := v.PutSecret(ctx, &vault.SecretItem{
		Type:       vault.SecretTypeToken,
		Identifier: "github-token",
		Token:      &vault.TokenPayload{Name: "github-token", Token: "tok-secret"},
	}); err != nil {
		t.Fatalf("put token: %v", err)
	}
	kind, secret, err = v.GetValue(ctx, "github-token", "", false, "")
	if err != nil {
		t.Fatalf("probe token: %v", err)
	}
	if kind != vault.SecretTypeToken || secret != "tok-secret" {
		t.Fatalf("probe token: kind=%q secret=%q", kind, secret)
	}

	if err := v.PutSecret(ctx, &vault.SecretItem{
		Type:       vault.SecretTypeEnv,
		Identifier: "SYLVA_EXAMPLE",
		Env: &vault.EnvPayload{
			Project:   "SYLVA_EXAMPLE",
			Variables: map[string]string{"SYLVA_EXAMPLE": "env-secret"},
		},
	}); err != nil {
		t.Fatalf("put env: %v", err)
	}
	kind, secret, err = v.GetValue(ctx, "SYLVA_EXAMPLE", vault.SecretTypeEnv, false, "")
	if err != nil {
		t.Fatalf("get env: %v", err)
	}
	if kind != vault.SecretTypeEnv || secret != "env-secret" {
		t.Fatalf("get env: kind=%q secret=%q", kind, secret)
	}

	if err := v.PutSecret(ctx, &vault.SecretItem{
		Type:       vault.SecretTypeSSH,
		Identifier: "10.0.0.1",
		SSH:        &vault.SSHPayload{Name: "10.0.0.1", Host: "10.0.0.1", Passphrase: "ssh-secret"},
	}); err != nil {
		t.Fatalf("put ssh: %v", err)
	}
	kind, secret, err = v.GetValue(ctx, "10.0.0.1", vault.SecretTypeSSH, false, "")
	if err != nil {
		t.Fatalf("get ssh: %v", err)
	}
	if kind != vault.SecretTypeSSH || secret != "ssh-secret" {
		t.Fatalf("get ssh: kind=%q secret=%q", kind, secret)
	}

	kind, secret, err = v.GetValue(ctx, "10.0.0.1", "", false, "")
	if err != nil {
		t.Fatalf("probe ssh ip: %v", err)
	}
	if kind != vault.SecretTypeSSH || secret != "ssh-secret" {
		t.Fatalf("probe ssh ip: kind=%q secret=%q", kind, secret)
	}

	kind, secret, err = v.GetValue(ctx, "missing-name", "", false, "")
	if err == nil || !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected missing probe, got kind=%q secret=%q err=%v", kind, secret, err)
	}
}
