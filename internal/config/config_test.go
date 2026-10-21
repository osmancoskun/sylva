package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/leakcheck"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func TestLoadConfigFromEnvFile(t *testing.T) {
	envPath := filepath.Join("..", "..", ".env.example")

	srvCfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatalf("unexpected error loading server config: %v", err)
	}
	if srvCfg.Host == "" || srvCfg.Port == "" {
		t.Fatalf("expected host and port to be populated from env file")
	}

	cliCfg, err := config.LoadClientConfig(envPath)
	if err != nil {
		t.Fatalf("unexpected error loading client config: %v", err)
	}
	if cliCfg.ServerURL == "" {
		t.Fatalf("expected ServerURL to be constructed from env file")
	}
	if cliCfg.ClipboardClearAfter <= 0 || cliCfg.AgentSocketPath == "" {
		t.Fatalf("expected clipboard and agent settings from env file")
	}
	if cliCfg.ConfigPath != envPath {
		t.Fatalf("ConfigPath = %q, want %q", cliCfg.ConfigPath, envPath)
	}
}

func TestMissingRequiredEnvFails(t *testing.T) {
	os.Clearenv()
	_, err := config.LoadServerConfig("")
	if err == nil {
		t.Fatalf("expected error when required env variables are missing, got nil")
	}
}

func TestMTLSRequiresCertificatePaths(t *testing.T) {
	envPath := filepath.Join("..", "..", ".env.example")
	t.Setenv("SYLVA_MTLS_ENABLED", "true")
	t.Setenv("SYLVA_CA_CERT_PATH", "")
	t.Setenv("SYLVA_SERVER_CERT_PATH", "")
	t.Setenv("SYLVA_SERVER_KEY_PATH", "")
	if _, err := config.LoadServerConfig(envPath); err == nil {
		t.Fatal("expected server config to require mTLS certificate paths")
	}

	t.Setenv("SYLVA_CLIENT_CERT_PATH", "")
	t.Setenv("SYLVA_CLIENT_KEY_PATH", "")
	if _, err := config.LoadClientConfig(envPath); err == nil {
		t.Fatal("expected client config to require https and mTLS certificate paths")
	}
}
