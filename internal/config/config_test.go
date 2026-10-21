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
