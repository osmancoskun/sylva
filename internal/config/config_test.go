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
	config.IsolateProcessEnv(t)
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
		t.Fatalf("expected clipboard and agent settings from defaults")
	}
	if cliCfg.Crypto.PasswordDefaultLen != 24 {
		t.Fatalf("password default len = %d, want 24 from default.conf", cliCfg.Crypto.PasswordDefaultLen)
	}
	if cliCfg.ConfigPath != envPath {
		t.Fatalf("ConfigPath = %q, want %q", cliCfg.ConfigPath, envPath)
	}
}

func TestDefaultsWithoutEnv(t *testing.T) {
	os.Clearenv()
	t.Setenv("SYLVA_LOCAL_CONFIG", filepath.Join(t.TempDir(), "config"))
	cfg, err := config.LoadServerConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "127.0.0.1" || cfg.Port != "8443" {
		t.Fatalf("defaults host:port = %s:%s", cfg.Host, cfg.Port)
	}
}

func TestLocalConfigOverridesPasswordLen(t *testing.T) {
	config.IsolateProcessEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("password_default_len=32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYLVA_LOCAL_CONFIG", path)
	cfg, err := config.LoadCryptoConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PasswordDefaultLen != 32 {
		t.Fatalf("got %d", cfg.PasswordDefaultLen)
	}
}

func TestTailscaleDefaultsWhenEnabled(t *testing.T) {
	config.IsolateProcessEnv(t)
	envPath := filepath.Join("..", "..", ".env.example")
	t.Setenv("SYLVA_LOCAL_CONFIG", filepath.Join(t.TempDir(), "config"))
	t.Setenv("SYLVA_TAILSCALE_ENABLED", "true")
	t.Setenv("SYLVA_TAILSCALE_NODE", "")
	t.Setenv("SYLVA_TAILSCALE_STATE_DIR", "")
	cfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EnableTailscale {
		t.Fatal("expected Tailscale enabled")
	}
	if cfg.TailscaleNode != config.DefaultTailscaleNode {
		t.Fatalf("node = %q", cfg.TailscaleNode)
	}
	if cfg.TailscaleStateDir != config.DefaultTailscaleStateDir {
		t.Fatalf("state dir = %q", cfg.TailscaleStateDir)
	}
}

func TestTailscaleAutoFromState(t *testing.T) {
	config.IsolateProcessEnv(t)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "tsnet")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "tailscaled.state"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join("..", "..", ".env.example")
	t.Setenv("SYLVA_LOCAL_CONFIG", filepath.Join(dir, "config"))
	t.Setenv("SYLVA_TAILSCALE_STATE_DIR", stateDir)
	os.Unsetenv("SYLVA_TAILSCALE_ENABLED")
	cfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EnableTailscale {
		t.Fatal("expected Tailscale from existing tsnet state")
	}
}

func TestLocalConfigDisablesTailscaleDespiteState(t *testing.T) {
	config.IsolateProcessEnv(t)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "tsnet")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "tailscaled.state"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYLVA_LOCAL_CONFIG", filepath.Join(dir, "config"))
	t.Setenv("SYLVA_TAILSCALE_STATE_DIR", stateDir)
	os.Unsetenv("SYLVA_TAILSCALE_ENABLED")
	if err := config.SetLocalFeature("tailscale", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadServerConfig(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnableTailscale {
		t.Fatal("local config false should win over tsnet state")
	}
}

func TestMTLSRequiresCertificateFiles(t *testing.T) {
	config.IsolateProcessEnv(t)
	envPath := filepath.Join("..", "..", ".env.example")
	t.Setenv("SYLVA_LOCAL_CONFIG", filepath.Join(t.TempDir(), "config"))
	t.Setenv("SYLVA_MTLS_ENABLED", "true")
	t.Setenv("SYLVA_CA_CERT_PATH", filepath.Join(t.TempDir(), "missing-ca.pem"))
	t.Setenv("SYLVA_SERVER_CERT_PATH", filepath.Join(t.TempDir(), "missing-server.pem"))
	t.Setenv("SYLVA_SERVER_KEY_PATH", filepath.Join(t.TempDir(), "missing-server.key"))
	if _, err := config.LoadServerConfig(envPath); err == nil {
		t.Fatal("expected server config to require mTLS certificate files")
	}

	t.Setenv("SYLVA_CLIENT_CERT_PATH", filepath.Join(t.TempDir(), "missing-client.pem"))
	t.Setenv("SYLVA_CLIENT_KEY_PATH", filepath.Join(t.TempDir(), "missing-client.key"))
	if _, err := config.LoadClientConfig(envPath); err == nil {
		t.Fatal("expected client config to require mTLS certificate files")
	}
}

func TestSetLocalFeaturePersists(t *testing.T) {
	config.IsolateProcessEnv(t)
	dir := t.TempDir()
	t.Setenv("SYLVA_LOCAL_CONFIG", filepath.Join(dir, "config"))
	if err := config.SetLocalFeature("mtls", true); err != nil {
		t.Fatal(err)
	}
	if err := config.SetLocalFeature("tailscale", false); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join("..", "..", ".env.example")
	os.Unsetenv("SYLVA_MTLS_ENABLED")
	os.Unsetenv("SYLVA_TAILSCALE_ENABLED")
	if _, err := config.LoadServerConfig(envPath); err == nil {
		t.Fatal("mtls enabled without certs should fail")
	}
	if err := config.SetLocalFeature("mtls", false); err != nil {
		t.Fatal(err)
	}
	srv, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if srv.EnableMTLS {
		t.Fatal("expected mtls off")
	}
	if srv.EnableTailscale {
		t.Fatal("expected tailscale off")
	}
}
