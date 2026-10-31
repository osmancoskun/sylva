package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/config"
)

func TestGitBackendUsesIndependentTransportConfiguration(t *testing.T) {
	config.IsolateProcessEnv(t)
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("backend=git\ngit_remote=git@example.test:vault.git\ngit_branch=vault/main\ngit_timeout=45s\nmtls=true\nca_cert_path="+path+".missing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYLVA_LOCAL_CONFIG", path)
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backend != "git" || cfg.EnableMTLS || cfg.Timeout != 45*time.Second || cfg.GitBranch != "vault/main" {
		t.Fatalf("Git configuration incorrectly inherited HTTP transport settings: %+v", cfg)
	}
	t.Setenv("SYLVA_BACKEND", "self-hosted")
	if _, err := config.LoadClientConfig(""); err == nil {
		t.Fatal("self-hosted mTLS stopped checking missing certificates")
	}
}
