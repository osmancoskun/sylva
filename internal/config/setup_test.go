package config_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/osman/sylva/internal/config"
)

func TestSetupPreviewAndAtomicSaveRespectEnvironmentAndSecrets(t *testing.T) {
	config.IsolateProcessEnv(t)
	before := []byte("client_timeout=7s\npassword_default_len=31\n")
	if err := os.WriteFile(config.LocalConfigPath(), before, 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"backend": "git", "git_remote": "git@example.test:vault.git", "git_branch": "main", "profile": "work"}
	cfg, err := config.PreviewSetup("", values)
	if err != nil || cfg.Profile != "work" || cfg.Crypto.PasswordDefaultLen != 31 {
		t.Fatalf("setup preview: %v", err)
	}
	raw, err := os.ReadFile(config.LocalConfigPath())
	if err != nil || !bytes.Equal(raw, before) {
		t.Fatal("preview changed configuration")
	}
	for _, changes := range []map[string]string{{"master_passphrase": "secret"}, {"git_remote": "git@example.test:repo\nmaster_passphrase=secret"}} {
		if err := config.SaveSetup(changes); err == nil {
			t.Fatal("setup accepted a secret or injected configuration line")
		}
	}
	t.Setenv("SYLVA_PROFILE", "personal")
	if _, err := config.PreviewSetup("", values); err == nil {
		t.Fatal("setup ignored an environment override")
	}
	t.Setenv("SYLVA_PROFILE", "")
	if err := config.SaveSetup(values); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.LoadClientConfig("")
	if err != nil || cfg.Backend != "git" || cfg.Profile != "work" || cfg.Crypto.PasswordDefaultLen != 31 {
		t.Fatalf("saved setup not effective: %v", err)
	}
}
