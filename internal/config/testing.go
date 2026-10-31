package config

import (
	"path/filepath"
	"testing"
)

// IsolateProcessEnv keeps tests on loopback defaults so a developer .env
// (MagicDNS host, auth key) cannot change listen addresses.
func IsolateProcessEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SYLVA_GIT_CACHE_DIR", filepath.Join(t.TempDir(), "git-cache"))
	t.Setenv("SYLVA_HOST", "127.0.0.1")
	t.Setenv("SYLVA_PORT", "8443")
	t.Setenv("SYLVA_LOCAL_CONFIG", filepath.Join(t.TempDir(), "config"))
	for _, key := range []string{
		"SYLVA_PROFILE", "SYLVA_BACKEND", "SYLVA_GIT_REMOTE", "SYLVA_GIT_BRANCH", "SYLVA_GIT_TIMEOUT", "SYLVA_SSH_UNLOCK_DIR",
		"SYLVA_SERVER_ADDR",
		"SYLVA_SERVER_URL",
		"SYLVA_TAILSCALE_AUTHKEY",
		"SYLVA_MASTER_PASSPHRASE",
		"SYLVA_MTLS_ENABLED",
		"SYLVA_TAILSCALE_ENABLED",
		"SYLVA_TAILSCALE_STATE_DIR",
		"SYLVA_TAILSCALE_NODE",
	} {
		t.Setenv(key, "")
	}
}
