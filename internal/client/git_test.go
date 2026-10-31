package client_test

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func gitVaultConfig(t *testing.T) config.ClientConfig {
	t.Helper()
	config.IsolateProcessEnv(t)
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(t.TempDir(), "remote.git")
	if output, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("init disposable Git remote: %v: %s", err, output)
	}
	cfg.Backend, cfg.GitRemote, cfg.GitBranch = "git", remote, "main"
	cfg.CacheEnabled = false
	cfg.Timeout = 30 * time.Second
	cfg.Crypto.KDFMemoryKB, cfg.Crypto.KDFTime, cfg.Crypto.KDFThreads = 1024, 1, 1
	return cfg
}

func TestGitVaultSharesEncryptedRecordsAcrossDevices(t *testing.T) {
	cfg := gitVaultConfig(t)
	ctx := context.Background()
	a := openKeyCheckVault(t, cfg)
	if err := a.Unlock(ctx, "shared Git master"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LoginSet(ctx, "company.example", "test-user", "domain-secret", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LoginSet(ctx, "mail.company.example", "", "", true, false); err != nil {
		t.Fatal(err)
	}
	if err := a.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: "github", Token: &vault.TokenPayload{Name: "github", Token: "github-secret"}}); err != nil {
		t.Fatal(err)
	}
	// A second device must use the vault's published KDF, not its own defaults.
	cfg.Crypto.KDFMemoryKB, cfg.Crypto.KDFTime = 2048, 2
	b := openKeyCheckVault(t, cfg)
	if err := b.Unlock(ctx, "wrong master"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("wrong password accepted: %v", err)
	}
	if err := b.Unlock(ctx, "shared Git master"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, value string }{{"github", "github-secret"}, {"mail.company.example", "domain-secret"}} {
		_, value, err := b.GetValue(ctx, tc.id, "", false, "")
		if err != nil || value != tc.value {
			t.Fatalf("second device read %s: %v", tc.id, err)
		}
	}
	oldA, err := a.GetSecret(ctx, vault.SecretTypeToken, "github")
	if err != nil {
		t.Fatal(err)
	}
	oldB, err := b.GetSecret(ctx, vault.SecretTypeToken, "github")
	if err != nil {
		t.Fatal(err)
	}
	oldA.Token.Token = "updated-secret"
	if err := a.UpdateSecret(ctx, oldA); err != nil {
		t.Fatal(err)
	}
	oldB.Token.Token = "stale-secret"
	if err := b.UpdateSecret(ctx, oldB); !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("stale edit overwrote newer ciphertext: %v", err)
	}
	if err := b.DeleteSecret(ctx, vault.SecretTypeToken, "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetSecret(ctx, vault.SecretTypeToken, "github"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("deletion did not reach the other device: %v", err)
	}
	raw, err := exec.Command("git", "--git-dir="+cfg.GitRemote, "log", "-p", "refs/heads/main").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"github-secret", "domain-secret", "updated-secret", "company.example", "test-user", "shared Git master"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("Git history contains plaintext %q", secret)
		}
	}
}

func TestGitVaultRotationBackupRestoreAndStaleSessions(t *testing.T) {
	cfg := gitVaultConfig(t)
	ctx := context.Background()
	a := openKeyCheckVault(t, cfg)
	b := openKeyCheckVault(t, cfg)
	if err := a.Unlock(ctx, "old Git master"); err != nil {
		t.Fatal(err)
	}
	putCachedToken(t, a, "Git recovery value")
	if err := b.Unlock(ctx, "old Git master"); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "archive")
	if err := a.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := a.ChangePassphrase(ctx, "new Git master"); err != nil {
		t.Fatal(err)
	}
	if err := b.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: "stale", Token: &vault.TokenPayload{Name: "stale", Token: "stale"}}); !errors.Is(err, storage.ErrVaultChanged) {
		t.Fatalf("old session wrote after rotation: %v", err)
	}
	assertLocked(t, b)
	if err := b.Unlock(ctx, "old Git master"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("old master still unlocked: %v", err)
	}
	if err := b.Unlock(ctx, "new Git master"); err != nil {
		t.Fatal(err)
	}
	if _, value, err := b.GetValue(ctx, "shared-token", vault.SecretTypeToken, false, ""); err != nil || value != "Git recovery value" {
		t.Fatalf("rotation lost the secret: %v", err)
	}
	target := openKeyCheckVault(t, gitVaultConfig(t))
	if err := target.Restore(ctx, backup, "wrong backup master"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("wrong backup passphrase accepted: %v", err)
	}
	if err := target.Restore(ctx, backup, "old Git master"); err != nil {
		t.Fatal(err)
	}
	if _, value, err := target.GetValue(ctx, "shared-token", vault.SecretTypeToken, false, ""); err != nil || value != "Git recovery value" {
		t.Fatalf("restore lost the secret: %v", err)
	}
	if err := target.Restore(ctx, backup, "old Git master"); err == nil {
		t.Fatal("restore overwrote an existing Git vault")
	}
}
