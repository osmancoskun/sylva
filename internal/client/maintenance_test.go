package client_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestPassphraseRotationPreservesRecordsAndRejectsOldWriters(t *testing.T) {
	reader, writer, _, _, _ := cachedClients(t)
	ctx := context.Background()
	putCachedToken(t, writer, "token secret")
	if _, err := writer.LoginSet(ctx, "company.test", "user", "login secret", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.LoginSet(ctx, "mail.company.test", "", "", true, false); err != nil {
		t.Fatal(err)
	}
	old, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.ChangePassphrase(ctx, "new master passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := reader.UpdateSecret(ctx, old); !errors.Is(err, storage.ErrVaultChanged) {
		t.Fatalf("old session could update after rotation: %v", err)
	}
	if err := reader.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: "stale-write", Token: &vault.TokenPayload{Name: "stale-write", Token: "old key ciphertext"}}); !errors.Is(err, sylva.ErrLocked) {
		t.Fatalf("old session could insert after rotation: %v", err)
	}
	if err := reader.Remote().DeleteRecord(ctx, old.ID); !errors.Is(err, storage.ErrVaultChanged) {
		t.Fatalf("old session could delete after rotation: %v", err)
	}
	if err := reader.Unlock(ctx, "cache test passphrase"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("old password still unlocked: %v", err)
	}
	if err := reader.Unlock(ctx, "new master passphrase"); err != nil {
		t.Fatal(err)
	}
	got, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || got.Token.Token != "token secret" || got.ID != old.ID || got.Version != old.Version+1 {
		t.Fatalf("rotation changed token: %v", err)
	}
	res, err := reader.LoginGet(ctx, "mail.company.test", false)
	if err != nil || res.Item.Login.Password != "login secret" || !res.Inherited {
		t.Fatalf("rotation broke inheritance: %v", err)
	}
	got.Token.Token = "updated after rotation"
	if err := reader.UpdateSecret(ctx, got); err != nil {
		t.Fatalf("new session could not update: %v", err)
	}
}

func TestBackupRestoreAuthenticatesBeforeChangingTarget(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	source := openKeyCheckVault(t, cfg)
	ctx := context.Background()
	if err := source.Unlock(ctx, "backup passphrase"); err != nil {
		t.Fatal(err)
	}
	putCachedToken(t, source, "private backup value")
	path := filepath.Join(t.TempDir(), "vault.sylva")
	if err := source.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions: %v", info.Mode())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private backup value")) || bytes.Contains(raw, []byte("shared-token")) {
		t.Fatal("backup leaked plaintext")
	}
	if err := source.Backup(ctx, path); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, raw) {
		t.Fatal("existing backup was modified")
	}
	targetCfg, targetStore := keyCheckServer(t)
	target := openKeyCheckVault(t, targetCfg)
	if err := target.Restore(ctx, path, "wrong passphrase"); err == nil {
		t.Fatal("wrong backup password accepted")
	}
	var archive map[string]any
	if err := json.Unmarshal(raw, &archive); err != nil {
		t.Fatal(err)
	}
	env := archive["envelope"].(map[string]any)
	ciphertext, err := base64.StdEncoding.DecodeString(env["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	env["ciphertext"] = base64.StdEncoding.EncodeToString(ciphertext)
	corrupt, err := json.Marshal(archive)
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "corrupt.sylva")
	if err := os.WriteFile(badPath, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := target.Restore(ctx, badPath, "backup passphrase"); err == nil {
		t.Fatal("tampered backup accepted")
	}
	state, err := targetStore.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 0 || len(state.Salt) != 0 || state.KeyCheck != nil || len(state.Records) != 0 {
		t.Fatal("failed restore changed the target")
	}
	if err := source.ChangePassphrase(ctx, "rotated source passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := target.Restore(ctx, path, "backup passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := target.Unlock(ctx, "backup passphrase"); err != nil {
		t.Fatal(err)
	}
	item, err := target.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || item.Token.Token != "private backup value" {
		t.Fatalf("restored value mismatch: %v", err)
	}
	item.Token.Token = "restored update"
	if err := target.UpdateSecret(ctx, item); err != nil {
		t.Fatalf("restored generation cannot write: %v", err)
	}
	if err := target.Restore(ctx, path, "backup passphrase"); err == nil {
		t.Fatal("restore overwrote an initialized vault")
	}
}

func TestConcurrentWriteAbortsWholePassphraseRotation(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	writer := openKeyCheckVault(t, cfg)
	ctx := context.Background()
	if err := writer.Unlock(ctx, "old passphrase"); err != nil {
		t.Fatal(err)
	}
	putCachedToken(t, writer, "original")
	url, err := url.Parse(cfg.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	reverse := httputil.NewSingleHostReverseProxy(url)
	ready := make(chan struct{})
	release := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/vault/snapshot" {
			close(ready)
			<-release
		}
		reverse.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	cfg.ServerURL = proxy.URL
	rotator := openKeyCheckVault(t, cfg)
	if err := rotator.Unlock(ctx, "old passphrase"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- rotator.ChangePassphrase(ctx, "new passphrase") }()
	<-ready
	item, err := writer.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	item.Token.Token = "concurrent edit"
	err = writer.UpdateSecret(ctx, item)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, storage.ErrVaultChanged) {
		t.Fatalf("rotation ignored concurrent edit: %v", err)
	}
	if err := writer.Unlock(ctx, "new passphrase"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("failed rotation changed the password: %v", err)
	}
	if err := writer.Unlock(ctx, "old passphrase"); err != nil {
		t.Fatal(err)
	}
	got, err := writer.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || got.Token.Token != "concurrent edit" {
		t.Fatalf("rotation lost concurrent edit: %v", err)
	}
}
