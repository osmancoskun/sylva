package client_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/vault"
)

func TestLargeVaultListRotateBackupAndRestore(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	source := openKeyCheckVault(t, cfg)
	ctx := context.Background()
	if err := source.Unlock(ctx, "original passphrase"); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("large-%d", i)
		value := strings.Repeat(fmt.Sprint(i), 260000)
		values[name] = value
		if err := source.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: name, Token: &vault.TokenPayload{Name: name, Token: value}}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := source.ListSecrets(ctx, "")
	if err != nil || len(items) != 4 {
		t.Fatalf("large list: %v", err)
	}
	if err := source.ChangePassphrase(ctx, "rotated passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := source.Unlock(ctx, "original passphrase"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("old passphrase: %v", err)
	}
	if err := source.Unlock(ctx, "rotated passphrase"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "large.sylva")
	if err := source.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= limits.DefaultBodyBytes {
		t.Fatal("test did not exceed old 1 MiB limit")
	}
	targetCfg, _ := keyCheckServer(t)
	target := openKeyCheckVault(t, targetCfg)
	if err := target.Restore(ctx, path, "rotated passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := target.Unlock(ctx, "rotated passphrase"); err != nil {
		t.Fatal(err)
	}
	for name, value := range values {
		item, err := target.GetSecret(ctx, vault.SecretTypeToken, name)
		if err != nil {
			t.Fatal(err)
		}
		if item.Token == nil || item.Token.Token != value || item.Version != 2 {
			t.Fatal("restore changed a record or its revision")
		}
	}
	item, err := target.GetSecret(ctx, vault.SecretTypeToken, "large-0")
	if err != nil {
		t.Fatal(err)
	}
	item.Token.Token = "updated after restore"
	if err := target.UpdateSecret(ctx, item); err != nil {
		t.Fatal(err)
	}
}

func TestBackupLimitsDoNotPublishOrMutate(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	cfg.MaxBackupBytes = 128
	source := openKeyCheckVault(t, cfg)
	ctx := context.Background()
	if err := source.Unlock(ctx, "test passphrase"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "too-large.sylva")
	if err := source.Backup(ctx, path); !errors.Is(err, limits.ErrExceeded) {
		t.Fatalf("backup limit: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed backup published or left temporary files")
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(limits.DefaultBackupBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	targetCfg, store := keyCheckServer(t)
	target := openKeyCheckVault(t, targetCfg)
	if err := target.Restore(ctx, path, "test passphrase"); !errors.Is(err, limits.ErrExceeded) {
		t.Fatalf("restore limit: %v", err)
	}
	state, err := store.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 0 || state.KeyCheck != nil || len(state.Records) != 0 {
		t.Fatal("oversized restore changed target")
	}
}
