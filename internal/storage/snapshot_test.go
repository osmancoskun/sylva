package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestVaultReplacementRollsBackAllMetadataOnFailure(t *testing.T) {
	ctx := context.Background()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "vault.db"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := make([]byte, 32)
	seal := func(id string) *vault.EncryptedRecord {
		rec, err := vault.Seal(key, &vault.SecretItem{ID: id, Type: vault.SecretTypeToken, Identifier: id, Token: &vault.TokenPayload{Name: id, Token: "secret"}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	if err := store.Put(ctx, seal("original")); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateMetadata(ctx, storage.MetadataKDFSalt, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	check := &crypto.Envelope{Nonce: make([]byte, 12), Ciphertext: make([]byte, 16)}
	kdf := &config.CryptoConfig{KDFTime: 1, KDFMemoryKB: 1024, KDFThreads: 1, KDFKeyLen: 32, KDFSaltLen: 16}
	duplicate := seal("new")
	next := &vault.Snapshot{Generation: "new generation", Salt: make([]byte, 16), KeyCheck: check, KDF: kdf, Records: []*vault.EncryptedRecord{duplicate, duplicate}}
	if err := store.ReplaceVault(ctx, before.Revision, before.Generation, next, false); err == nil {
		t.Fatal("invalid replacement succeeded")
	}
	after, err := store.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("failed replacement changed salt, generation, revision or records")
	}
	next.Records = []*vault.EncryptedRecord{seal("restored")}
	if err := store.ReplaceVault(ctx, before.Revision, before.Generation, next, true); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("restore overwrote a nonempty vault: %v", err)
	}
	if err := store.ReplaceVault(ctx, before.Revision, before.Generation, next, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, seal("stale")); !errors.Is(err, storage.ErrVaultChanged) {
		t.Fatalf("old generation still wrote: %v", err)
	}
	if err := store.Put(storage.WithGeneration(ctx, next.Generation), seal("current")); err != nil {
		t.Fatalf("current generation could not write: %v", err)
	}
	if err := store.ReplaceVault(ctx, before.Revision, before.Generation, next, false); !errors.Is(err, storage.ErrVaultChanged) {
		t.Fatalf("stale snapshot replaced newer vault: %v", err)
	}
}
