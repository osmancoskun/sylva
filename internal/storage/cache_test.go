package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestCacheSnapshotRollsBackOnInsertFailure(t *testing.T) {
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "cache.db"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	record := func(id, identifier string) *vault.EncryptedRecord {
		rec, err := vault.Seal(make([]byte, 32), &vault.SecretItem{ID: id, Type: vault.SecretTypeToken, Identifier: identifier, Token: &vault.TokenPayload{Name: identifier, Token: "secret"}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	old := record("old", "old-index")
	if err := store.Upsert(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := store.PutMetadata(ctx, storage.MetadataKDFSalt, []byte("salt")); err != nil {
		t.Fatal(err)
	}
	one := record("new", "one")
	two := record("new", "two")
	// The second insert violates the primary key after the transaction has
	// deleted the old snapshot and inserted the first record.
	if err := store.ReplaceRecords(ctx, "", []*vault.EncryptedRecord{one, two}); err == nil {
		t.Fatal("duplicate-ID snapshot accepted")
	}
	records, err := store.List(ctx, "")
	if err != nil || len(records) != 1 || records[0].ID != old.ID {
		t.Fatalf("failed snapshot destroyed original: count=%d err=%v", len(records), err)
	}
	if err := store.ReplaceRecords(ctx, vault.SecretTypeEnv, []*vault.EncryptedRecord{one}); err == nil {
		t.Fatal("snapshot accepted a different type")
	}
	if err := store.ReplaceRecords(ctx, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetByID(ctx, old.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("empty snapshot retained old entry: %v", err)
	}
	if salt, err := store.GetMetadata(ctx, storage.MetadataKDFSalt); err != nil || string(salt) != "salt" {
		t.Fatalf("snapshot changed vault metadata: %v", err)
	}
}
