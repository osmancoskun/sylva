package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/leakcheck"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func TestSQLitePutGetListDeleteAndMetadata(t *testing.T) {
	envPath := filepath.Join("..", "..", ".env.example")
	cfg, err := config.LoadCryptoConfig(envPath)
	if err != nil {
		t.Fatalf("load crypto config: %v", err)
	}
	srvCfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "store.db")
	store, err := storage.OpenSQLite(dbPath, srvCfg.SQLiteBusyTimeout)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	salt, err := crypto.GenerateSalt(cfg.KDFSaltLen)
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if err := store.PutMetadata(ctx, storage.MetadataKDFSalt, salt); err != nil {
		t.Fatalf("put metadata: %v", err)
	}
	gotSalt, err := store.GetMetadata(ctx, storage.MetadataKDFSalt)
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	if string(gotSalt) != string(salt) {
		t.Fatalf("salt mismatch")
	}

	masterKey, err := crypto.DeriveKey([]byte("storage-test-passphrase"), salt, cfg)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.ZeroBytes(masterKey)

	item := &vault.SecretItem{
		ID:         "rec-1",
		Type:       vault.SecretTypeLogin,
		Identifier: "company.com",
		Login: &vault.LoginPayload{
			Domain:   "company.com",
			Username: "osman",
			Password: "secret",
		},
	}
	rec, err := vault.Seal(masterKey, item, srvCfg.RecordInitialVersion)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if err := store.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	byID, err := store.GetByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	unsealed, err := vault.Unseal(masterKey, byID)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if unsealed.Login.Password != "secret" {
		t.Fatalf("unexpected password %q", unsealed.Login.Password)
	}

	byIdx, err := store.GetByBlindIndex(ctx, rec.BlindIndex)
	if err != nil {
		t.Fatalf("get by blind index: %v", err)
	}
	if byIdx.ID != rec.ID {
		t.Fatalf("blind index lookup id mismatch")
	}

	listed, err := store.List(ctx, vault.SecretTypeLogin)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected 1 login record, got %d", len(listed))
	}

	if err := store.Put(ctx, rec); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("expected conflict on duplicate id, got %v", err)
	}

	item.Login.Password = "updated-secret"
	updated, err := vault.Seal(masterKey, item, rec.Version+1)
	if err != nil {
		t.Fatalf("seal update: %v", err)
	}
	updated.ID = rec.ID
	if err := store.Update(ctx, updated); err != nil {
		t.Fatalf("update: %v", err)
	}
	gotUpdated, err := store.GetByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	unsealedUpdated, err := vault.Unseal(masterKey, gotUpdated)
	if err != nil {
		t.Fatalf("unseal updated: %v", err)
	}
	if unsealedUpdated.Login.Password != "updated-secret" {
		t.Fatalf("updated password %q", unsealedUpdated.Login.Password)
	}

	conflict := *rec
	conflict.ID = "rec-2"
	if err := store.Put(ctx, &conflict); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	if err := store.Delete(ctx, rec.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.GetByID(ctx, rec.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}

	_, err = store.GetMetadata(ctx, "missing")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected metadata not found, got %v", err)
	}

	// Keep busy-timeout wiring honest even if unused beyond OpenSQLite.
	if srvCfg.SQLiteBusyTimeout < time.Millisecond {
		t.Fatalf("expected positive sqlite busy timeout from env")
	}
}
