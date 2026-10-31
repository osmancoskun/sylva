package storage_test

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestLegacySQLiteProfileMigrationPreservesCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE records(id TEXT PRIMARY KEY,type TEXT NOT NULL,blind_index TEXT NOT NULL UNIQUE,parent_blind_index TEXT NOT NULL DEFAULT '',nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,version INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	rec, err := vault.Seal(key, &vault.SecretItem{ID: "legacy", Type: vault.SecretTypeToken, Identifier: "github", Token: &vault.TokenPayload{Name: "github", Token: "legacy secret"}}, 1)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?)`, rec.ID, string(rec.Type), rec.BlindIndex, rec.ParentBlindIndex, rec.Envelope.Nonce, rec.Envelope.Ciphertext, rec.Version, rec.CreatedAt.Format(time.RFC3339Nano), rec.UpdatedAt.Format(time.RFC3339Nano))
	closeErr := db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	for range 2 {
		store, err := storage.OpenSQLite(path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.GetByID(context.Background(), rec.ID)
		if err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		if got.ProfileID != "" || !bytes.Equal(got.Envelope.Ciphertext, rec.Envelope.Ciphertext) {
			_ = store.Close()
			t.Fatal("migration changed the legacy envelope")
		}
		if _, err := vault.Unseal(key, got); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
