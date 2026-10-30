package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestConcurrentUpdatesCompareVersionsAcrossConnections(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault.db")
	first, err := storage.OpenSQLite(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := storage.OpenSQLite(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	key := make([]byte, 32)
	seal := func(value string, version int) *vault.EncryptedRecord {
		rec, err := vault.Seal(key, &vault.SecretItem{ID: "shared", Type: vault.SecretTypeToken, Identifier: "token", Token: &vault.TokenPayload{Name: "token", Token: value}}, version)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	if err := first.Put(ctx, seal("original", 1)); err != nil {
		t.Fatal(err)
	}
	candidates := []*vault.EncryptedRecord{seal("first writer", 2), seal("second writer", 2)}
	errs := make([]error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, store := range []*storage.SQLiteStore{first, second} {
		wg.Add(1)
		go func(i int, store *storage.SQLiteStore) {
			defer wg.Done()
			<-start
			errs[i] = store.Update(ctx, candidates[i])
		}(i, store)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, err := range errs {
		if err == nil {
			if winner != -1 {
				t.Fatal("both writers overwrote the same source version")
			}
			winner = i
		} else if !errors.Is(err, storage.ErrVersionConflict) {
			t.Fatalf("unexpected update error: %v", err)
		}
	}
	if winner == -1 {
		t.Fatal("neither writer succeeded")
	}
	got, err := first.GetByID(ctx, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || string(got.Envelope.Ciphertext) != string(candidates[winner].Envelope.Ciphertext) {
		t.Fatal("losing writer modified the stored record")
	}
	for _, version := range []int{-1, 0, 1, 2, 4} {
		stale := *candidates[winner]
		stale.Version = version
		if err := second.Update(ctx, &stale); !errors.Is(err, storage.ErrVersionConflict) {
			t.Fatalf("version %d accepted: %v", version, err)
		}
	}
	if err := second.Update(ctx, seal("fresh update", 3)); err != nil {
		t.Fatalf("next version rejected: %v", err)
	}
	if err := first.Delete(ctx, "shared"); err != nil {
		t.Fatal(err)
	}
	if err := second.Update(ctx, seal("deleted", 4)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("deleted record was recreated: %v", err)
	}
}
