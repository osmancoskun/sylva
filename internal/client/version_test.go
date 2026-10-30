package client_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestStaleEditsDoNotOverwriteNewerRecords(t *testing.T) {
	reader, writer, cache, proxy, _ := cachedClients(t)
	ctx := context.Background()
	putCachedToken(t, writer, "original")
	stale, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	current, err := writer.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	current.Token.Token = "newer value"
	if err := writer.UpdateSecret(ctx, current); err != nil {
		t.Fatal(err)
	}
	if current.Version != stale.Version+1 {
		t.Fatal("successful update did not advance the source version")
	}
	stale.Token.Token = "stale edit"
	if err := reader.UpdateSecret(ctx, stale); !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("stale edit overwrote a newer record: %v", err)
	}
	if stale.Version != current.Version-1 || stale.Token.Token != "stale edit" {
		t.Fatal("conflict changed the pending edit or advanced its source version")
	}
	if cached, err := cache.List(ctx, ""); err != nil || len(cached) != 0 {
		t.Fatalf("conflict left stale cached credentials: count=%d err=%v", len(cached), err)
	}
	latest, err := writer.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || latest.Token.Token != "newer value" {
		t.Fatalf("winning update lost: %v", err)
	}
	// Refetching is an explicit user decision, not an automatic retry.
	fresh, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	fresh.Token.Token = "fresh edit"
	if err := reader.UpdateSecret(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	fresh.Token.Token = "another edit"
	if err := reader.UpdateSecret(ctx, fresh); err != nil {
		t.Fatalf("successful item could not be updated again: %v", err)
	}
	proxy.Close()
	got, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || got.Token.Token != "another edit" {
		t.Fatalf("successful update was not cached: %v", err)
	}
}

func TestSimultaneousClientUpdatesAllowOnlyOneWriter(t *testing.T) {
	reader, writer, _, _, _ := cachedClients(t)
	ctx := context.Background()
	putCachedToken(t, writer, "original")
	items := make([]*vault.SecretItem, 2)
	for i, v := range []*sylva.Vault{reader, writer} {
		item, err := v.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
		if err != nil {
			t.Fatal(err)
		}
		if item == nil || item.Token == nil {
			t.Fatal("expected a token record")
		}
		items[i] = item
	}
	items[0].Token.Token = "first writer"
	items[1].Token.Token = "second writer"
	start := make(chan struct{})
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, v := range []*sylva.Vault{reader, writer} {
		wg.Add(1)
		go func(i int, v *sylva.Vault) { defer wg.Done(); <-start; errs[i] = v.UpdateSecret(ctx, items[i]) }(i, v)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, err := range errs {
		if err == nil {
			if winner != -1 {
				t.Fatal("both clients updated the same source version")
			}
			winner = i
		} else if !errors.Is(err, storage.ErrVersionConflict) {
			t.Fatalf("unexpected failure: %v", err)
		}
	}
	if winner == -1 {
		t.Fatal("neither client updated the record")
	}
	got, err := writer.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || got.Token.Token != items[winner].Token.Token {
		t.Fatalf("winning value was not preserved: %v", err)
	}
}

func TestOldEditCannotUpdateRecreatedIdentifier(t *testing.T) {
	reader, writer, cache, _, _ := cachedClients(t)
	ctx := context.Background()
	putCachedToken(t, writer, "original")
	old, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.DeleteSecret(ctx, vault.SecretTypeToken, "shared-token"); err != nil {
		t.Fatal(err)
	}
	putCachedToken(t, writer, "recreated value")
	old.Token.Token = "stale edit"
	if err := reader.UpdateSecret(ctx, old); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("old edit changed the recreated identifier: %v", err)
	}
	if cached, err := cache.List(ctx, ""); err != nil || len(cached) != 0 {
		t.Fatalf("old ID remained cached: %v", err)
	}
	got, err := writer.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || got.ID == old.ID || got.Token.Token != "recreated value" {
		t.Fatalf("recreated record changed: %v", err)
	}
}

func TestUpdateRequiresAnItemReadFromTheVault(t *testing.T) {
	reader, writer, _, _, _ := cachedClients(t)
	ctx := context.Background()
	putCachedToken(t, writer, "original")
	item := &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: "shared-token", Token: &vault.TokenPayload{Name: "shared-token", Token: "blind overwrite"}}
	if err := reader.UpdateSecret(ctx, item); err == nil {
		t.Fatal("update without a source revision succeeded")
	}
	got, err := writer.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || got.Token.Token != "original" {
		t.Fatalf("blind update changed the record: %v", err)
	}
}
