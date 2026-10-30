package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
)

// Two clients share a real vault server. Only the reader caches records; its
// proxy can independently fail without preventing the other device's writes.
func cachedClients(t *testing.T) (reader, writer *sylva.Vault, cache *storage.SQLiteStore, proxy *httptest.Server, status *atomic.Int32) {
	t.Helper()
	cfg, _ := keyCheckServer(t)
	writer = openKeyCheckVault(t, cfg)
	if err := writer.Unlock(context.Background(), "cache test passphrase"); err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(cfg.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	reverse := httputil.NewSingleHostReverseProxy(target)
	status = new(atomic.Int32)
	proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := status.Load(); code != 0 && r.URL.Path == "/api/v1/records" {
			if code < 0 {
				_, _ = w.Write([]byte(map[int32]string{-1: "invalid json", -2: "", -3: `{}`, -4: `{"records":null}`, -5: `null`}[code]))
				return
			}
			w.WriteHeader(int(code))
			return
		}
		reverse.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	cfg.ServerURL = proxy.URL
	cfg.CacheEnabled = true
	cfg.CachePath = filepath.Join(t.TempDir(), "cache.db")
	reader = openKeyCheckVault(t, cfg)
	if err := reader.Unlock(context.Background(), "cache test passphrase"); err != nil {
		t.Fatal(err)
	}
	cache, err = storage.OpenSQLite(cfg.CachePath, cfg.SQLiteBusyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	return
}

func putCachedToken(t *testing.T, v *sylva.Vault, value string) {
	t.Helper()
	if err := v.PutSecret(context.Background(), &vault.SecretItem{
		Type: vault.SecretTypeToken, Identifier: "shared-token",
		Token: &vault.TokenPayload{Name: "shared-token", Token: value},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteDeletionEvictsCachedIdentifier(t *testing.T) {
	reader, writer, cache, proxy, _ := cachedClients(t)
	ctx := context.Background()
	putCachedToken(t, writer, "old value")
	if _, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token"); err != nil {
		t.Fatal(err)
	}
	if err := writer.DeleteSecret(ctx, vault.SecretTypeToken, "shared-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("deleted secret resurfaced: %v", err)
	}
	if exists, err := reader.SecretExists(ctx, vault.SecretTypeToken, "shared-token"); err != nil || exists {
		t.Fatalf("deleted secret exists: %v, %v", exists, err)
	}
	if recs, err := cache.List(ctx, ""); err != nil || len(recs) != 0 {
		t.Fatalf("deleted record remained cached: count=%d err=%v", len(recs), err)
	}
	proxy.Close()
	if _, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("offline cache resurrected deletion: %v", err)
	}
}

func TestServerSnapshotsPruneDeletedCachedRecords(t *testing.T) {
	for _, scope := range []vault.SecretType{"", vault.SecretTypeToken} {
		t.Run("scope="+string(scope), func(t *testing.T) {
			reader, writer, cache, proxy, _ := cachedClients(t)
			ctx := context.Background()
			putCachedToken(t, writer, "token value")
			if err := writer.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeEnv, Identifier: "project", Env: &vault.EnvPayload{Project: "project", Variables: map[string]string{"KEY": "value"}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ListSecrets(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if err := writer.DeleteSecret(ctx, vault.SecretTypeToken, "shared-token"); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ListSecrets(ctx, scope); err != nil {
				t.Fatal(err)
			}
			recs, err := cache.List(ctx, "")
			if err != nil || len(recs) != 1 || recs[0].Type != vault.SecretTypeEnv {
				t.Fatalf("snapshot did not preserve only the env record: count=%d err=%v", len(recs), err)
			}
			proxy.Close()
			if _, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("pruned record returned offline: %v", err)
			}
			if _, err := reader.GetSecret(ctx, vault.SecretTypeEnv, "project"); err != nil {
				t.Fatalf("filtered snapshot lost another type: %v", err)
			}
		})
	}
}

func TestEmptySnapshotClearsCachedDomainInheritance(t *testing.T) {
	reader, writer, cache, proxy, _ := cachedClients(t)
	ctx := context.Background()
	if _, err := writer.LoginSet(ctx, "company.test", "user", "secret", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.LoginSet(ctx, "mail.company.test", "", "", true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.LoginGet(ctx, "mail.company.test", false); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"mail.company.test", "company.test"} {
		if err := writer.DeleteSecret(ctx, vault.SecretTypeLogin, domain); err != nil {
			t.Fatal(err)
		}
	}
	if items, err := reader.ListSecrets(ctx, ""); err != nil || len(items) != 0 {
		t.Fatalf("empty snapshot: count=%d err=%v", len(items), err)
	}
	if recs, err := cache.List(ctx, ""); err != nil || len(recs) != 0 {
		t.Fatalf("empty snapshot left cached logins: count=%d err=%v", len(recs), err)
	}
	proxy.Close()
	if _, err := reader.LoginGet(ctx, "mail.company.test", false); err == nil {
		t.Fatal("offline inheritance resurrected deleted logins")
	}
}

func TestRecreatedIdentifierReplacesOldCachedID(t *testing.T) {
	reader, writer, cache, proxy, _ := cachedClients(t)
	ctx := context.Background()
	putCachedToken(t, writer, "old value")
	old, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.DeleteSecret(ctx, vault.SecretTypeToken, "shared-token"); err != nil {
		t.Fatal(err)
	}
	putCachedToken(t, writer, "new value")
	updated, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID == old.ID {
		t.Fatal("test must recreate the identifier with a different ID")
	}
	if _, err := cache.GetByID(ctx, old.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("old ID remained cached: %v", err)
	}
	proxy.Close()
	item, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
	if err != nil || item.Token.Token != "new value" {
		t.Fatalf("offline recreated identifier is stale: %v", err)
	}
}

func TestCacheDoesNotHideHTTPOrDecodeErrors(t *testing.T) {
	for _, code := range []int32{401, 403, 404, 500, 503, -1} {
		name := http.StatusText(int(code))
		if code == -1 {
			name = "malformed JSON"
		}
		t.Run(name, func(t *testing.T) {
			reader, writer, _, proxy, status := cachedClients(t)
			ctx := context.Background()
			putCachedToken(t, writer, "cached value")
			if _, err := reader.ListSecrets(ctx, ""); err != nil {
				t.Fatal(err)
			}
			status.Store(code)
			_, getErr := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
			_, listErr := reader.ListSecrets(ctx, "")
			for i, err := range []error{getErr, listErr} {
				if err == nil {
					t.Fatal("server error hidden by cache")
				}
				if code > 0 {
					if i == 0 && code == http.StatusNotFound {
						if !errors.Is(err, storage.ErrNotFound) {
							t.Fatalf("missing-record error lost: %v", err)
						}
						continue
					}
					var he *transport.HTTPError
					if !errors.As(err, &he) || he.Status != int(code) {
						t.Fatalf("HTTP error lost: %v", err)
					}
				}
			}
			proxy.Close()
			items, err := reader.ListSecrets(ctx, "")
			want := 1
			if code == 404 {
				want = 0
			}
			if err != nil || len(items) != want {
				t.Fatalf("failed response changed snapshot: count=%d want=%d err=%v", len(items), want, err)
			}
		})
	}
}

func TestCanceledReadDoesNotFallBackToCache(t *testing.T) {
	reader, writer, _, _, _ := cachedClients(t)
	putCachedToken(t, writer, "cached value")
	if _, err := reader.ListSecrets(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.GetSecret(ctx, vault.SecretTypeToken, "shared-token"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled get used cache: %v", err)
	}
	if _, err := reader.ListSecrets(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list used cache: %v", err)
	}
}

func TestInvalidListResponseDoesNotEraseCachedSnapshot(t *testing.T) {
	for _, code := range []int32{-2, -3, -4, -5} {
		t.Run(map[int32]string{-2: "empty body", -3: "missing records", -4: "null records", -5: "null response"}[code], func(t *testing.T) {
			reader, writer, _, proxy, status := cachedClients(t)
			ctx := context.Background()
			putCachedToken(t, writer, "cached value")
			if _, err := reader.ListSecrets(ctx, ""); err != nil {
				t.Fatal(err)
			}
			status.Store(code)
			if _, err := reader.ListSecrets(ctx, ""); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			proxy.Close()
			if items, err := reader.ListSecrets(ctx, ""); err != nil || len(items) != 1 {
				t.Fatalf("invalid snapshot destroyed cache: count=%d err=%v", len(items), err)
			}
		})
	}
}
