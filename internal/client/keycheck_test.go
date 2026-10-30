package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
)

func keyCheckServer(t *testing.T) (config.ClientConfig, *storage.SQLiteStore) {
	t.Helper()
	config.IsolateProcessEnv(t)
	sc, err := config.LoadServerConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cc, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "vault.db"), sc.SQLiteBusyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	srv := transport.NewServer(sc, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	cc.ServerURL = "http://" + ln.Addr().String()
	cc.CacheEnabled = false
	cc.Crypto.KDFMemoryKB = 1024
	cc.Crypto.KDFTime = 1
	cc.Crypto.KDFThreads = 1
	return cc, store
}

func openKeyCheckVault(t *testing.T, cfg config.ClientConfig) *sylva.Vault {
	t.Helper()
	v, err := sylva.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func assertLocked(t *testing.T, v *sylva.Vault) {
	t.Helper()
	if _, err := v.CopyMasterKey(); !errors.Is(err, sylva.ErrLocked) {
		t.Fatalf("expected locked vault, got %v", err)
	}
}

func TestUnlockVerifiesEmptyAndPreviouslyPopulatedVault(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	ctx := context.Background()
	v := openKeyCheckVault(t, cfg)
	if setup, err := v.NeedsPassphraseSetup(ctx); err != nil || !setup {
		t.Fatalf("new vault: setup=%v err=%v", setup, err)
	}
	if err := v.Unlock(ctx, "correct passphrase"); err != nil {
		t.Fatal(err)
	}
	key, err := v.CopyMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(key)
	if setup, err := v.NeedsPassphraseSetup(ctx); err != nil || setup {
		t.Fatalf("initialized vault: setup=%v err=%v", setup, err)
	}
	if err := v.Unlock(ctx, "wrong passphrase"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("wrong passphrase accepted: %v", err)
	}
	assertLocked(t, v)
	if err := v.PutSecret(ctx, &vault.SecretItem{}); !errors.Is(err, sylva.ErrLocked) {
		t.Fatalf("write after failed unlock: %v", err)
	}
	if err := v.UnlockWithKey(ctx, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("wrong agent key accepted: %v", err)
	}
	assertLocked(t, v)
	if err := v.UnlockWithKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := v.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: "test", Token: &vault.TokenPayload{Name: "test", Token: "secret"}}); err != nil {
		t.Fatal(err)
	}
	if err := v.DeleteSecret(ctx, vault.SecretTypeToken, "test"); err != nil {
		t.Fatal(err)
	}
	other := openKeyCheckVault(t, cfg)
	if err := other.Unlock(ctx, "wrong passphrase"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("wrong passphrase after delete: %v", err)
	}
	assertLocked(t, other)
	if err := other.Unlock(ctx, "correct passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := other.Unlock(ctx, " "); err == nil {
		t.Fatal("empty passphrase accepted")
	}
	assertLocked(t, other)
}

func TestLegacyVaultMigrationRequiresEveryRecordToAuthenticate(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt record"}[corrupt], func(t *testing.T) {
			cfg, store := keyCheckServer(t)
			ctx := context.Background()
			v := openKeyCheckVault(t, cfg)
			salt, err := v.Init(ctx)
			if err != nil {
				t.Fatal(err)
			}
			key, err := crypto.DeriveKey([]byte("legacy passphrase"), salt, cfg.Crypto)
			if err != nil {
				t.Fatal(err)
			}
			defer crypto.ZeroBytes(key)
			for _, id := range []string{"one", "two"} {
				rec, err := vault.Seal(key, &vault.SecretItem{ID: id, Type: vault.SecretTypeToken, Identifier: id, Token: &vault.TokenPayload{Name: id, Token: "legacy secret"}}, 1)
				if err != nil {
					t.Fatal(err)
				}
				if corrupt && id == "two" {
					rec.Envelope.Ciphertext[0] ^= 1
				}
				if err := store.Put(ctx, rec); err != nil {
					t.Fatal(err)
				}
			}
			if err := v.UnlockWithKey(ctx, key); err == nil {
				t.Fatal("agent key initialized legacy verifier")
			}
			if err := v.Unlock(ctx, "wrong passphrase"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
				t.Fatalf("wrong legacy passphrase: %v", err)
			}
			assertLocked(t, v)
			if _, err := store.GetMetadata(ctx, storage.MetadataKeyCheck); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("wrong passphrase created verifier: %v", err)
			}
			err = v.Unlock(ctx, "legacy passphrase")
			if corrupt {
				if !errors.Is(err, sylva.ErrInvalidPassphrase) {
					t.Fatalf("corruption accepted: %v", err)
				}
				assertLocked(t, v)
				if _, err := store.GetMetadata(ctx, storage.MetadataKeyCheck); !errors.Is(err, storage.ErrNotFound) {
					t.Fatalf("corruption created verifier: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.GetMetadata(ctx, storage.MetadataKeyCheck); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestConcurrentFirstUnlockEstablishesOnlyOnePassphrase(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	v1, v2 := openKeyCheckVault(t, cfg), openKeyCheckVault(t, cfg)
	start := make(chan struct{})
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, v := range []*sylva.Vault{v1, v2} {
		wg.Add(1)
		go func(i int, v *sylva.Vault) {
			defer wg.Done()
			<-start
			errs[i] = v.Unlock(context.Background(), []string{"first", "second"}[i])
		}(i, v)
	}
	close(start)
	wg.Wait()
	success := 0
	for i, err := range errs {
		if err == nil {
			success++
			continue
		}
		if !errors.Is(err, sylva.ErrInvalidPassphrase) {
			t.Fatalf("unexpected error: %v", err)
		}
		assertLocked(t, []*sylva.Vault{v1, v2}[i])
	}
	if success != 1 {
		t.Fatalf("successful first unlocks: %d", success)
	}
}

func TestKeyCheckIsImmutableAndTamperingFailsClosed(t *testing.T) {
	cfg, store := keyCheckServer(t)
	ctx := context.Background()
	v := openKeyCheckVault(t, cfg)
	if err := v.Unlock(ctx, "passphrase"); err != nil {
		t.Fatal(err)
	}
	env, err := v.Remote().GetKeyCheck(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env.Ciphertext[0] ^= 1
	if err := v.Remote().PutKeyCheck(ctx, env); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("verifier replaced: %v", err)
	}
	if err := v.Unlock(ctx, "passphrase"); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutMetadata(ctx, storage.MetadataKeyCheck, raw); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(ctx, "passphrase"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("tampered verifier accepted: %v", err)
	}
	assertLocked(t, v)
}

func TestUnlockDoesNotInitializeOnServerErrors(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	for _, path := range []string{"salt", "key-check", "records"} {
		t.Run(path, func(t *testing.T) {
			writes := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes++
					w.WriteHeader(500)
					return
				}
				switch r.URL.Path {
				case "/api/v1/vault/salt":
					if path == "salt" {
						w.WriteHeader(503)
						return
					}
					_, _ = io.WriteString(w, `{"salt_hex":"000102030405060708090a0b0c0d0e0f"}`)
				case "/api/v1/vault/key-check":
					if path == "key-check" {
						w.WriteHeader(503)
					} else {
						w.WriteHeader(404)
					}
				default:
					w.WriteHeader(503)
				}
			}))
			defer srv.Close()
			cfg.ServerURL = srv.URL
			v := openKeyCheckVault(t, cfg)
			if err := v.Unlock(context.Background(), "passphrase"); err == nil {
				t.Fatal("server error accepted")
			}
			assertLocked(t, v)
			if writes != 0 {
				t.Fatalf("server error triggered %d writes", writes)
			}
		})
	}
}
