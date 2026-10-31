package client_test

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func profileBackends() map[string]func(*testing.T) config.ClientConfig {
	return map[string]func(*testing.T) config.ClientConfig{
		"self-hosted": func(t *testing.T) config.ClientConfig { cfg, _ := keyCheckServer(t); return cfg },
		"git":         gitVaultConfig,
	}
}

func TestProfilesIsolateAccountsAndShareRootUnlock(t *testing.T) {
	for backend, setup := range profileBackends() {
		t.Run(backend, func(t *testing.T) {
			cfg := setup(t)
			cfg.CacheEnabled, cfg.CachePath = true, filepath.Join(t.TempDir(), "shared-cache.db")
			ctx := context.Background()
			v := openKeyCheckVault(t, cfg)
			if err := v.Unlock(ctx, "profiles master"); err != nil {
				t.Fatal(err)
			}
			putCachedToken(t, v, "legacy default token")
			before, err := v.Remote().Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"personal", "work"} {
				if err := v.CreateProfile(ctx, name); err != nil {
					t.Fatal(err)
				}
			}
			if err := v.CreateProfile(ctx, "work"); !errors.Is(err, sylva.ErrAlreadyExists) {
				t.Fatalf("duplicate profile: %v", err)
			}
			if err := v.CreateProfile(ctx, "../invalid"); err == nil {
				t.Fatal("accepted invalid profile name")
			}
			after, err := v.Remote().GetRecordByBlindIndex(ctx, before.Records[0].BlindIndex)
			if err != nil || !bytes.Equal(after.Envelope.Ciphertext, before.Records[0].Envelope.Ciphertext) {
				t.Fatalf("profile creation rewrote default ciphertext: %v", err)
			}
			for _, name := range []string{"personal", "work"} {
				if err := v.UseProfile(ctx, name); err != nil {
					t.Fatal(err)
				}
				putCachedToken(t, v, name+" token")
				if _, err := v.LoginSet(ctx, "github.com", name+"@example.test", name+" password", false, false); err != nil {
					t.Fatal(err)
				}
			}
			foreign, err := v.GetSecret(ctx, vault.SecretTypeToken, "shared-token")
			if err != nil {
				t.Fatal(err)
			}
			if err := v.UseProfile(ctx, "personal"); err != nil {
				t.Fatal(err)
			}
			if err := v.UpdateSecret(ctx, foreign); err == nil {
				t.Fatal("updated another profile's item")
			}
			if _, err := v.LoginSet(ctx, "mail.github.com", "", "", true, false); err != nil {
				t.Fatal(err)
			}
			_, value, err := v.GetValue(ctx, "mail.github.com", vault.SecretTypeLogin, false, "")
			if err != nil || value != "personal password" {
				t.Fatalf("profile inheritance: %v", err)
			}
			profiles, err := v.ListProfiles(ctx)
			if err != nil || len(profiles) != 3 {
				t.Fatalf("profiles=%v err=%v", profiles, err)
			}
			items, err := v.ListSecrets(ctx, "")
			if err != nil || len(items) != 3 {
				t.Fatalf("list leaked another profile or descriptor: %d %v", len(items), err)
			}
			for _, name := range []string{"default", "work", "personal"} {
				if err := v.UseProfile(ctx, name); err != nil {
					t.Fatal(err)
				}
				_, value, err := v.GetValue(ctx, "shared-token", vault.SecretTypeToken, false, "")
				want := name + " token"
				if name == "default" {
					want = "legacy default token"
				}
				if err != nil || value != want {
					t.Fatalf("%s read %q: %v", name, value, err)
				}
			}
			if err := v.UseProfile(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("unknown profile: %v", err)
			}
			if err := v.DeleteSecret(ctx, vault.SecretTypeToken, "shared-token"); err != nil {
				t.Fatal(err)
			}
			if err := v.UseProfile(ctx, "work"); err != nil {
				t.Fatal(err)
			}
			if _, _, err := v.GetValue(ctx, "shared-token", vault.SecretTypeToken, false, ""); err != nil {
				t.Fatal(err)
			}
			cfg.Profile = "work"
			other := openKeyCheckVault(t, cfg)
			rootKey, err := v.CopyMasterKey()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(rootKey)
			if err := other.UnlockWithKey(ctx, rootKey); err != nil {
				t.Fatal(err)
			}
			login, err := other.GetSecret(ctx, vault.SecretTypeLogin, "github.com")
			if err != nil || login.Login.Username != "work@example.test" {
				t.Fatalf("device/profile account: %v", err)
			}
			cfg.Profile = "missing"
			unknown := openKeyCheckVault(t, cfg)
			if err := unknown.UnlockWithKey(ctx, rootKey); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("unknown profile unlocked: %v", err)
			}
			assertLocked(t, unknown)
			if backend == "git" {
				files, err := exec.Command("git", "--git-dir="+cfg.GitRemote, "ls-tree", "-r", "--name-only", "main").Output()
				if err != nil || !strings.Contains(string(files), "profiles/") {
					t.Fatalf("Git profile directories: %v", err)
				}
				for _, name := range []string{"personal", "work", "github.com"} {
					if strings.Contains(string(files), name) {
						t.Fatalf("plaintext profile/account in filename: %s", name)
					}
				}
			}
		})
	}
}

func TestProfileBackupAndRotationCoverAllProfiles(t *testing.T) {
	for backend, setup := range profileBackends() {
		t.Run(backend, func(t *testing.T) {
			cfg := setup(t)
			ctx := context.Background()
			v := openKeyCheckVault(t, cfg)
			if err := v.Unlock(ctx, "old profiles master"); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"default", "personal", "work"} {
				if name != "default" {
					if err := v.CreateProfile(ctx, name); err != nil {
						t.Fatal(err)
					}
				}
				if err := v.UseProfile(ctx, name); err != nil {
					t.Fatal(err)
				}
				putCachedToken(t, v, name+" value")
			}
			backup := filepath.Join(t.TempDir(), "profiles.backup")
			if err := v.Backup(ctx, backup); err != nil {
				t.Fatal(err)
			}
			cfg.Profile = "personal"
			stale := openKeyCheckVault(t, cfg)
			if err := stale.Unlock(ctx, "old profiles master"); err != nil {
				t.Fatal(err)
			}
			if err := v.ChangePassphrase(ctx, "new profiles master"); err != nil {
				t.Fatal(err)
			}
			if err := stale.PutSecret(ctx, &vault.SecretItem{Type: vault.SecretTypeToken, Identifier: "stale", Token: &vault.TokenPayload{Name: "stale", Token: "value"}}); !errors.Is(err, storage.ErrVaultChanged) {
				t.Fatalf("old profile session wrote after rotation: %v", err)
			}
			assertLocked(t, stale)
			if err := stale.Unlock(ctx, "old profiles master"); !errors.Is(err, sylva.ErrInvalidPassphrase) {
				t.Fatalf("old master unlocked: %v", err)
			}
			if err := stale.Unlock(ctx, "new profiles master"); err != nil {
				t.Fatal(err)
			}
			freshCfg := setup(t)
			fresh := openKeyCheckVault(t, freshCfg)
			if err := fresh.Restore(ctx, backup, "old profiles master"); err != nil {
				t.Fatal(err)
			}
			if err := fresh.Unlock(ctx, "old profiles master"); err != nil {
				t.Fatal(err)
			}
			for _, reader := range []*sylva.Vault{stale, fresh} {
				for _, name := range []string{"default", "personal", "work"} {
					if err := reader.UseProfile(ctx, name); err != nil {
						t.Fatal(err)
					}
					_, value, err := reader.GetValue(ctx, "shared-token", vault.SecretTypeToken, false, "")
					if err != nil || value != name+" value" {
						t.Fatalf("%s not recovered: %v", name, err)
					}
				}
			}
		})
	}
}

func TestProfileCacheDoesNotMixAccountsOrPruneOtherProfiles(t *testing.T) {
	cfg, _ := keyCheckServer(t)
	ctx := context.Background()
	writer := openKeyCheckVault(t, cfg)
	if err := writer.Unlock(ctx, "profile cache master"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"personal", "work"} {
		if err := writer.CreateProfile(ctx, name); err != nil {
			t.Fatal(err)
		}
		if err := writer.UseProfile(ctx, name); err != nil {
			t.Fatal(err)
		}
		putCachedToken(t, writer, name+" cache secret")
	}
	target, err := url.Parse(cfg.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(target))
	defer proxy.Close()
	cfg.ServerURL = proxy.URL
	cfg.CacheEnabled, cfg.CachePath = true, filepath.Join(t.TempDir(), "shared-profile-cache.db")
	readers := map[string]*sylva.Vault{}
	for _, name := range []string{"personal", "work"} {
		cfg.Profile = name
		reader := openKeyCheckVault(t, cfg)
		if err := reader.Unlock(ctx, "profile cache master"); err != nil {
			t.Fatal(err)
		}
		items, err := reader.ListSecrets(ctx, "")
		if err != nil || len(items) != 1 {
			t.Fatalf("warm %s cache: %v", name, err)
		}
		readers[name] = reader
	}
	proxy.Close()
	for name, reader := range readers {
		_, value, err := reader.GetValue(ctx, "shared-token", vault.SecretTypeToken, false, "")
		if err != nil || value != name+" cache secret" {
			t.Fatalf("offline %s read %q: %v", name, value, err)
		}
		items, err := reader.ListSecrets(ctx, "")
		if err != nil || len(items) != 1 || items[0].Token.Token != name+" cache secret" {
			t.Fatalf("offline %s list mixed profiles: %v", name, err)
		}
	}
}
