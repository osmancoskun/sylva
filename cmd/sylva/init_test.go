package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/sshunlock"
	"github.com/osman/sylva/internal/storage"
)

func scriptedSetup(t *testing.T, lines, passwords []string) (setupPrompts, *[]string) {
	t.Helper()
	labels := new([]string)
	p := setupPrompts{
		line: func(label string) (string, error) {
			*labels = append(*labels, label)
			if len(lines) == 0 {
				return "", io.EOF
			}
			answer := lines[0]
			lines = lines[1:]
			return answer, nil
		},
		password: func(label string) (string, error) {
			*labels = append(*labels, label)
			if len(passwords) == 0 {
				return "", io.EOF
			}
			answer := passwords[0]
			passwords = passwords[1:]
			return answer, nil
		},
	}
	return p, labels
}

func setupConfigFile(t *testing.T, extra string) []byte {
	t.Helper()
	raw := []byte("agent_enabled=false\nclient_cache_enabled=false\nkeyring_enabled=false\nkdf_time=1\nkdf_memory_kb=1024\nkdf_threads=1\npassword_default_len=32\n" + extra)
	if err := os.WriteFile(config.LocalConfigPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func requireUnchangedSetup(t *testing.T, before []byte) {
	t.Helper()
	after, err := os.ReadFile(config.LocalConfigPath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed setup changed configuration: %v", err)
	}
}

func TestSetupWizardCreatesGitVaultAndSelectedProfile(t *testing.T) {
	config.IsolateProcessEnv(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	if output, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("init test remote: %v %s", err, output)
	}
	// Wizard must bootstrap Git even if the previous HTTP configuration cannot
	// currently load because its certificate is unavailable.
	setupConfigFile(t, "mtls=true\nca_cert_path=missing.pem\n")
	p, labels := scriptedSetup(t, []string{"2", remote, "", "work", "n", "y"}, []string{"wizard master", "wizard master"})
	if err := runSetupWizard("", initOverrides{}, p); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backend != "git" || cfg.Profile != "work" || cfg.GitRemote != remote || cfg.EnableMTLS || cfg.Crypto.PasswordDefaultLen != 32 {
		t.Fatalf("incorrect wizard configuration: backend=%s profile=%s", cfg.Backend, cfg.Profile)
	}
	raw, err := os.ReadFile(config.LocalConfigPath())
	if err != nil || bytes.Contains(raw, []byte("wizard master")) {
		t.Fatalf("password persisted in configuration: %v", err)
	}
	info, err := os.Stat(config.LocalConfigPath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("setup configuration permissions: %v", err)
	}
	if !strings.Contains(strings.Join(*labels, "\n"), "Confirm master passphrase") {
		t.Fatal("new vault did not require passphrase confirmation")
	}
	v, err := sylva.OpenForCommand(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Unlock(context.Background(), "wizard master"); err != nil {
		t.Fatal(err)
	}
	profiles, err := v.ListProfiles(context.Background())
	if err != nil || len(profiles) != 2 || profiles[1].Name != "work" {
		t.Fatalf("selected profile was not initialized: %v", err)
	}
}

func TestSetupWizardReusesExistingVaultWithoutChangingMaster(t *testing.T) {
	cfg := sshTestServer(t)
	v, err := sylva.OpenForCommand(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ctx := context.Background()
	if err := v.Unlock(ctx, cfg.MasterPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := v.CreateProfile(ctx, "personal"); err != nil {
		t.Fatal(err)
	}
	before, err := v.Remote().Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setupConfigFile(t, "")
	p, labels := scriptedSetup(t, []string{"self-hosted", cfg.ServerURL, "n", "personal", "n", "y"}, []string{cfg.MasterPassphrase})
	if err := runSetupWizard("", initOverrides{}, p); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(*labels, "\n"), "Confirm master") {
		t.Fatal("existing master passphrase was treated as a new one")
	}
	loaded, err := config.LoadClientConfig("")
	if err != nil || loaded.Profile != "personal" || loaded.ServerURL != cfg.ServerURL {
		t.Fatalf("existing source/profile not selected: %v", err)
	}
	after, err := v.Remote().Snapshot(ctx)
	if err != nil || before.Revision != after.Revision || !bytes.Equal(before.Salt, after.Salt) {
		t.Fatalf("wizard rewrote an existing vault: %v", err)
	}
}

func TestSetupWizardFailuresPreserveLocalConfiguration(t *testing.T) {
	for _, scenario := range []string{"cancel", "wrong password", "confirmation mismatch", "offline", "environment conflict", "input EOF", "invalid SSH file then EOF"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := sshTestServer(t)
			ctx := context.Background()
			v, err := sylva.OpenForCommand(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if scenario == "wrong password" {
				if err := v.Unlock(ctx, cfg.MasterPassphrase); err != nil {
					t.Fatal(err)
				}
			}
			before := setupConfigFile(t, "")
			lines := []string{"1", cfg.ServerURL, "n", "work", "n", "y"}
			passwords := []string{"first master", "first master"}
			switch scenario {
			case "cancel":
				lines[len(lines)-1] = "n"
				passwords = nil
			case "wrong password":
				passwords = []string{"incorrect master"}
			case "confirmation mismatch":
				passwords = []string{"first master", "different master"}
			case "offline":
				lines = []string{"git", filepath.Join(t.TempDir(), "missing.git"), "", "work", "n", "y"}
				passwords = nil
			case "environment conflict":
				t.Setenv("SYLVA_PROFILE", "personal")
				passwords = nil
			case "input EOF":
				lines = lines[:2]
				passwords = nil
			case "invalid SSH file then EOF":
				lines = []string{"1", cfg.ServerURL, "n", "work", "y", filepath.Join(t.TempDir(), "missing.pub")}
				passwords = nil
			}
			p, _ := scriptedSetup(t, lines, passwords)
			err = runSetupWizard("", initOverrides{}, p)
			if scenario == "cancel" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid setup succeeded")
			}
			requireUnchangedSetup(t, before)
			if scenario != "wrong password" {
				if _, err := v.Remote().GetSalt(ctx); !errors.Is(err, storage.ErrNotFound) {
					t.Fatalf("failed setup initialized remote salt: %v", err)
				}
			}
		})
	}
}

func TestSetupWizardEnrollsSSHUsingVerifiedMaster(t *testing.T) {
	cfg := sshTestServer(t)
	socket, publicPath, _ := sshTestIdentity(t)
	t.Setenv("SSH_AUTH_SOCK", socket)
	_ = sshTestSession(t, &cfg)
	setupConfigFile(t, "agent_enabled=true\nagent_socket_path="+cfg.AgentSocketPath+"\nssh_unlock_dir="+cfg.SSHUnlockDir+"\n")
	badPath := filepath.Join(t.TempDir(), "invalid.pub")
	if err := os.WriteFile(badPath, []byte("not a public key"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, labels := scriptedSetup(t, []string{"1", cfg.ServerURL, "n", "work", "y", filepath.Join(t.TempDir(), "osman"), badPath, publicPath, "y"}, []string{"SSH wizard master", "SSH wizard master"})
	if err := runSetupWizard("", initOverrides{}, p); err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.Join(*labels, "\n"), "Ed25519 public-key file (.pub)") != 3 {
		t.Fatal("invalid SSH files were not retried in the same setup step")
	}
	loaded, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	path, endpoint := sshRegistration(loaded)
	if _, err := sshunlock.Fingerprint(path, endpoint); err != nil {
		t.Fatal(err)
	}
	registration, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, labels = scriptedSetup(t, []string{"1", cfg.ServerURL, "n", "work", "y", publicPath, "y"}, []string{"SSH wizard master"})
	if err := runSetupWizard("", initOverrides{}, p); err != nil {
		t.Fatalf("repeating setup with the same SSH registration: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(registration, after) {
		t.Fatalf("repeated setup changed the existing SSH registration: %v", err)
	}
	if strings.Contains(strings.Join(*labels, "\n"), "Confirm master") {
		t.Fatal("repeated setup asked to create a new master passphrase")
	}
	if err := runLock(loaded); err != nil {
		t.Fatal(err)
	}
	if err := runUnlockSSH(loaded); err != nil {
		t.Fatal(err)
	}
}

func TestSetupSSHRejectsUnusableRegistrationsWithoutReplacingThem(t *testing.T) {
	for _, scenario := range []string{"different key", "stale vault key", "corrupt registration", "locked SSH agent"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := sshTestServer(t)
			socket, publicPath, ring := sshTestIdentity(t)
			t.Setenv("SSH_AUTH_SOCK", socket)
			v, err := sylva.OpenForCommand(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if err := v.Unlock(context.Background(), cfg.MasterPassphrase); err != nil {
				t.Fatal(err)
			}
			publicKey, err := readSSHUnlockPublicKey(publicPath)
			if err != nil {
				t.Fatal(err)
			}
			path, endpoint := sshRegistration(cfg)
			if err := enrollVerifiedSSH(cfg, v, publicKey, path, endpoint); err != nil {
				t.Fatal(err)
			}
			wantError := ""
			switch scenario {
			case "different key":
				_, differentPath, _ := sshTestIdentity(t)
				publicKey, err = readSSHUnlockPublicKey(differentPath)
				if err != nil {
					t.Fatal(err)
				}
				wantError = "different key"
			case "stale vault key":
				if err := v.ChangePassphrase(context.Background(), "rotated wizard master"); err != nil {
					t.Fatal(err)
				}
				wantError = "does not match the current vault key"
			case "corrupt registration":
				if err := os.WriteFile(path, []byte("invalid registration"), 0o600); err != nil {
					t.Fatal(err)
				}
				wantError = "read existing SSH registration"
			case "locked SSH agent":
				if err := ring.Lock([]byte("test lock")); err != nil {
					t.Fatal(err)
				}
				wantError = "verify existing SSH unlock"
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			keyBefore, err := v.CopyMasterKey()
			if err != nil {
				t.Fatal(err)
			}
			defer crypto.ZeroBytes(keyBefore)
			if err := ensureVerifiedSSH(cfg, v, publicKey, path, endpoint); err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("unusable registration was not rejected: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected registration was changed: %v", err)
			}
			keyAfter, err := v.CopyMasterKey()
			if err != nil {
				t.Fatal(err)
			}
			defer crypto.ZeroBytes(keyAfter)
			if !bytes.Equal(keyBefore, keyAfter) {
				t.Fatal("SSH setup changed the verified master key")
			}
		})
	}
}

func TestNonInteractiveInitKeepsSaltOnlyBehavior(t *testing.T) {
	cfg := sshTestServer(t)
	before := setupConfigFile(t, "server_url="+cfg.ServerURL+"\n")
	if err := runInitCommand("", []string{"--non-interactive"}, initOverrides{}); err != nil {
		t.Fatal(err)
	}
	requireUnchangedSetup(t, before)
	v, err := sylva.OpenForCommand(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := v.Remote().GetKeyCheck(context.Background()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("non-interactive init established a master password: %v", err)
	}
	for _, args := range [][]string{{"--wizard", "--non-interactive"}, {"unexpected"}, {"--unknown"}} {
		if err := runInitCommand("", args, initOverrides{}); err == nil {
			t.Fatalf("accepted invalid init arguments: %v", args)
		}
	}
}
