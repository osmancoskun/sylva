package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func sshTestServer(t *testing.T) config.ClientConfig {
	t.Helper()
	config.IsolateProcessEnv(t)
	sc, err := config.LoadServerConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadClientConfig("")
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
	server := transport.NewServer(sc, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { done <- server.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	cfg.ServerURL = "http://" + ln.Addr().String()
	cfg.CacheEnabled = false
	cfg.KeyringEnabled = false
	cfg.MasterPassphrase = "synthetic-shared-master-passphrase"
	cfg.Crypto.KDFMemoryKB = 1024
	cfg.Crypto.KDFTime = 1
	cfg.Crypto.KDFThreads = 1
	cfg.SSHUnlockDir = filepath.Join(t.TempDir(), "ssh")
	return cfg
}

func sshTestIdentity(t *testing.T) (string, string, sshagent.Agent) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring := sshagent.NewKeyring()
	if err := ring.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	publicPath := filepath.Join(directory, "key.pub")
	if err := os.WriteFile(publicPath, ssh.MarshalAuthorizedKey(public), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "ssh.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_ = sshagent.ServeAgent(ring, conn)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return socket, publicPath, ring
}

func sshTestSession(t *testing.T, cfg *config.ClientConfig) *agent.Client {
	t.Helper()
	cfg.AgentEnabled = true
	cfg.AgentSocketPath = filepath.Join(t.TempDir(), "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.Serve(ctx, cfg.AgentSocketPath, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client, err := agent.Dial(cfg.AgentSocketPath, time.Second)
		if err == nil {
			return client
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Sylva session agent did not start")
	return nil
}

func TestSSHUnlockAcrossDevicesAndMasterRotation(t *testing.T) {
	cfg := sshTestServer(t)
	ctx := context.Background()
	source, err := sylva.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.Unlock(ctx, cfg.MasterPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := source.PutSecret(ctx, &vault.SecretItem{
		Type: vault.SecretTypeToken, Identifier: "github",
		Token: &vault.TokenPayload{Name: "github", Token: "synthetic-github-secret"},
	}); err != nil {
		t.Fatal(err)
	}
	deviceA, deviceB := cfg, cfg
	deviceB.SSHUnlockDir = filepath.Join(t.TempDir(), "ssh")
	for _, device := range []*config.ClientConfig{&deviceA, &deviceB} {
		socket, publicPath, ring := sshTestIdentity(t)
		t.Setenv("SSH_AUTH_SOCK", socket)
		ac := sshTestSession(t, device)
		if err := runSSH(*device, []string{"add", publicPath}); err != nil {
			t.Fatal(err)
		}
		device.MasterPassphrase = "" // SSH unlock must work without this secret.
		if err := runUnlockCommand(*device, []string{"--ssh"}); err != nil {
			t.Fatal(err)
		}
		reader, err := openUnlocked(*device)
		if err != nil {
			t.Fatal(err)
		}
		_, got, readErr := reader.GetValue(ctx, "github", vault.SecretTypeToken, false, "")
		_ = reader.Close()
		if readErr != nil || got != "synthetic-github-secret" {
			t.Fatalf("second-device read: err=%v", readErr)
		}
		if err := runLock(*device); err != nil {
			t.Fatal(err)
		}
		if _, err := ac.MasterKey(); !errors.Is(err, agent.ErrLocked) {
			t.Fatal("SSH-unlocked key survived sylva lock")
		}
		if err := ring.Lock([]byte("test SSH agent lock")); err != nil {
			t.Fatal(err)
		}
		if err := runUnlockSSH(*device); err == nil {
			t.Fatal("locked SSH agent unlocked Sylva")
		}
		if _, err := ac.MasterKey(); !errors.Is(err, agent.ErrLocked) {
			t.Fatal("failed SSH unlock changed the Sylva session")
		}
		if err := ring.Unlock([]byte("test SSH agent lock")); err != nil {
			t.Fatal(err)
		}
		if err := runSSH(*device, []string{"status"}); err != nil {
			t.Fatal(err)
		}
	}
	// device B's SSH socket remains selected. Neither its local credential nor
	// the old master passphrase may unlock after the server rotates the key.
	if err := source.ChangePassphrase(ctx, "new-master-passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := runUnlockSSH(deviceB); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("old SSH credential was not rejected after rotation: %v", err)
	}
	deviceB.MasterPassphrase = "new-master-passphrase"
	if err := runUnlockCommand(deviceB, nil); err != nil {
		t.Fatalf("master passphrase fallback failed: %v", err)
	}
	if err := runLock(deviceB); err != nil {
		t.Fatal(err)
	}
	if err := runSSH(deviceB, []string{"remove"}); err != nil {
		t.Fatal(err)
	}
	if err := runUnlockSSH(deviceB); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed local SSH credential still usable: %v", err)
	}
}

func TestSSHEnrollmentRequiresTheMasterPassphrase(t *testing.T) {
	cfg := sshTestServer(t)
	socket, publicPath, _ := sshTestIdentity(t)
	t.Setenv("SSH_AUTH_SOCK", socket)
	if err := runSSH(cfg, []string{"add", publicPath}); err == nil || !strings.Contains(err.Error(), "initialize the master") {
		t.Fatalf("SSH enrollment initialized a new vault: %v", err)
	}
	v, err := sylva.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Unlock(context.Background(), cfg.MasterPassphrase); err != nil {
		t.Fatal(err)
	}
	cfg.MasterPassphrase = "wrong master passphrase"
	if err := runSSH(cfg, []string{"add", publicPath}); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("wrong master passphrase enrolled an SSH key: %v", err)
	}
	path, _ := sshRegistration(cfg)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed enrollment wrote a credential")
	}
	if err := runUnlockCommand(cfg, []string{"--sshh"}); err == nil {
		t.Fatal("unknown unlock option silently used the master password")
	}
}

func TestGitBackendCLIAndSSHUnlock(t *testing.T) {
	config.IsolateProcessEnv(t)
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Backend, cfg.GitBranch = "git", "main"
	cfg.GitRemote = filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", cfg.GitRemote).CombinedOutput(); err != nil {
		t.Fatalf("create test remote: %v: %s", err, out)
	}
	cfg.CacheEnabled, cfg.KeyringEnabled = false, false
	cfg.Timeout = 30 * time.Second
	cfg.Crypto.KDFMemoryKB, cfg.Crypto.KDFTime, cfg.Crypto.KDFThreads = 1024, 1, 1
	cfg.SSHUnlockDir = filepath.Join(t.TempDir(), "ssh")
	cfg.MasterPassphrase = "synthetic Git CLI master"
	socket, publicPath, _ := sshTestIdentity(t)
	t.Setenv("SSH_AUTH_SOCK", socket)
	_ = sshTestSession(t, &cfg)
	if err := runPing(cfg); err != nil {
		t.Fatal(err)
	}
	if err := runInit(cfg); err != nil {
		t.Fatal(err)
	}
	if err := runUnlock(cfg); err != nil {
		t.Fatal(err)
	}
	if err := runSSH(cfg, []string{"add", publicPath}); err != nil {
		t.Fatal(err)
	}
	if err := runLock(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.MasterPassphrase = ""
	if err := runUnlockSSH(cfg); err != nil {
		t.Fatal(err)
	}
	v, err := openUnlocked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()
	path, _ := sshRegistration(cfg)
	other := cfg
	other.GitBranch = "other"
	otherPath, _ := sshRegistration(other)
	if path == otherPath {
		t.Fatal("different Git vaults share an SSH unlock registration")
	}
}
