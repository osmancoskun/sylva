package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
)

func TestProfileSwitchKeepsSSHSessionAndClearsClipboard(t *testing.T) {
	cfg := sshTestServer(t)
	socket, publicPath, _ := sshTestIdentity(t)
	t.Setenv("SSH_AUTH_SOCK", socket)
	cfg.AgentEnabled = true
	cfg.AgentSocketPath = filepath.Join(t.TempDir(), "agent.sock")
	cfg.ClipboardBackend, cfg.ClipboardFile = clipboard.BackendFile, filepath.Join(t.TempDir(), "clipboard")
	clip, err := clipboard.NewManager(cfg.ClipboardBackend, cfg.ClipboardFile, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx, cfg.AgentSocketPath, clip, nil) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	var ac *agent.Client
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ac, err = agent.Dial(cfg.AgentSocketPath, time.Second)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || ac == nil {
		t.Fatalf("agent did not start: %v", err)
	}
	if err := runUnlock(cfg); err != nil {
		t.Fatal(err)
	}
	if err := runSSH(cfg, []string{"add", publicPath}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"work", "personal"} {
		if err := runProfile(cfg, []string{"create", name}); err != nil {
			t.Fatal(err)
		}
	}
	if err := runLock(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.MasterPassphrase = ""
	if err := runUnlockSSH(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ac.Copy("synthetic previous-profile secret", "password", "github"); err != nil {
		t.Fatal(err)
	}
	if err := runSwitch(cfg, "work"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfg.ClipboardFile)
	if err != nil || len(raw) != 0 {
		t.Fatalf("previous profile clipboard survived switch: %v", err)
	}
	if unlocked, err := ac.Status(); err != nil || !unlocked {
		t.Fatalf("switch locked root session: %v", err)
	}
	loaded, err := config.LoadClientConfig("")
	if err != nil || loaded.Profile != "work" {
		t.Fatalf("active profile not saved: %v", err)
	}
	if err := runSwitch(cfg, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown profile switched: %v", err)
	}
	loaded, err = config.LoadClientConfig("")
	if err != nil || loaded.Profile != "work" {
		t.Fatalf("failed switch changed selection: %v", err)
	}
	cfg.Profile = "work"
	v, err := openUnlocked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	key, err := v.CopyMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := v.UseProfile(context.Background(), "personal"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYLVA_PROFILE", "work")
	if err := runSwitch(cfg, "personal"); err == nil || !strings.Contains(err.Error(), "SYLVA_PROFILE") {
		t.Fatalf("environment override silently ignored: %v", err)
	}
	if err := runLock(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := ac.MasterKey(); !errors.Is(err, agent.ErrLocked) {
		t.Fatalf("lock left root key available: %v", err)
	}
	if _, err := os.Stat(config.LocalConfigPath()); err != nil {
		t.Fatal(err)
	}
}
