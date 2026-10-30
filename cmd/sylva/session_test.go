package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
)

func TestUnlockOnlyPublishesVerifiedKeyToAgent(t *testing.T) {
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
	defer store.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := transport.NewServer(sc, store, log)
	go func() { done <- srv.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	cfg.ServerURL = "http://" + ln.Addr().String()
	cfg.CacheEnabled = false
	cfg.KeyringEnabled = false
	cfg.AgentEnabled = true
	cfg.AgentSocketPath = filepath.Join(t.TempDir(), "agent.sock")
	cfg.Crypto.KDFMemoryKB = 1024
	cfg.Crypto.KDFTime = 1
	cfg.Crypto.KDFThreads = 1
	cfg.MasterPassphrase = "correct passphrase"

	agentCtx, stopAgent := context.WithCancel(context.Background())
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Serve(agentCtx, cfg.AgentSocketPath, nil, log) }()
	defer func() {
		stopAgent()
		if err := <-agentDone; err != nil {
			t.Error(err)
		}
	}()
	var ac *agent.Client
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ac, err = agent.Dial(cfg.AgentSocketPath, time.Second)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := runUnlock(cfg); err != nil {
		t.Fatal(err)
	}
	if unlocked, err := ac.Status(); err != nil || !unlocked {
		t.Fatalf("correct unlock: unlocked=%v err=%v", unlocked, err)
	}
	if err := ac.Lock(); err != nil {
		t.Fatal(err)
	}
	cfg.MasterPassphrase = "wrong passphrase"
	if err := runUnlock(cfg); !errors.Is(err, sylva.ErrInvalidPassphrase) {
		t.Fatalf("wrong unlock: %v", err)
	}
	if unlocked, err := ac.Status(); err != nil || unlocked {
		t.Fatalf("failed unlock changed agent: unlocked=%v err=%v", unlocked, err)
	}
	if _, err := ac.MasterKey(); !errors.Is(err, agent.ErrLocked) {
		t.Fatalf("failed unlock exposed a key: %v", err)
	}
}

func TestMasterPassphraseRejectsRedirectedInput(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("secret\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = previous }()
	if _, err := promptMasterPassphrase("Master passphrase: "); err == nil {
		t.Fatal("redirected master passphrase accepted")
	}
	pos, err := f.Seek(0, 1)
	if err != nil || pos != 0 {
		t.Fatalf("redirected input was consumed: pos=%d err=%v", pos, err)
	}
}
