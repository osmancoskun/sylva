package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
	"github.com/osman/sylva/internal/config"
)

type failingDeleteKeyring struct {
	err     error
	deleted bool
}

func (k *failingDeleteKeyring) Set(string) error     { return nil }
func (k *failingDeleteKeyring) Get() (string, error) { return "", errors.New("empty") }
func (k *failingDeleteKeyring) Delete() error        { k.deleted = true; return k.err }

func TestLockAttemptsBothCleanupTargets(t *testing.T) {
	keyringErr := errors.New("keyring deletion denied")
	agentErr := errors.New("agent cleanup failed")
	kr := &failingDeleteKeyring{err: keyringErr}
	called := false
	err := lockSession(kr, func() error { called = true; return agentErr })
	if !kr.deleted || !called || !errors.Is(err, keyringErr) || !errors.Is(err, agentErr) {
		t.Fatalf("cleanup skipped or errors lost: %v", err)
	}
}

func TestFailedLockNeverPrintsSuccess(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old; _ = r.Close(); _ = w.Close() })
	err = runLock(config.ClientConfig{AgentEnabled: true, AgentSocketPath: filepath.Join(t.TempDir(), "agent.sock"), Timeout: 0})
	_ = w.Close()
	os.Stdout = old
	out, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err == nil || strings.Contains(string(out), "Session locked") {
		t.Fatalf("failed lock reported success: %v %s", err, out)
	}
}

func TestPendingCleanupPreventsConfiguredPassphraseFallback(t *testing.T) {
	config.IsolateProcessEnv(t)
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.CacheEnabled = false
	cfg.AgentEnabled = true
	cfg.KeyringEnabled = false
	cfg.ServerURL = "http://127.0.0.1:1"
	cfg.MasterPassphrase = "synthetic configured passphrase"
	cfg.AgentSocketPath = filepath.Join(t.TempDir(), "agent.sock")
	var fail atomic.Bool
	fail.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.Serve(ctx, cfg.AgentSocketPath, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), agent.Options{OnLock: func() error {
			if fail.Load() {
				return errors.New("keyring cleanup failed")
			}
			return nil
		}})
	}()
	t.Cleanup(func() {
		fail.Store(false)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("agent did not stop")
		}
	})
	var ac *agent.Client
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ac, err = agent.Dial(cfg.AgentSocketPath, time.Second)
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil || ac == nil {
		t.Fatal("agent did not start")
	}
	if err := ac.Unlock(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := ac.Lock(); !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatal(err)
	}
	v, err := openUnlocked(cfg)
	if v != nil {
		_ = v.Close()
		t.Fatal("cleanup failure returned an unlocked vault")
	}
	if !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatalf("configured passphrase bypassed cleanup: %v", err)
	}
	if err := runUnlock(cfg); !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatalf("unlock bypassed cleanup: %v", err)
	}
}
