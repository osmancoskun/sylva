package agent_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
	"github.com/osman/sylva/internal/clipboard"
)

func TestIdleLockExpiresKeyClipboardAndKeyring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clip, err := clipboard.NewManager(clipboard.BackendMemory, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var cleared atomic.Int32
	done := make(chan error, 1)
	socket := filepath.Join(t.TempDir(), "agent.sock")
	go func() {
		done <- agent.Serve(ctx, socket, clip, slog.New(slog.NewTextHandler(io.Discard, nil)), agent.Options{IdleTimeout: 300 * time.Millisecond, OnLock: func() error { cleared.Add(1); return nil }})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := waitDial(t, socket, time.Second)
	if err := client.Unlock(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := client.Copy("secret", "token", "probe"); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		time.Sleep(60 * time.Millisecond)
		if _, err := client.MasterKey(); err != nil {
			t.Fatalf("active session expired: %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		unlocked, err := client.Status()
		if err != nil {
			t.Fatal(err)
		}
		if !unlocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("status probes prevented automatic lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := client.MasterKey(); !errors.Is(err, agent.ErrLocked) {
		t.Fatalf("expired key remained accessible: %v", err)
	}
	if value, err := clip.Read(); err != nil || value != "" {
		t.Fatalf("expired session retained clipboard: %v", err)
	}
	if cleared.Load() == 0 {
		t.Fatal("auto-lock did not clear the keyring")
	}
	if err := client.Unlock(make([]byte, 31)); err == nil {
		t.Fatal("invalid key length accepted")
	}
	if err := client.Unlock(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := client.Copy("secret", "token", "probe"); err != nil {
		t.Fatal(err)
	}
	if err := client.Lock(); err != nil {
		t.Fatal(err)
	}
	if value, err := clip.Read(); err != nil || value != "" {
		t.Fatalf("manual lock retained clipboard: %v", err)
	}
}
