package agent_test

import (
	"bytes"
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
	"github.com/osman/sylva/internal/clipboard"
)

func startCleanupAgent(t *testing.T, clip *clipboard.Manager, log *slog.Logger, opt agent.Options) *runningAgent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a := &runningAgent{socket: filepath.Join(t.TempDir(), "agent.sock"), cancel: cancel, done: make(chan error, 1)}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	go func() { a.done <- agent.Serve(ctx, a.socket, clip, log, opt) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-a.done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("agent did not stop")
		}
	})
	a.client = waitDial(t, a.socket, time.Second)
	return a
}

func TestLockReportsBothCleanupFailuresAndAllowsRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clipboard")
	clip, err := clipboard.NewManager(clipboard.BackendFile, path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	fail.Store(true)
	var deletions atomic.Int32
	a := startCleanupAgent(t, clip, nil, agent.Options{OnLock: func() error {
		deletions.Add(1)
		if fail.Load() {
			return errors.New("keyring permission denied")
		}
		return nil
	}})
	key := bytes.Repeat([]byte{5}, 32)
	if err := a.client.Unlock(key); err != nil {
		t.Fatal(err)
	}
	if err := a.client.Copy("synthetic secret", "token", "test"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err = a.client.Lock()
	if !errors.Is(err, agent.ErrCleanupIncomplete) || !strings.Contains(err.Error(), "clear clipboard") || !strings.Contains(err.Error(), "clear keyring") {
		t.Fatalf("cleanup failures hidden: %v", err)
	}
	if deletions.Load() != 1 {
		t.Fatal("clipboard failure skipped keyring cleanup")
	}
	if unlocked, err := a.client.Status(); unlocked || !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatalf("incorrect status: unlocked=%v err=%v", unlocked, err)
	}
	if got, err := a.client.MasterKey(); got != nil || !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatal("incomplete cleanup returned a key")
	}
	if err := a.client.Unlock(key); !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatal("incomplete cleanup allowed unlock")
	}
	if err := a.client.Copy("new secret", "token", "test"); !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatal("incomplete cleanup allowed copy")
	}
	if err := a.client.ScheduleClear("new secret"); !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatal("incomplete cleanup allowed scheduling")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	fail.Store(false)
	if err := a.client.Lock(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if unlocked, err := a.client.Status(); unlocked || err != nil {
		t.Fatalf("retry status: %v %v", unlocked, err)
	}
	if err := a.client.Unlock(key); err != nil {
		t.Fatalf("unlock after cleanup: %v", err)
	}
	value, err := clip.Read()
	if err != nil || value != "" {
		t.Fatal("retry did not clear clipboard")
	}
}

func TestAutomaticLockRetainsCleanupFailure(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	a := startCleanupAgent(t, nil, nil, agent.Options{IdleTimeout: 50 * time.Millisecond, OnLock: func() error {
		if fail.Load() {
			return errors.New("keyring unavailable")
		}
		return nil
	}})
	if err := a.client.Unlock(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		unlocked, err := a.client.Status()
		if errors.Is(err, agent.ErrCleanupIncomplete) {
			if unlocked {
				t.Fatal("automatic lock retained key")
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("automatic cleanup failure was not observable")
		}
		time.Sleep(5 * time.Millisecond)
	}
	fail.Store(false)
	if err := a.client.Lock(); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticClipboardFailureDoesNotClaimSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clipboard")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	clip, err := clipboard.NewManager(clipboard.BackendFile, path, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	a := startCleanupAgent(t, clip, slog.New(slog.NewTextHandler(&logs, nil)), agent.Options{IdleTimeout: time.Hour})
	if err := a.client.Unlock(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := a.client.ScheduleClear("synthetic secret"); err != nil {
		t.Fatal(err)
	}
	clip.Wait()
	if !strings.Contains(logs.String(), "automatic clipboard clear failed") || strings.Contains(logs.String(), `msg="clipboard cleared"`) {
		t.Fatal("automatic clear log was misleading")
	}
	if unlocked, err := a.client.Status(); !unlocked || !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatalf("clipboard failure status: %v %v", unlocked, err)
	}
	if key, err := a.client.MasterKey(); key != nil || !errors.Is(err, agent.ErrCleanupIncomplete) {
		t.Fatal("failed clear allowed key reuse")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := a.client.Lock(); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownReturnsCleanupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(t.TempDir(), "agent.sock")
	done := make(chan error, 1)
	go func() {
		done <- agent.Serve(ctx, socket, nil, nil, agent.Options{OnLock: func() error { return errors.New("keyring deletion denied") }})
	}()
	_ = waitDial(t, socket, time.Second)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, agent.ErrCleanupIncomplete) {
			t.Fatalf("shutdown cleanup lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("cleanup failure prevented socket removal")
	}
}
