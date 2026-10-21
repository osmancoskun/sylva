package agent_test

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/leakcheck"
	"github.com/osman/sylva/internal/vault"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func TestAgentUnlockLockAndClipboardClear(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "agent.sock")
	clip, err := clipboard.NewManager(clipboard.BackendMemory, "", 40*time.Millisecond)
	if err != nil {
		t.Fatalf("clipboard: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	errCh := make(chan error, 1)
	go func() { errCh <- agent.Serve(ctx, socket, clip, logger) }()

	client := waitDial(t, socket, 2*time.Second)

	unlocked, err := client.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if unlocked {
		t.Fatal("expected locked agent")
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	if err := client.Unlock(key); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	got, err := client.MasterKey()
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("got key %q", got)
	}

	if err := client.Copy("clipboard-secret", string(vault.SecretTypeLogin), "clipboard.probe"); err != nil {
		t.Fatalf("agent copy: %v", err)
	}
	if !strings.Contains(logs.String(), `type=login`) || !strings.Contains(logs.String(), `identifier=clipboard.probe`) || !strings.Contains(logs.String(), "secret copied to clipboard") {
		t.Fatalf("expected copy log for login clipboard.probe, got %s", logs.String())
	}
	clip.Wait()
	if !strings.Contains(logs.String(), "clipboard cleared") {
		t.Fatalf("expected clipboard cleared log, got %s", logs.String())
	}
	text, err := clip.Read()
	if err != nil {
		t.Fatalf("read clipboard: %v", err)
	}
	if text != "" {
		t.Fatalf("expected clipboard cleared via agent, got %q", text)
	}

	if err := client.Lock(); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, err := client.MasterKey(); err == nil {
		t.Fatal("expected locked master key error")
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not shut down")
	}
}

func TestMemoryKeyringRoundTrip(t *testing.T) {
	kr := &agent.MemoryKeyring{}
	if _, err := kr.Get(); err == nil {
		t.Fatal("expected empty keyring error")
	}
	if err := kr.Set("passphrase"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := kr.Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "passphrase" {
		t.Fatalf("got %q", got)
	}
	if err := kr.Delete(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := kr.Get(); err == nil {
		t.Fatal("expected empty keyring after delete")
	}
}

func waitDial(t *testing.T, socket string, timeout time.Duration) *agent.Client {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		c, err := agent.Dial(socket, 200*time.Millisecond)
		if err == nil {
			return c
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dial agent: %v", last)
	return nil
}
