package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/config"
)

func TestUnavailableClipboardDoesNotReportCopySuccess(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = out
	t.Cleanup(func() {
		os.Stdout = previous
		_ = out.Close()
	})
	cfg := config.ClientConfig{
		ClipboardBackend:    clipboard.BackendAuto,
		ClipboardClearAfter: time.Second,
	}
	if err := copyToClipboard(cfg, "password", "test", "never-print-this-secret"); err == nil {
		t.Fatal("copy succeeded without a desktop clipboard")
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("failed copy printed output: %q", data)
	}
}

func TestAgentLogsClipboardInitializationFailure(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	cfg := config.ClientConfig{
		AgentLogPath:        filepath.Join(t.TempDir(), "agent.log"),
		ClipboardBackend:    clipboard.BackendAuto,
		ClipboardClearAfter: time.Second,
	}
	if err := runAgent(cfg); err == nil {
		t.Fatal("agent started without a desktop clipboard")
	}
	data, err := os.ReadFile(cfg.AgentLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "initialize agent clipboard") {
		t.Fatalf("clipboard initialization failure missing from log: %s", data)
	}
}
