package clipboard_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/leakcheck"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func TestMemoryCopyAutoClears(t *testing.T) {
	mgr, err := clipboard.NewManager(clipboard.BackendMemory, "", 40*time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	if err := mgr.Copy("company-secret"); err != nil {
		t.Fatalf("copy: %v", err)
	}
	got, err := mgr.Read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "company-secret" {
		t.Fatalf("got %q, want company-secret", got)
	}

	mgr.Wait()
	got, err = mgr.Read()
	if err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	if got != "" {
		t.Fatalf("expected clipboard to be cleared, got %q", got)
	}
}

func TestFileBackendRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clip.txt")
	mgr, err := clipboard.NewManager(clipboard.BackendFile, path, 40*time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	if err := mgr.Copy("file-secret"); err != nil {
		t.Fatalf("copy: %v", err)
	}
	got, err := mgr.Read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "file-secret" {
		t.Fatalf("got %q, want file-secret", got)
	}

	mgr.Wait()
	got, err = mgr.Read()
	if err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	if got != "" {
		t.Fatalf("expected file clipboard to be cleared, got %q", got)
	}
}

func TestUnknownBackendRejected(t *testing.T) {
	_, err := clipboard.NewManager("ftp", "", time.Second)
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
