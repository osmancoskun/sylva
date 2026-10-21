package clipboard

import (
	"testing"
	"time"
)

func TestSkipClearWhenContentsChanged(t *testing.T) {
	mgr, err := NewManager(BackendMemory, "", 40*time.Millisecond)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := mgr.Copy("first-secret"); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := mgr.backend.Write("user-replaced"); err != nil {
		t.Fatalf("replace clipboard: %v", err)
	}
	mgr.Wait()
	got, err := mgr.Read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "user-replaced" {
		t.Fatalf("expected user replacement to be kept, got %q", got)
	}
}
