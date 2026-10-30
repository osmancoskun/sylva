package clipboard_test

import (
	"testing"
	"time"

	"github.com/osman/sylva/internal/clipboard"
)

// Long timers must be canceled on Close, including replaced clear operations.
func TestRepeatedCopyAndCloseStopsPendingClears(t *testing.T) {
	for range 50 {
		mgr, err := clipboard.NewManager(clipboard.BackendMemory, "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for range 20 {
			if err := mgr.Copy("test secret"); err != nil {
				_ = mgr.Close()
				t.Fatal(err)
			}
		}
		if err := mgr.Close(); err != nil {
			t.Fatal(err)
		}
		mgr.Wait()
	}
}

func BenchmarkClipboardLifecycle(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mgr, err := clipboard.NewManager(clipboard.BackendMemory, "", time.Hour)
		if err != nil {
			b.Fatal(err)
		}
		if err := mgr.Copy("synthetic benchmark secret"); err != nil {
			_ = mgr.Close()
			b.Fatal(err)
		}
		if err := mgr.Close(); err != nil {
			b.Fatal(err)
		}
		mgr.Wait()
	}
}
