package clipboard_test

import (
	"testing"
	"time"

	"github.com/osman/sylva/internal/clipboard"
)

func TestDesktopBackendsRejectHeadlessEnvironment(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	for _, backend := range []string{clipboard.BackendAuto, clipboard.BackendOS} {
		t.Run(backend, func(t *testing.T) {
			mgr, err := clipboard.NewManager(backend, "", time.Second)
			if mgr != nil {
				_ = mgr.Close()
				t.Fatal("unavailable desktop clipboard produced a manager")
			}
			if err == nil {
				t.Fatal("unavailable desktop clipboard must return an error")
			}
		})
	}
}

func TestExplicitMemoryBackendWorksWithoutDesktop(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	mgr, err := clipboard.NewManager(clipboard.BackendMemory, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := mgr.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := mgr.Copy("headless-test-secret"); err != nil {
		t.Fatal(err)
	}
	if got, err := mgr.Read(); err != nil || got != "headless-test-secret" {
		t.Fatalf("memory copy: got=%q err=%v", got, err)
	}
}
