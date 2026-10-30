package clipboard_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/clipboard"
)

func TestDesktopProbeFailuresArePreserved(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", filepath.Join(t.TempDir(), "missing-wayland"))
	t.Setenv("DISPLAY", "invalid-display")
	for _, backend := range []string{clipboard.BackendAuto, clipboard.BackendOS} {
		t.Run(backend, func(t *testing.T) {
			mgr, err := clipboard.NewManager(backend, "", time.Second)
			if mgr != nil {
				_ = mgr.Close()
				t.Fatal("failed desktop probes produced a manager")
			}
			if err == nil || !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing Wayland socket error was lost: %v", err)
			}
			for _, name := range []string{"wayland clipboard", "X11 clipboard"} {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("missing %s failure: %v", name, err)
				}
			}
		})
	}
}
