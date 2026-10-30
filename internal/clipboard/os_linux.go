package clipboard

import (
	"errors"
	"fmt"
	"os"
)

func newOS() (Backend, error) {
	var probeErr error
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		if err := probeWaylandClipboard(); err == nil {
			return &osBackend{kind: "wayland"}, nil
		} else {
			probeErr = errors.Join(probeErr, fmt.Errorf("wayland clipboard: %w", err))
		}
	}
	if os.Getenv("DISPLAY") != "" {
		if err := probeX11Clipboard(); err == nil {
			return &osBackend{kind: "x11"}, nil
		} else {
			probeErr = errors.Join(probeErr, fmt.Errorf("X11 clipboard: %w", err))
		}
	}
	return nil, errors.Join(errors.New("os clipboard unavailable: requires an X11 DISPLAY or a Wayland compositor with wlr-data-control"), probeErr)
}

func startOSClipboard(kind, text string, lost func()) (clipboardHolder, error) {
	switch kind {
	case "wayland":
		return startWaylandClipboard(text, lost)
	case "x11":
		return startX11Clipboard(text, lost)
	default:
		return nil, fmt.Errorf("unknown os clipboard kind %q", kind)
	}
}
