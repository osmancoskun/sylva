package clipboard

import (
	"fmt"
	"os"
)

func newOS() (Backend, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		if err := probeWaylandClipboard(); err == nil {
			return &osBackend{kind: "wayland"}, nil
		}
	}
	if os.Getenv("DISPLAY") != "" {
		if err := probeX11Clipboard(); err == nil {
			return &osBackend{kind: "x11"}, nil
		}
	}
	return nil, fmt.Errorf("os clipboard requires an X11 DISPLAY or a Wayland compositor with wlr-data-control")
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
