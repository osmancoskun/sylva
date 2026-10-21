//go:build !linux

package clipboard

import (
	"fmt"
	"runtime"
)

func newOS() (Backend, error) {
	return nil, fmt.Errorf("os clipboard talks to X11/Wayland sockets and is not supported on %s", runtime.GOOS)
}

func startOSClipboard(kind, text string, lost func()) (clipboardHolder, error) {
	return nil, fmt.Errorf("os clipboard is not supported on %s", runtime.GOOS)
}
