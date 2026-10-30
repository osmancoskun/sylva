//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package agent

import (
	"fmt"
	"os"
	"runtime"
)

func lockSocket(string) (*os.File, error) {
	return nil, fmt.Errorf("session-agent file locking is not supported on %s", runtime.GOOS)
}
