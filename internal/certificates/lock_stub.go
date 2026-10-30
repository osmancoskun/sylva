//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package certificates

import (
	"fmt"
	"os"
	"runtime"
)

func lockUpdate(string) (*os.File, error) {
	return nil, fmt.Errorf("certificate update locking is not supported on %s", runtime.GOOS)
}
