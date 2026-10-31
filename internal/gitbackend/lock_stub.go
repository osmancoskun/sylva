//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package gitbackend

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

func lockRepository(context.Context, string) (*os.File, error) {
	return nil, fmt.Errorf("git cache file locking is not supported on %s", runtime.GOOS)
}
