//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package certificates

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Keep the lock inode in place; closing it releases the advisory lock even
// after a crash, while removal could let competing issuers lock different files.
func lockUpdate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Getuid()) {
		_ = f.Close()
		return nil, errors.New("certificate lock must be a regular file owned by the current user")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another certificate update may be in progress: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
