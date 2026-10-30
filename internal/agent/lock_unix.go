//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package agent

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Keep this file in place after unlock: removing it would let contenders lock
// different inodes. CLOEXEC prevents detached children from retaining the lock.
func lockSocket(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open agent lock: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Getuid()) {
		_ = f.Close()
		return nil, errors.New("agent lock must be a regular file owned by the current user")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("lock agent socket: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
