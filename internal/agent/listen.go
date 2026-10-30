package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func listenAgent(path string) (*net.UnixListener, func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	lock, err := lockSocket(path + ".lock")
	if err != nil {
		return nil, nil, err
	}
	if err := removeStaleSocket(path); err != nil {
		_ = lock.Close()
		return nil, nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		_ = lock.Close()
		return nil, nil, fmt.Errorf("listen on agent socket: %w", err)
	}
	ln.SetUnlinkOnClose(false)
	info, err := os.Lstat(path)
	release := func() error {
		closeErr := ln.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
		current, statErr := os.Lstat(path)
		var removeErr error
		if statErr == nil && info != nil && os.SameFile(info, current) {
			removeErr = os.Remove(path)
		}
		if os.IsNotExist(statErr) {
			statErr = nil
		}
		return errors.Join(closeErr, statErr, removeErr, lock.Close())
	}
	if err != nil {
		return nil, nil, errors.Join(err, release())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, nil, errors.Join(err, release())
	}
	return ln, release, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket agent path %s", path)
	}
	// Also protect agents from older versions which did not take the file lock.
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return ErrAlreadyRunning
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !os.IsNotExist(err) {
		return fmt.Errorf("probe existing agent socket: %w", err)
	}
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) {
		return errors.New("agent socket changed during startup")
	}
	return os.Remove(path)
}
