package clipboard

import (
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"testing"
)

type releaseConn struct {
	net.Conn
	err   error
	calls int
}

func (c *releaseConn) Close() error { c.calls++; return c.err }

func TestX11HolderDoesNotHideFailedCloseOnRetry(t *testing.T) {
	failure := errors.New("connection close failed")
	c := &releaseConn{err: failure}
	h := &x11Holder{xc: &x11Conn{c: c}, done: make(chan struct{})}
	for range 2 {
		if err := h.Close(); !errors.Is(err, failure) {
			t.Fatal("failed release disappeared")
		}
	}
	c.err = nil
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if c.calls != 3 {
		t.Fatal("failed connection close was not retried")
	}
}

func TestWaylandHolderReportsNotificationFailureAndClosesConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wl.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialUnix("unix", nil, ln.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	h := &waylandHolder{w: &wlConn{c: client}, done: make(chan struct{}), device: 1, source: 2}
	if err := h.Close(); err == nil {
		t.Fatal("failed Wayland release notification was hidden")
	}
	if err := h.Close(); err != nil {
		t.Fatalf("already closed connection should be idempotent: %v", err)
	}
	h.w.fds = []int{-1}
	if err := h.Close(); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("closed connection hid descriptor cleanup failure: %v", err)
	}
}
