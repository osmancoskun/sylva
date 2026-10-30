package transport

import (
	"errors"
	"fmt"
	"net"
)

// ErrInsecureListener prevents unauthenticated vault access outside loopback.
var ErrInsecureListener = errors.New("unprotected remote listener")

// Check the actual bound address, rather than a hostname or configured flag.
// Tailnet trust is supplied only by Start after opening the tsnet listener.
func (s *Server) validateListener(ln net.Listener, tailnet bool) error {
	if ln == nil {
		return errors.New("server listener cannot be nil")
	}
	if s.cfg.EnableMTLS || tailnet {
		return nil
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if ok && addr != nil && addr.IP.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%w: HTTP requires a loopback listener (127.0.0.1 or ::1); enable mTLS for LAN/public listeners, or start the embedded Tailscale listener", ErrInsecureListener)
}
