package transport

import (
	"errors"
	"net"
	"sync"
)

type acceptResult struct {
	conn net.Conn
	err  error
}

// fanInListener Accepts from several listeners until Close.
type fanInListener struct {
	listeners []net.Listener
	ch        chan acceptResult
	closeOnce sync.Once
	closed    chan struct{}
}

func mergeListeners(listeners ...net.Listener) net.Listener {
	f := &fanInListener{
		listeners: listeners,
		ch:        make(chan acceptResult),
		closed:    make(chan struct{}),
	}
	for _, ln := range listeners {
		go f.acceptLoop(ln)
	}
	return f
}

func (f *fanInListener) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		select {
		case <-f.closed:
			if conn != nil {
				_ = conn.Close()
			}
			return
		case f.ch <- acceptResult{conn: conn, err: err}:
			if err != nil {
				return
			}
		}
	}
}

func (f *fanInListener) Accept() (net.Conn, error) {
	select {
	case <-f.closed:
		return nil, net.ErrClosed
	case res, ok := <-f.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return res.conn, res.err
	}
}

func (f *fanInListener) Close() error {
	var err error
	f.closeOnce.Do(func() {
		close(f.closed)
		for _, ln := range f.listeners {
			if e := ln.Close(); e != nil && !errors.Is(e, net.ErrClosed) && err == nil {
				err = e
			}
		}
	})
	return err
}

func (f *fanInListener) Addr() net.Addr {
	if len(f.listeners) == 0 {
		return nil
	}
	return f.listeners[0].Addr()
}
