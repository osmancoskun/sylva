package transport

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestMergeListenersAcceptsBoth(t *testing.T) {
	a, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := mergeListeners(a, b)
	t.Cleanup(func() { _ = ln.Close() })

	got := make(chan string, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
			got <- string(buf)
			_ = c.Close()
		}
	}()

	dial := func(addr net.Addr, payload byte) {
		c, err := net.DialTimeout("tcp", addr.String(), time.Second)
		if err != nil {
			t.Errorf("dial %s: %v", addr, err)
			return
		}
		_, _ = c.Write([]byte{payload})
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}
	go dial(a.Addr(), 'a')
	go dial(b.Addr(), 'b')

	seen := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(seen) < 2 {
		select {
		case s := <-got:
			seen[s] = true
		case <-deadline:
			t.Fatalf("got %v", seen)
		}
	}
}
