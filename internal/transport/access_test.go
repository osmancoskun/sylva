package transport_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/transport"
)

type rejectedListener struct {
	addr     net.Addr
	accepted bool
	closed   bool
}

func (l *rejectedListener) Accept() (net.Conn, error) {
	l.accepted = true
	return nil, errors.New("unexpected Accept call")
}
func (l *rejectedListener) Close() error   { l.closed = true; return nil }
func (l *rejectedListener) Addr() net.Addr { return l.addr }

func TestHTTPRejectsRemoteListenersBeforeAccept(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.1", "100.64.0.1", "2001:db8::1", "::ffff:192.0.2.1"} {
		for _, tailscaleFlag := range []bool{false, true} {
			t.Run(host+"/tailscale="+strconv.FormatBool(tailscaleFlag), func(t *testing.T) {
				ln := &rejectedListener{addr: &net.TCPAddr{IP: net.ParseIP(host), Port: 8443}}
				// A configured loopback address or Tailscale flag must not bless
				// a different, externally supplied network listener.
				cfg := config.ServerConfig{ListenAddr: "127.0.0.1:8443", EnableTailscale: tailscaleFlag}
				srv := transport.NewServer(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
				if err := srv.Serve(context.Background(), ln); !errors.Is(err, transport.ErrInsecureListener) {
					t.Fatalf("unprotected listener accepted: %v", err)
				}
				if ln.accepted || !ln.closed {
					t.Fatalf("rejected listener: accepted=%v closed=%v", ln.accepted, ln.closed)
				}
			})
		}
	}
}

func TestHTTPAllowsOnlyActualLoopbackAddresses(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			ln := &rejectedListener{addr: &net.TCPAddr{IP: net.ParseIP(host), Port: 8443}}
			srv := transport.NewServer(config.ServerConfig{}, nil, nil)
			if err := srv.Serve(context.Background(), ln); errors.Is(err, transport.ErrInsecureListener) {
				t.Fatal(err)
			}
			if !ln.accepted || !ln.closed {
				t.Fatal("loopback listener was not served and closed")
			}
		})
	}
}

func TestInvalidMTLSCannotFallBackToHTTP(t *testing.T) {
	ln := &rejectedListener{addr: &net.TCPAddr{IP: net.IPv4zero, Port: 8443}}
	srv := transport.NewServer(config.ServerConfig{EnableMTLS: true}, nil, nil)
	if err := srv.Serve(context.Background(), ln); err == nil {
		t.Fatal("mTLS without certificates was accepted")
	}
	if ln.accepted || !ln.closed {
		t.Fatal("invalid mTLS configuration served requests or leaked its listener")
	}
}

func TestHTTPRejectsUnknownOrMissingListenerAddress(t *testing.T) {
	var typedNil *net.TCPAddr
	for _, addr := range []net.Addr{nil, typedNil, &net.UnixAddr{Name: "socket", Net: "unix"}} {
		ln := &rejectedListener{addr: addr}
		srv := transport.NewServer(config.ServerConfig{}, nil, nil)
		if err := srv.Serve(context.Background(), ln); !errors.Is(err, transport.ErrInsecureListener) {
			t.Fatalf("unknown listener address accepted: %v", err)
		}
	}
	srv := transport.NewServer(config.ServerConfig{}, nil, nil)
	if err := srv.Serve(context.Background(), nil); err == nil {
		t.Fatal("nil listener accepted")
	}
}

func TestStartRejectsWildcardHTTP(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0"} {
		t.Run(addr, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			srv := transport.NewServer(config.ServerConfig{ListenAddr: addr}, nil, nil)
			if err := srv.Start(ctx); !errors.Is(err, transport.ErrInsecureListener) {
				t.Fatalf("Start accepted wildcard HTTP: %v", err)
			}
		})
	}
}
