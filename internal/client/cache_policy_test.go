package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/osman/sylva/internal/transport"
)

func TestCacheFallbackRejectsTLSAndAuthorizationFailures(t *testing.T) {
	for name, err := range map[string]error{
		"certificate":   &tls.CertificateVerificationError{Err: errors.New("untrusted certificate")},
		"protocol":      tls.RecordHeaderError{Msg: "invalid TLS record"},
		"TLS alert":     tls.AlertError(116),
		"authorization": &transport.HTTPError{Status: 403},
	} {
		t.Run(name, func(t *testing.T) {
			// Even when wrapped as a socket read failure, a TLS or permission
			// error must not be turned into permission to read cached secrets.
			err = fmt.Errorf("request failed: %w", &net.OpError{Op: "read", Net: "tcp", Err: err})
			if canReadCache(context.Background(), err) {
				t.Fatal("security failure allowed cached secrets")
			}
		})
	}
}
