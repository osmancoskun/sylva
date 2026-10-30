package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/osman/sylva/internal/transport"
)

// Only connection failures may use a previously cached value. HTTP errors,
// TLS verification failures, malformed responses, and caller cancellation
// must remain visible rather than being hidden behind stale credentials.
func canReadCache(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var certificateError *tls.CertificateVerificationError
	var protocolError tls.RecordHeaderError
	var alertError tls.AlertError
	var responseError *transport.HTTPError
	if errors.As(err, &certificateError) || errors.As(err, &protocolError) || errors.As(err, &alertError) || errors.As(err, &responseError) {
		return false
	}
	var networkError *net.OpError
	if !errors.As(err, &networkError) {
		return false
	}
	return networkError.Op == "dial" || networkError.Op == "read" || networkError.Op == "write"
}

func (v *Vault) cacheForget(ctx context.Context, blindIndex string) {
	if v.cache != nil {
		if err := v.cache.DeleteByBlindIndex(ctx, blindIndex); err != nil {
			v.disableCache()
		}
	}
}

// Once cache maintenance fails, do not read a potentially stale snapshot for
// the remainder of this session. Successful server operations still succeed.
func (v *Vault) disableCache() {
	if v.cache != nil {
		_ = v.cache.Close()
		v.cache = nil
	}
}
