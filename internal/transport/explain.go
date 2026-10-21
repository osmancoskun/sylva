package transport

import (
	"fmt"
	"net/http"
	"strings"
)

const mtlsDocs = "see docs/mtls.md"

func explainRequestError(reqURL string, err error) error {
	return fmt.Errorf("request to %s failed: %w", reqURL, explainTransport(err))
}

func explainStatus(he *HTTPError) error {
	if he == nil {
		return nil
	}
	if he.Status == http.StatusBadRequest && strings.Contains(he.Body, "HTTP request to an HTTPS server") {
		return fmt.Errorf("sylvad is in HTTPS/mTLS mode but this client sent HTTP. Set SYLVA_SCHEME=https and SYLVA_MTLS_ENABLED=true with certificate paths (%s): %w", mtlsDocs, he)
	}
	return he
}

func explainTransport(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "certificate required"):
		return fmt.Errorf("sylvad requires a client certificate (mTLS). Set SYLVA_MTLS_ENABLED=true and SYLVA_CA_CERT_PATH, SYLVA_CLIENT_CERT_PATH, SYLVA_CLIENT_KEY_PATH (%s): %w", mtlsDocs, err)
	case strings.Contains(msg, "unknown authority") || strings.Contains(msg, "certificate signed by unknown"):
		return fmt.Errorf("this client does not trust sylvad's certificate. Point SYLVA_CA_CERT_PATH at the same CA used by the server (%s): %w", mtlsDocs, err)
	case strings.Contains(msg, "bad certificate") || strings.Contains(msg, "certificate unknown"):
		return fmt.Errorf("sylvad rejected this client certificate. Issue it from the same CA as the server (%s): %w", mtlsDocs, err)
	default:
		return err
	}
}
