package transport

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestExplainTransportMessages(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"remote error: tls: certificate required", "client certificate"},
		{"tls: failed to verify certificate: x509: certificate signed by unknown authority", "does not trust"},
		{"remote error: tls: bad certificate", "rejected this client certificate"},
	}
	for _, tc := range cases {
		got := explainTransport(errors.New(tc.in)).Error()
		if !strings.Contains(got, tc.want) {
			t.Errorf("explain(%q) = %q, want substring %q", tc.in, got, tc.want)
		}
	}
}

func TestExplainStatusHTTPOnHTTPS(t *testing.T) {
	t.Parallel()
	err := explainStatus(&HTTPError{Status: http.StatusBadRequest, Body: "Client sent an HTTP request to an HTTPS server."})
	if err == nil || !strings.Contains(err.Error(), "sent HTTP") {
		t.Fatalf("got %v", err)
	}
}
