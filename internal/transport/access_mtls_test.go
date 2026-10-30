package transport_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
)

func TestRemoteMTLSProtectsEveryEndpoint(t *testing.T) {
	_, cfg := startMTLSServerAt(t, "0.0.0.0:0")
	valid, err := transport.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	ctx := context.Background()
	if err := valid.PutSalt(ctx, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	item := &vault.SecretItem{ID: "protected", Type: vault.SecretTypeToken, Identifier: "protected", Token: &vault.TokenPayload{Name: "protected", Token: "synthetic test value"}}
	rec, err := vault.Seal(make([]byte, 32), item, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := valid.PutRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	foreign := writeMTLSBundle(t, t.TempDir(), "untrusted-client")
	foreignCert, err := tls.LoadX509KeyPair(foreign.clientCert, foreign.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, tlsCfg := range map[string]*tls.Config{
		"no client certificate":        {RootCAs: roots, MinVersion: tls.VersionTLS13},
		"untrusted client certificate": {RootCAs: roots, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{foreignCert}},
		"TLS 1.2":                      {RootCAs: roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
	} {
		t.Run(name, func(t *testing.T) {
			// Trust the actual server CA, so a failure cannot be explained
			// merely by the client rejecting the server certificate.
			tr := &http.Transport{TLSClientConfig: tlsCfg}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: time.Second}
			for _, ep := range api.HTTPEndpoints() {
				t.Run(ep.Name, func(t *testing.T) {
					path := strings.ReplaceAll(ep.AbsPath(cfg.APIPrefix), "{id}", item.ID)
					req, err := http.NewRequestWithContext(ctx, ep.Method, cfg.ServerURL+path, strings.NewReader("{}"))
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Do(req)
					if resp != nil {
						defer resp.Body.Close()
					}
					if err == nil {
						t.Fatalf("unauthorized request reached HTTP endpoint: %s", ep.Name)
					}
				})
			}
		})
	}
	got, err := valid.GetRecord(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != item.ID || got.Version != rec.Version {
		t.Fatal("unauthorized requests changed the record")
	}
	salt, err := valid.GetSalt(ctx)
	if err != nil || len(salt) != 16 {
		t.Fatalf("authorized client lost access to vault salt: %v", err)
	}
}
