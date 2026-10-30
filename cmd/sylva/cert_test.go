package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/certificates"
	"github.com/osman/sylva/internal/config"
)

func TestCertInitCreatesBundleWithoutEnablingMTLS(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := runCert("", []string{"init", "--host", "remote.example", "--host", "10.1.2.3"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key", "client.pem", "client.key"} {
		if _, err := os.Stat(filepath.Join(".sylva", "certs", name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(".sylva", "config")); !os.IsNotExist(err) {
		t.Fatalf("certificate initialization changed transport config: %v", err)
	}
	if err := runCert("", []string{"init"}); err == nil {
		t.Fatal("repeated init succeeded")
	}
}

func TestCertInitAddsOnlyJoinedLocalSylvaIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status api.StatusResponse
		code   int
		ok     bool
	}{
		{name: "joined node", status: api.StatusResponse{Tailscale: true, TailscaleDNSName: "resolved-node-2.tail-example.ts.net."}, ok: true},
		{name: "tailscale disabled", status: api.StatusResponse{TailscaleDNSName: "other.tail-example.ts.net"}},
		{name: "old daemon or no identity", status: api.StatusResponse{Tailscale: true}},
		{name: "invalid DNS", status: api.StatusResponse{Tailscale: true, TailscaleDNSName: "https://bad.example"}},
		{name: "HTTP error", code: http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.IsolateProcessEnv(t)
			t.Chdir(t.TempDir())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/ping" || r.Method != http.MethodGet {
					t.Errorf("unexpected discovery request: %s %s", r.Method, r.URL.Path)
				}
				if tc.code != 0 {
					w.WriteHeader(tc.code)
					return
				}
				if err := json.NewEncoder(w).Encode(tc.status); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(srv.Close)
			_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("SYLVA_PORT", port)
			// Discovery must stay local even if normal CLI commands target a remote server.
			t.Setenv("SYLVA_SERVER_URL", "http://must-not-contact.invalid")
			err = runCert("", []string{"init", "--add-tailscale", "--host", "extra.example"})
			if (err == nil) != tc.ok {
				t.Fatalf("expected success=%v, err=%v", tc.ok, err)
			}
			if !tc.ok {
				if _, err := os.Stat(".sylva/certs"); !os.IsNotExist(err) {
					t.Fatalf("failed discovery wrote certificates: %v", err)
				}
				return
			}
			data, err := os.ReadFile(".sylva/certs/server.pem")
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			if block == nil {
				t.Fatal("invalid server PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			for _, host := range []string{"resolved-node-2.tail-example.ts.net", "extra.example", "localhost", "sylvad", "127.0.0.1"} {
				if err := cert.VerifyHostname(host); err != nil {
					t.Errorf("missing identity %s: %v", host, err)
				}
			}
			if _, err := os.Stat(".sylva/config"); !os.IsNotExist(err) {
				t.Fatalf("discovery changed feature settings: %v", err)
			}
		})
	}
}

func TestCertRejectsInvalidArgumentsWithoutWriting(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, args := range [][]string{nil, {"renew"}, {"add-tailscale", "unexpected"}, {"add-tailscale", "--host", "other.example"}, {"init", "unexpected"}, {"init", "--host"}, {"init", "--host", "https://example.com"}, {"init", "--force"}} {
		if err := runCert("", args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	if _, err := os.Stat(".sylva"); !os.IsNotExist(err) {
		t.Fatalf("invalid command wrote files: %v", err)
	}
}

func TestCertAddTailscaleDiscoversIdentityOverExistingMTLS(t *testing.T) {
	config.IsolateProcessEnv(t)
	t.Chdir(t.TempDir())
	if err := certificates.Init(".sylva/certs", []string{"existing.example"}); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(".sylva/certs", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	rootPEM := read("ca.pem")
	before := make(map[string]string)
	for _, name := range []string{"ca.pem", "ca.key", "server.key", "client.pem", "client.key"} {
		before[name] = string(read(name))
	}
	pair, err := tls.LoadX509KeyPair(".sylva/certs/server.pem", ".sylva/certs/server.key")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid CA")
	}
	name := "actual-node-2.tail-example.ts.net"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ping" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(api.StatusResponse{Tailscale: true, MTLS: true, TailscaleDNSName: name}); err != nil {
			t.Error(err)
		}
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYLVA_PORT", port)
	if err := os.WriteFile(config.LocalConfigPath(), []byte("mtls=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCert("", []string{"add-tailscale"}); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(read("server.pem"))
	if block == nil {
		t.Fatal("invalid updated PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{name, "existing.example", "localhost", "127.0.0.1"} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	for name, want := range before {
		if string(read(name)) != want {
			t.Errorf("%s changed", name)
		}
	}
	updated := string(read("server.pem"))
	if err := os.Remove(".sylva/certs/ca.key"); err != nil {
		t.Fatal(err)
	}
	if err := runCert("", []string{"add-tailscale"}); err != nil {
		t.Fatal(err)
	}
	if string(read("server.pem")) != updated {
		t.Fatal("already-added DNS name changed the certificate")
	}
}
