package certificates_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/osman/sylva/internal/certificates"
	"github.com/osman/sylva/internal/leakcheck"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func readCert(t *testing.T, dir, name string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func loadPair(t *testing.T, dir, name string) tls.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestGeneratedBundleIdentitiesAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := certificates.Init(dir, []string{"Vault.Example.", "10.1.2.3", "::1", "localhost"}); err != nil {
		t.Fatal(err)
	}
	root := readCert(t, dir, "ca")
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		t.Fatal("invalid self-signed CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	server := readCert(t, dir, "server")
	for _, name := range []string{"localhost", "sylvad", "127.0.0.1", "::1", "vault.example", "10.1.2.3"} {
		if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("server identity %s: %v", name, err)
		}
	}
	if server.VerifyHostname("other.example") == nil {
		t.Fatal("unexpected server identity accepted")
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: server.NotAfter.Add(time.Second)}); err == nil {
		t.Fatal("expired server certificate accepted")
	}
	client := readCert(t, dir, "client")
	if _, err := client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Verify(x509.VerifyOptions{Roots: roots}); err == nil {
		t.Fatal("client certificate accepted for server authentication")
	}
	seen := make(map[string]bool)
	for _, name := range []string{"ca", "server", "client"} {
		loadPair(t, dir, name)
		cert := readCert(t, dir, name)
		serial := cert.SerialNumber.String()
		if cert.SerialNumber.Sign() <= 0 || seen[serial] {
			t.Fatal("invalid or duplicate serial number")
		}
		seen[serial] = true
		for _, suffix := range []string{".pem", ".key"} {
			info, err := os.Stat(filepath.Join(dir, name+suffix))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("%s%s permissions: %v %v", name, suffix, info, err)
			}
		}
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory permissions: %v %v", info, err)
	}
}

func TestGeneratedBundleMutualTLS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := certificates.Init(dir, nil); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(readCert(t, dir, "ca"))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{loadPair(t, dir, "server")},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	foreign := filepath.Join(t.TempDir(), "certs")
	if err := certificates.Init(foreign, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		pair []tls.Certificate
		max  uint16
		ok   bool
	}{
		{name: "valid client", pair: []tls.Certificate{loadPair(t, dir, "client")}, ok: true},
		{name: "no certificate"},
		{name: "foreign CA", pair: []tls.Certificate{loadPair(t, foreign, "client")}},
		{name: "wrong purpose", pair: []tls.Certificate{loadPair(t, dir, "server")}},
		{name: "TLS 1.2", pair: []tls.Certificate{loadPair(t, dir, "client")}, max: tls.VersionTLS12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, MaxVersion: tc.max,
				RootCAs: roots, Certificates: tc.pair,
			}}
			t.Cleanup(tr.CloseIdleConnections)
			client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
			res, err := client.Get(srv.URL)
			if res != nil {
				_ = res.Body.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("expected success=%v, err=%v", tc.ok, err)
			}
		})
	}
}

func TestInitPreservesExistingDirectoryAndSymlink(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory", true: "symlink"}[symlink], func(t *testing.T) {
			parent := t.TempDir()
			existing := filepath.Join(parent, "existing")
			if err := certificates.Init(existing, nil); err != nil {
				t.Fatal(err)
			}
			dir := existing
			if symlink {
				dir = filepath.Join(parent, "link")
				if err := os.Symlink(existing, dir); err != nil {
					t.Fatal(err)
				}
			}
			before := make(map[string]string)
			files, err := os.ReadDir(existing)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				data, err := os.ReadFile(filepath.Join(existing, f.Name()))
				if err != nil {
					t.Fatal(err)
				}
				before[f.Name()] = string(data)
			}
			if err := certificates.Init(dir, []string{"new.example"}); err == nil {
				t.Fatal("existing directory was reused")
			}
			for name, want := range before {
				got, err := os.ReadFile(filepath.Join(existing, name))
				if err != nil || string(got) != want {
					t.Fatalf("existing %s was changed: %v", name, err)
				}
			}
		})
	}
}

func TestInvalidHostsLeaveNoBundle(t *testing.T) {
	for _, host := range []string{"", "https://vault.example", "example:8443", "host/path", "*.example", "0.0.0.0", "::", "bad..host", "-bad", "bad_", "[::1]"} {
		dir := filepath.Join(t.TempDir(), "certs")
		if err := certificates.Init(dir, []string{host}); err == nil {
			t.Errorf("invalid host %q accepted", host)
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Errorf("invalid host %q created output: %v", host, err)
		}
	}
}

func TestConcurrentInitKeepsOneCompleteBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- certificates.Init(dir, nil)
		}()
	}
	wg.Wait()
	close(errors)
	success := 0
	for err := range errors {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly one initializer, got %d", success)
	}
	for _, name := range []string{"ca", "server", "client"} {
		loadPair(t, dir, name)
	}
}
