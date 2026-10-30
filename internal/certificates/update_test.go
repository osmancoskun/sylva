package certificates_test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/osman/sylva/internal/certificates"
)

func bundleFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key", "client.pem", "client.key"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(data)
	}
	return files
}

func changeServer(t *testing.T, dir string, change func(*x509.Certificate)) {
	t.Helper()
	ca := readCert(t, dir, "ca")
	issuer := loadPair(t, dir, "ca")
	cert := readCert(t, dir, "server")
	cert.SerialNumber = nil
	change(cert)
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, cert.PublicKey, issuer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAddServerNamePreservesBundleAndExistingIdentities(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := certificates.Init(dir, []string{"existing.example", "10.1.2.3"}); err != nil {
		t.Fatal(err)
	}
	changeServer(t, dir, func(cert *x509.Certificate) {
		cert.EmailAddresses = []string{"service@example.test"}
		cert.URIs = []*url.URL{{Scheme: "spiffe", Host: "example.test", Path: "/sylva"}}
		cert.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
	})
	before := bundleFiles(t, dir)
	old := readCert(t, dir, "server")
	name := "node-2.tail-example.ts.net"
	changed, err := certificates.AddServerName(dir, name)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	after := bundleFiles(t, dir)
	for file, data := range before {
		if file != "server.pem" && after[file] != data {
			t.Errorf("%s changed", file)
		}
	}
	cert := readCert(t, dir, "server")
	if !cert.NotBefore.Equal(old.NotBefore) || !cert.NotAfter.Equal(old.NotAfter) || !bytes.Equal(cert.RawSubject, old.RawSubject) || cert.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Fatal("validity/subject changed or serial was reused")
	}
	if !reflect.DeepEqual(cert.EmailAddresses, old.EmailAddresses) || !reflect.DeepEqual(cert.URIs, old.URIs) {
		t.Fatal("non-DNS SANs were lost")
	}
	for _, ext := range old.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		found := false
		for _, current := range cert.Extensions {
			if ext.Id.Equal(current.Id) && ext.Critical == current.Critical && bytes.Equal(ext.Value, current.Value) {
				found = true
			}
		}
		if !found {
			t.Errorf("lost extension %s", ext.Id)
		}
	}
	for _, host := range append(old.DNSNames, name, "127.0.0.1", "::1", "10.1.2.3") {
		if err := cert.VerifyHostname(host); err != nil {
			t.Errorf("host %s: %v", host, err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(readCert(t, dir, "ca"))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{loadPair(t, dir, "server")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: name, Certificates: []tls.Certificate{loadPair(t, dir, "client")}}}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	res, err := client.Get(srv.URL)
	if res != nil {
		_ = res.Body.Close()
	}
	if err != nil {
		t.Fatalf("old client cannot authenticate new server identity: %v", err)
	}
	// An already-covered name must not require bringing the offline CA key back.
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if changed, err := certificates.AddServerName(dir, name); err != nil || changed {
		t.Fatalf("repeated add: changed=%v err=%v", changed, err)
	}
	current := bundleFiles(t, dir)
	if current["server.pem"] != after["server.pem"] {
		t.Fatal("already-covered name reissued the server certificate")
	}
}

func TestAddServerNameFailuresLeaveBundleUntouched(t *testing.T) {
	foreign := filepath.Join(t.TempDir(), "certs")
	if err := certificates.Init(foreign, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "missing CA key", mutate: func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "foreign CA key", mutate: func(t *testing.T, dir string) { copyBundleFile(t, foreign, dir, "ca.key") }},
		{name: "foreign CA", mutate: func(t *testing.T, dir string) { copyBundleFile(t, foreign, dir, "ca.pem") }},
		{name: "wrong server key", mutate: func(t *testing.T, dir string) { copyBundleFile(t, foreign, dir, "server.key") }},
		{name: "malformed signing key", mutate: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("invalid PEM"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized certificate", mutate: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "server.pem"), make([]byte, (1<<20)+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "expired certificate", mutate: func(t *testing.T, dir string) {
			changeServer(t, dir, func(cert *x509.Certificate) {
				cert.NotBefore = time.Now().Add(-2 * time.Hour)
				cert.NotAfter = time.Now().Add(-time.Hour)
			})
		}},
		{name: "wrong certificate purpose", mutate: func(t *testing.T, dir string) {
			changeServer(t, dir, func(cert *x509.Certificate) { cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })
		}},
		{name: "symlink target", mutate: func(t *testing.T, dir string) {
			if err := os.Rename(filepath.Join(dir, "server.pem"), filepath.Join(dir, "original.pem")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("original.pem", filepath.Join(dir, "server.pem")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "certs")
			if err := certificates.Init(dir, nil); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, dir)
			before := bundleFiles(t, dir)
			if changed, err := certificates.AddServerName(dir, "node.tail-example.ts.net"); err == nil || changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if !reflect.DeepEqual(before, bundleFiles(t, dir)) {
				t.Fatal("failed operation changed a bundle file")
			}
			temps, err := filepath.Glob(filepath.Join(dir, ".server-cert-*"))
			if err != nil || len(temps) != 0 {
				t.Fatalf("temporary files left: %v err=%v", temps, err)
			}
		})
	}
}

func copyBundleFile(t *testing.T, from, to, name string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(from, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
