package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCertificateUpdateLockAndRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := Init(dir, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := lockUpdate(filepath.Join(dir, ".update.lock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if changed, err := AddServerName(dir, "node.tail-example.ts.net"); err == nil || changed {
		t.Fatalf("concurrent update: changed=%v err=%v", changed, err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "server.pem"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("locked operation changed the certificate")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if changed, err := AddServerName(dir, "node.tail-example.ts.net"); err != nil || !changed {
		t.Fatalf("retry: changed=%v err=%v", changed, err)
	}
}

func TestAtomicCertificatePublicationFailureCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "server.pem")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "existing")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceServerCertificate(target, []byte("replacement")); err == nil {
		t.Fatal("expected rename failure")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "preserve" {
		t.Fatal("failed publication changed target")
	}
	files, err := filepath.Glob(filepath.Join(dir, ".server-cert-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("staged files remain: %v %v", files, err)
	}
}

func TestSigningKeySupportsLegacyOpenSSLAndPKCS8(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		der  []byte
	}{{"EC PRIVATE KEY", ecDER}, {"PRIVATE KEY", pkcs8}, {"RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)}} {
		key, err := parseSigningKey(pem.EncodeToMemory(&pem.Block{Type: tc.name, Bytes: tc.der}))
		if err != nil || key == nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}
