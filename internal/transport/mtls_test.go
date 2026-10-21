package transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
)

func TestMTLSRejectsPlainHTTPClient(t *testing.T) {
	_, clientCfg := startMTLSServer(t)

	plainCfg := clientCfg
	plainCfg.EnableMTLS = false
	plainCfg.CACertPath = ""
	plainCfg.ClientCertPath = ""
	plainCfg.ClientKeyPath = ""

	plain, err := transport.NewClient(plainCfg)
	if err != nil {
		t.Fatalf("plain client: %v", err)
	}
	t.Cleanup(plain.Close)

	if _, err := plain.Ping(context.Background()); err == nil {
		t.Fatal("expected ping without client certificate to fail")
	}

	okClient, err := transport.NewClient(clientCfg)
	if err != nil {
		t.Fatalf("mtls client: %v", err)
	}
	t.Cleanup(okClient.Close)
	status, err := okClient.Ping(context.Background())
	if err != nil {
		t.Fatalf("mtls ping: %v", err)
	}
	if !status.MTLS {
		t.Fatalf("expected mtls_enabled in ping")
	}
}

func TestMTLSRejectsForeignClientCert(t *testing.T) {
	_, cfg := startMTLSServer(t)
	foreign := writeMTLSBundle(t, t.TempDir(), "foreign")
	cfg.CACertPath = foreign.ca
	cfg.ClientCertPath = foreign.clientCert
	cfg.ClientKeyPath = foreign.clientKey

	client, err := transport.NewClient(cfg)
	if err != nil {
		t.Fatalf("foreign client: %v", err)
	}
	t.Cleanup(client.Close)
	if _, err := client.Ping(context.Background()); err == nil {
		t.Fatal("expected ping with foreign CA to fail")
	}
}

func TestNewClientMTLSRequiresCerts(t *testing.T) {
	_, err := transport.NewClient(config.ClientConfig{
		EnableMTLS: true,
		Timeout:    time.Second,
	})
	if err == nil {
		t.Fatal("expected error when mTLS cert paths are empty")
	}
}

func TestServeRejectsUnimplementedTailscale(t *testing.T) {
	envPath := filepath.Join("..", "..", ".env.example")
	srvCfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	srvCfg.EnableTailscale = true
	srvCfg.DBPath = filepath.Join(t.TempDir(), "sylvad.db")
	store, err := storage.OpenSQLite(srvCfg.DBPath, srvCfg.SQLiteBusyTimeout)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := transport.NewServer(srvCfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	err = srv.Serve(context.Background(), ln)
	if err == nil {
		t.Fatal("expected tailscale not implemented")
	}
}

func startMTLSServer(t *testing.T) (config.ServerConfig, config.ClientConfig) {
	t.Helper()
	envPath := filepath.Join("..", "..", ".env.example")
	bundle := writeMTLSBundle(t, t.TempDir(), "sylva")

	srvCfg, err := config.LoadServerConfig(envPath)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	srvCfg.ListenAddr = net.JoinHostPort("127.0.0.1", "0")
	srvCfg.DBPath = filepath.Join(t.TempDir(), "sylvad.db")
	srvCfg.EnableMTLS = true
	srvCfg.CACertPath = bundle.ca
	srvCfg.ServerCertPath = bundle.serverCert
	srvCfg.ServerKeyPath = bundle.serverKey

	store, err := storage.OpenSQLite(srvCfg.DBPath, srvCfg.SQLiteBusyTimeout)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := transport.NewServer(srvCfg, store, logger)
	ln, err := net.Listen("tcp", srvCfg.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-errCh; err != nil {
			t.Errorf("server shutdown error: %v", err)
		}
	})

	clientCfg, err := config.LoadClientConfig(envPath)
	if err != nil {
		t.Fatalf("load client config: %v", err)
	}
	clientCfg.Scheme = "https"
	clientCfg.EnableMTLS = true
	clientCfg.CACertPath = bundle.ca
	clientCfg.ClientCertPath = bundle.clientCert
	clientCfg.ClientKeyPath = bundle.clientKey
	clientCfg.ServerURL = "https://" + ln.Addr().String()
	waitForTLS(t, ln.Addr().String())
	return srvCfg, clientCfg
}

func waitForTLS(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not listen on %s", addr)
}

type mtlsBundle struct {
	ca, serverCert, serverKey, clientCert, clientKey string
}

func writeMTLSBundle(t *testing.T, dir, name string) mtlsBundle {
	t.Helper()
	caKey := mustKey(t)
	caCert := mustCert(t, &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: name + "-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}, nil, &caKey.PublicKey, caKey)

	serverKey := mustKey(t)
	serverCert := mustCert(t, &x509.Certificate{
		SerialNumber: mustSerial(t),
		Subject:      pkix.Name{CommonName: name + "-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}, caCert, &serverKey.PublicKey, caKey)

	clientKey := mustKey(t)
	clientCert := mustCert(t, &x509.Certificate{
		SerialNumber: mustSerial(t),
		Subject:      pkix.Name{CommonName: name + "-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, caCert, &clientKey.PublicKey, caKey)

	bundle := mtlsBundle{
		ca:         filepath.Join(dir, "ca.pem"),
		serverCert: filepath.Join(dir, "server.pem"),
		serverKey:  filepath.Join(dir, "server-key.pem"),
		clientCert: filepath.Join(dir, "client.pem"),
		clientKey:  filepath.Join(dir, "client-key.pem"),
	}
	writePEM(t, bundle.ca, "CERTIFICATE", caCert.Raw)
	writePEM(t, bundle.serverCert, "CERTIFICATE", serverCert.Raw)
	writeECKey(t, bundle.serverKey, serverKey)
	writePEM(t, bundle.clientCert, "CERTIFICATE", clientCert.Raw)
	writeECKey(t, bundle.clientKey, clientKey)
	return bundle
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

func mustCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, pub any, priv *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeECKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writePEM(t, path, "EC PRIVATE KEY", der)
}
