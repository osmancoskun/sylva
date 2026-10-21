package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/osman/sylva/internal/config"
)

func loadCertPool(caPath string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("parse CA certificate %s: no certificates found", caPath)
	}
	return pool, nil
}

func serverTLSConfig(cfg config.ServerConfig) (*tls.Config, error) {
	if cfg.CACertPath == "" || cfg.ServerCertPath == "" || cfg.ServerKeyPath == "" {
		return nil, fmt.Errorf("mTLS enabled but SYLVA_CA_CERT_PATH, SYLVA_SERVER_CERT_PATH, and SYLVA_SERVER_KEY_PATH are required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	pool, err := loadCertPool(cfg.CACertPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func clientTLSConfig(cfg config.ClientConfig) (*tls.Config, error) {
	if cfg.CACertPath == "" || cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" {
		return nil, fmt.Errorf("mTLS enabled but SYLVA_CA_CERT_PATH, SYLVA_CLIENT_CERT_PATH, and SYLVA_CLIENT_KEY_PATH are required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	pool, err := loadCertPool(cfg.CACertPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}
