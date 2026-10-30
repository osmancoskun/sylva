package certificates

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// AddServerName reissues only server.pem under the same CA and server key,
// keeping existing identities, extensions and validity dates. An already
// covered name is a no-op and does not require the CA signing key.
func AddServerName(dir, name string) (bool, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if !validDNSName(name) || net.ParseIP(name) != nil {
		return false, fmt.Errorf("invalid Tailscale DNS name %q", name)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, errors.New("certificate directory must be a real directory, not a symlink")
	}
	lock, err := lockUpdate(filepath.Join(dir, ".update.lock"))
	if err != nil {
		return false, err
	}
	defer lock.Close()

	caPEM, err := readPEMFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return false, err
	}
	caBlock, rest := pem.Decode(caPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return false, errors.New("ca.pem must contain exactly one CA certificate")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse CA certificate: %w", err)
	}
	serverPath := filepath.Join(dir, "server.pem")
	serverPEM, err := readPEMFile(serverPath)
	if err != nil {
		return false, err
	}
	serverKey, err := readPEMFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return false, err
	}
	defer clear(serverKey)
	pair, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		return false, fmt.Errorf("server certificate/key mismatch: %w", err)
	}
	server, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if server.IsCA || server.CheckSignatureFrom(ca) != nil {
		return false, errors.New("server.pem must be a leaf certificate signed by ca.pem")
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		return false, fmt.Errorf("existing server certificate is not valid for server authentication: %w", err)
	}
	if server.VerifyHostname(name) == nil {
		return false, nil
	}

	caKeyPEM, err := readPEMFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return false, fmt.Errorf("CA signing key required; make ca.key available locally for this operation: %w", err)
	}
	defer clear(caKeyPEM)
	signer, err := parseSigningKey(caKeyPEM)
	if err != nil {
		return false, err
	}
	template := *server
	template.SerialNumber = nil
	template.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	template.DNSNames = append(append([]string(nil), server.DNSNames...), name)
	// Preserve extensions verbatim except SAN, which is extended below. This
	// also retains SAN types not exposed by x509.Certificate's parsed fields.
	for _, extension := range server.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			var names []asn1.RawValue
			if remaining, err := asn1.Unmarshal(extension.Value, &names); err != nil || len(remaining) != 0 {
				return false, errors.New("cannot preserve existing server SAN extension")
			}
			names = append(names, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(name)})
			extension.Value, err = asn1.Marshal(names)
			if err != nil {
				return false, err
			}
		}
		template.ExtraExtensions = append(template.ExtraExtensions, extension)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, ca, server.PublicKey, signer)
	if err != nil {
		return false, fmt.Errorf("sign server certificate with existing CA: %w", err)
	}
	updated, err := x509.ParseCertificate(der)
	if err != nil {
		return false, err
	}
	if _, err := updated.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
		return false, fmt.Errorf("verify updated server certificate: %w", err)
	}
	// Keep any existing PEM chain after the leaf.
	_, chain := pem.Decode(serverPEM)
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), chain...)
	if err := replaceServerCertificate(serverPath, data); err != nil {
		return false, err
	}
	return true, nil
}

func readPEMFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Certificate/key files are small; bound reads even if a file grows.
	const maxPEMBytes = 1 << 20
	data, readErr := io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
	if err := errors.Join(readErr, f.Close()); err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > maxPEMBytes {
		clear(data)
		return nil, fmt.Errorf("%s exceeds the 1 MiB PEM file limit", path)
	}
	return data, nil
}

func parseSigningKey(data []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("ca.key must contain exactly one unencrypted private key")
	}
	defer clear(block.Bytes)
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("ca.key must be an unencrypted PKCS#8, EC or RSA private key")
	}
	if err != nil {
		return nil, fmt.Errorf("parse CA signing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca.key cannot sign certificates")
	}
	return signer, nil
}

func replaceServerCertificate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".server-cert-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
