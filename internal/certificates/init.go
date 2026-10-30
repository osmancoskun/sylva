// Package certificates creates private mTLS bundles and extends server identities.
package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Init creates a CA and separate server/client key pairs in a new directory.
// Existing directories (including symlinks) are never reused. Additional hosts
// extend the localhost, sylvad, 127.0.0.1 and ::1 server identities.
func Init(dir string, hosts []string) (err error) {
	dns, ips, err := serverNames(hosts)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("certificate directory %s already exists; refusing to replace it", dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Sylva local CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	files := make(map[string][]byte)
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	if err := addPair(files, "ca", caDER, caKey); err != nil {
		return err
	}
	for _, name := range []string{"server", "client"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		leaf := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "Sylva " + name},
			NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if name == "server" {
			leaf.DNSNames, leaf.IPAddresses = dns, ips
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err := addPair(files, name, der, key); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	// Mkdir also rejects a competing init that won the race after Lstat.
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(dir))
		}
	}()
	for name, data := range files {
		if err := writeNew(filepath.Join(dir, name), data); err != nil {
			return fmt.Errorf("write certificate bundle: %w", err)
		}
	}
	return nil
}

func addPair(files map[string][]byte, name string, der []byte, key *ecdsa.PrivateKey) error {
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(privateDER)
	files[name+".pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	files[name+".key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}

func serverNames(hosts []string) ([]string, []net.IP, error) {
	dns := []string{"localhost", "sylvad"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	seen := map[string]bool{"localhost": true, "sylvad": true, "127.0.0.1": true, "::1": true}
	for _, raw := range hosts {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsUnspecified() {
				return nil, nil, fmt.Errorf("host %q is a bind address; supply the DNS name or IP clients dial", raw)
			}
			if !seen[ip.String()] {
				ips = append(ips, ip)
				seen[ip.String()] = true
			}
			continue
		}
		if !validDNSName(host) {
			return nil, nil, fmt.Errorf("invalid host %q: expected a DNS name or IP without scheme, port or path", raw)
		}
		if !seen[host] {
			dns = append(dns, host)
			seen[host] = true
		}
	}
	return dns, ips, nil
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
