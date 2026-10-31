// Package sshunlock protects a local copy of a verified vault key using a
// deterministic Ed25519 signature from ssh-agent. It never reads a private key
// file or changes the server's master-passphrase protection.
package sshunlock

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osman/sylva/internal/crypto"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const format = "sylva-ssh-unlock-v1"
const maxFileBytes = 16 * 1024

// Signer is the only SSH agent operation needed to unlock a registered key.
type Signer interface {
	Sign(ssh.PublicKey, []byte) (*ssh.Signature, error)
}

type header struct {
	Format    string `json:"format"`
	Endpoint  string `json:"endpoint"`
	PublicKey []byte `json:"public_key"`
	Salt      []byte `json:"salt"`
}

type registration struct {
	header
	Envelope *crypto.Envelope `json:"envelope"`
}

// Endpoint binds a registration to both the server and its configured API.
func Endpoint(serverURL, apiPrefix string) string {
	return strings.TrimRight(serverURL, "/") + "\x00" + strings.TrimRight(apiPrefix, "/")
}

// Path keeps registrations for different servers separate on this device.
func Path(directory, endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return filepath.Join(directory, hex.EncodeToString(sum[:])+".json")
}

// Connect uses the existing ssh-agent socket with a bounded operation deadline.
// The caller must close the returned connection. Agent confirmation policies
// are preserved; an agent refusal is returned to the caller.
func Connect(socket string, timeout time.Duration) (Signer, io.Closer, error) {
	if socket == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK is not set; load your registered key with ssh-add")
	}
	if timeout <= 0 {
		return nil, nil, errors.New("SSH agent timeout must be positive")
	}
	conn, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to SSH agent: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return agent.NewClient(conn), conn, nil
}

// ParsePublicKey accepts exactly one ordinary Ed25519 public key. Certificates,
// FIDO keys, RSA and ECDSA are deliberately outside this format's contract.
func ParsePublicKey(raw []byte) (ssh.PublicKey, error) {
	if len(raw) > maxFileBytes {
		return nil, errors.New("SSH public key file is too large")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse SSH public key: %w", err)
	}
	if len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("provide a single SSH public key without authorized_keys options")
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("SSH unlock supports ordinary ssh-ed25519 keys only")
	}
	return key, nil
}

// Register wraps a caller-verified master key and publishes it without replacing
// an existing registration. Neither the signature nor wrapping key is stored.
func Register(path, endpoint string, publicKey ssh.PublicKey, masterKey []byte, signer Signer) error {
	if publicKey == nil || publicKey.Type() != ssh.KeyAlgoED25519 || len(masterKey) != sha256.Size || endpoint == "" {
		return errors.New("SSH registration requires an Ed25519 key, endpoint and 32-byte vault key")
	}
	salt, err := crypto.GenerateSalt(32)
	if err != nil {
		return err
	}
	h := header{Format: format, Endpoint: endpoint, PublicKey: publicKey.Marshal(), Salt: salt}
	key, err := wrappingKey(h, publicKey, signer)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	// Check that this particular agent returns repeatable signatures before
	// committing any credential to disk. Registration can require two approvals.
	second, err := wrappingKey(h, publicKey, signer)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(second)
	if subtle.ConstantTimeCompare(key, second) != 1 {
		return errors.New("SSH agent signatures are not deterministic; use the master passphrase")
	}
	aad, err := json.Marshal(h)
	if err != nil {
		return err
	}
	envelope, err := crypto.Encrypt(key, masterKey, aad)
	if err != nil {
		return err
	}
	return publish(path, registration{header: h, Envelope: envelope})
}

// Open unwraps the local key. The caller MUST verify it against the live server
// before installing it in a session, and must zero it after use.
func Open(path, endpoint string, signer Signer) ([]byte, error) {
	file, publicKey, err := read(path, endpoint)
	if err != nil {
		return nil, err
	}
	key, err := wrappingKey(file.header, publicKey, signer)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)
	aad, err := json.Marshal(file.header)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Decrypt(key, file.Envelope, aad)
	if err != nil {
		return nil, errors.New("SSH registration could not be authenticated; register it again using the master passphrase")
	}
	if len(plain) != sha256.Size {
		crypto.ZeroBytes(plain)
		return nil, errors.New("invalid SSH-wrapped vault key")
	}
	return plain, nil
}

// Fingerprint inspects the local registration without contacting an agent.
func Fingerprint(path, endpoint string) (string, error) {
	_, key, err := read(path, endpoint)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(key), nil
}

func wrappingKey(h header, publicKey ssh.PublicKey, signer Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("SSH agent is unavailable")
	}
	aad, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	digest := sha512.Sum512(aad)
	// OpenSSH PROTOCOL.sshsig section 3: this namespace and preamble prevent
	// these signatures from being accepted as SSH login or other file signatures.
	data := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace string
		Reserved  string
		Hash      string
		Digest    []byte
	}{Namespace: format, Hash: "sha512", Digest: digest[:]})...)
	signature, err := signer.Sign(publicKey, data)
	if err != nil {
		return nil, fmt.Errorf("SSH agent could not use the registered key: %w", err)
	}
	if signature == nil {
		return nil, errors.New("SSH agent returned no signature")
	}
	defer crypto.ZeroBytes(signature.Blob)
	if signature.Format != ssh.KeyAlgoED25519 || len(signature.Blob) != ed25519.SignatureSize {
		return nil, errors.New("SSH agent returned an unsupported signature")
	}
	if err := publicKey.Verify(data, signature); err != nil {
		return nil, fmt.Errorf("verify SSH agent signature: %w", err)
	}
	return hkdf.Key(sha256.New, signature.Blob, h.Salt, format, sha256.Size)
}

func read(path, endpoint string) (*registration, ssh.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxFileBytes {
		return nil, nil, errors.New("SSH registration must be a private regular file (0600) no larger than 16 KiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileBytes+1))
	decoder.DisallowUnknownFields()
	var out registration
	if err := decoder.Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("read SSH registration: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, errors.New("unexpected data after SSH registration")
	}
	if out.Format != format || out.Endpoint != endpoint || len(out.Salt) != 32 || out.Envelope == nil || len(out.Envelope.Nonce) != 12 || len(out.Envelope.Ciphertext) != sha256.Size+16 {
		return nil, nil, errors.New("invalid SSH registration or server binding")
	}
	key, err := ssh.ParsePublicKey(out.PublicKey)
	if err != nil || key.Type() != ssh.KeyAlgoED25519 {
		return nil, nil, errors.New("SSH registration requires an ordinary Ed25519 public key")
	}
	return &out, key, nil
}

func publish(path string, value registration) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".ssh-unlock-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil {
		return fmt.Errorf("publish SSH registration without overwriting (use sylva ssh remove before replacing it): %w", err)
	}
	return nil
}
