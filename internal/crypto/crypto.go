// Package crypto implements Sylva's zero-knowledge client-side cryptography,
// including Argon2id key derivation, AES-256-GCM authenticated encryption,
// HMAC-SHA256 blind indexing, secure password generation, and memory zeroing.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/osman/sylva/internal/config"
)

var (
	// ErrInvalidKeyLength indicates that the provided key does not match the AES-256 requirement.
	ErrInvalidKeyLength = errors.New("encryption key must be 32 bytes for AES-256-GCM")

	// ErrInvalidSaltLength indicates that the provided salt is empty or shorter than required.
	ErrInvalidSaltLength = errors.New("salt length must be positive")

	// ErrEmptyPassphrase indicates that an empty master passphrase was provided.
	ErrEmptyPassphrase = errors.New("master passphrase cannot be empty")

	// ErrDecryptionFailed indicates that ciphertext authentication or decryption failed.
	ErrDecryptionFailed = errors.New("ciphertext authentication failed or key is invalid")
)

// Envelope holds the output of an AES-256-GCM encryption operation.
type Envelope struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// GenerateSalt generates a cryptographically secure random salt of the configured length.
func GenerateSalt(length int) ([]byte, error) {
	if length <= 0 {
		return nil, ErrInvalidSaltLength
	}
	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate random salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a symmetric key from a master passphrase and salt using Argon2id
// with parameters supplied via config.CryptoConfig.
func DeriveKey(passphrase []byte, salt []byte, cfg config.CryptoConfig) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if len(salt) == 0 {
		return nil, ErrInvalidSaltLength
	}
	if cfg.KDFTime == 0 || cfg.KDFMemoryKB == 0 || cfg.KDFThreads == 0 || cfg.KDFKeyLen == 0 {
		return nil, errors.New("invalid Argon2id KDF configuration parameters")
	}

	key := argon2.IDKey(
		passphrase,
		salt,
		cfg.KDFTime,
		cfg.KDFMemoryKB,
		cfg.KDFThreads,
		cfg.KDFKeyLen,
	)
	return key, nil
}

// DeriveSubkey derives a purpose-specific 256-bit key (e.g., for encryption vs. blind indexing)
// from a master key using HMAC-SHA256 domain separation.
func DeriveSubkey(masterKey []byte, purpose string) ([]byte, error) {
	if len(masterKey) != sha256.Size {
		return nil, ErrInvalidKeyLength
	}
	mac := hmac.New(sha256.New, masterKey)
	_, _ = mac.Write([]byte(purpose))
	return mac.Sum(nil), nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a freshly generated random nonce
// and binds optional Additional Authenticated Data (aad) to the ciphertext integrity tag.
func Encrypt(key, plaintext, aad []byte) (*Envelope, error) {
	if len(key) != sha256.Size {
		return nil, ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate GCM nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return &Envelope{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt authenticates and decrypts an AES-256-GCM Envelope using the provided key and aad.
func Decrypt(key []byte, env *Envelope, aad []byte) ([]byte, error) {
	if len(key) != sha256.Size {
		return nil, ErrInvalidKeyLength
	}
	if env == nil {
		return nil, errors.New("encrypted envelope cannot be nil")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init GCM: %w", err)
	}

	if len(env.Nonce) != gcm.NonceSize() {
		return nil, ErrDecryptionFailed
	}

	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ComputeBlindIndex computes a deterministic, keyed HMAC-SHA256 hex digest of an identifier
// (such as a normalized domain or secret path) so the server can index and look up records
// without learning the plaintext identifier.
func ComputeBlindIndex(indexKey []byte, identifier string) (string, error) {
	if len(indexKey) != sha256.Size {
		return "", ErrInvalidKeyLength
	}
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	if normalized == "" {
		return "", errors.New("identifier for blind index cannot be empty")
	}

	mac := hmac.New(sha256.New, indexKey)
	_, _ = mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ZeroBytes overwrites a byte slice with zeroes to clear sensitive key material from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// PasswordPolicy defines character classes for random password generation.
type PasswordPolicy struct {
	Length         int
	IncludeUpper   bool
	IncludeLower   bool
	IncludeDigits  bool
	IncludeSymbols bool
}

const (
	charsetLower   = "abcdefghijklmnopqrstuvwxyz"
	charsetUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetDigits  = "0123456789"
	charsetSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// GeneratePassword produces a cryptographically random password satisfying the given policy.
func GeneratePassword(policy PasswordPolicy) (string, error) {
	if policy.Length <= 0 {
		return "", errors.New("password length must be greater than zero")
	}

	var pool strings.Builder
	var requiredPools []string

	if policy.IncludeLower {
		pool.WriteString(charsetLower)
		requiredPools = append(requiredPools, charsetLower)
	}
	if policy.IncludeUpper {
		pool.WriteString(charsetUpper)
		requiredPools = append(requiredPools, charsetUpper)
	}
	if policy.IncludeDigits {
		pool.WriteString(charsetDigits)
		requiredPools = append(requiredPools, charsetDigits)
	}
	if policy.IncludeSymbols {
		pool.WriteString(charsetSymbols)
		requiredPools = append(requiredPools, charsetSymbols)
	}

	fullCharset := pool.String()
	if fullCharset == "" {
		return "", errors.New("password policy must enable at least one character class")
	}
	if policy.Length < len(requiredPools) {
		return "", fmt.Errorf("password length (%d) is shorter than required character classes (%d)", policy.Length, len(requiredPools))
	}

	out := make([]byte, policy.Length)

	// Guarantee at least one character from each enabled character class.
	for i, classPool := range requiredPools {
		ch, err := randomChar(classPool)
		if err != nil {
			return "", err
		}
		out[i] = ch
	}

	// Fill remaining positions from the combined character pool.
	for i := len(requiredPools); i < policy.Length; i++ {
		ch, err := randomChar(fullCharset)
		if err != nil {
			return "", err
		}
		out[i] = ch
	}

	// Cryptographically shuffle the output slice (Fisher-Yates).
	for i := len(out) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("shuffle password: %w", err)
		}
		j := int(jBig.Int64())
		out[i], out[j] = out[j], out[i]
	}

	return string(out), nil
}

func randomChar(charset string) (byte, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, fmt.Errorf("read random index: %w", err)
	}
	return charset[idx.Int64()], nil
}
