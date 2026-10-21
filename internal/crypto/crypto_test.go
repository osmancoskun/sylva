package crypto_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/leakcheck"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func loadTestCryptoConfig(t *testing.T) config.CryptoConfig {
	t.Helper()
	envPath := filepath.Join("..", "..", ".env.example")
	cfg, err := config.LoadCryptoConfig(envPath)
	if err != nil {
		t.Fatalf("failed to load crypto config from %s: %v", envPath, err)
	}
	return cfg
}

func TestDeriveKeyAndEncryptDecrypt(t *testing.T) {
	cfg := loadTestCryptoConfig(t)

	salt, err := crypto.GenerateSalt(cfg.KDFSaltLen)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	passphrase := []byte("correct-horse-battery-staple")
	masterKey1, err := crypto.DeriveKey(passphrase, salt, cfg)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	defer crypto.ZeroBytes(masterKey1)

	masterKey2, err := crypto.DeriveKey(passphrase, salt, cfg)
	if err != nil {
		t.Fatalf("DeriveKey second call failed: %v", err)
	}
	defer crypto.ZeroBytes(masterKey2)

	if !bytes.Equal(masterKey1, masterKey2) {
		t.Fatalf("expected identical master keys from same passphrase and salt across machines")
	}

	encKey, err := crypto.DeriveSubkey(masterKey1, "sylva-vault-encryption-v1")
	if err != nil {
		t.Fatalf("DeriveSubkey failed: %v", err)
	}

	plaintext := []byte(`{"username":"osman","password":"super-secret-password"}`)
	aad := []byte("login:github.com")

	env, err := crypto.Encrypt(encKey, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(env.Ciphertext, plaintext) {
		t.Fatalf("ciphertext must not match plaintext")
	}

	decrypted, err := crypto.Decrypt(encKey, env, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted payload mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptTamperAndWrongAADDetection(t *testing.T) {
	cfg := loadTestCryptoConfig(t)
	salt, _ := crypto.GenerateSalt(cfg.KDFSaltLen)
	key, _ := crypto.DeriveKey([]byte("master-pass"), salt, cfg)

	plaintext := []byte("top-secret-token")
	aad := []byte("token:production-api")

	env, err := crypto.Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Wrong AAD must fail authentication.
	if _, err := crypto.Decrypt(key, env, []byte("token:staging-api")); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed with wrong AAD, got: %v", err)
	}

	// Tampered ciphertext byte must fail authentication.
	env.Ciphertext[0] ^= 0xff
	if _, err := crypto.Decrypt(key, env, aad); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed with tampered ciphertext, got: %v", err)
	}
}

func TestComputeBlindIndex(t *testing.T) {
	cfg := loadTestCryptoConfig(t)
	salt, _ := crypto.GenerateSalt(cfg.KDFSaltLen)
	masterKey, _ := crypto.DeriveKey([]byte("master-pass"), salt, cfg)
	indexKey, err := crypto.DeriveSubkey(masterKey, "sylva-blind-index-v1")
	if err != nil {
		t.Fatalf("DeriveSubkey failed: %v", err)
	}

	idx1, err := crypto.ComputeBlindIndex(indexKey, "Mail.Company.COM ")
	if err != nil {
		t.Fatalf("ComputeBlindIndex failed: %v", err)
	}
	idx2, err := crypto.ComputeBlindIndex(indexKey, "mail.company.com")
	if err != nil {
		t.Fatalf("ComputeBlindIndex failed: %v", err)
	}

	if idx1 != idx2 {
		t.Errorf("expected case-insensitive normalized blind index match: %s != %s", idx1, idx2)
	}
}

func TestGeneratePasswordAndZeroBytes(t *testing.T) {
	cfg := loadTestCryptoConfig(t)

	pwd, err := crypto.GeneratePassword(crypto.PasswordPolicy{
		Length:         cfg.PasswordDefaultLen,
		IncludeLower:   true,
		IncludeUpper:   true,
		IncludeDigits:  true,
		IncludeSymbols: true,
	})
	if err != nil {
		t.Fatalf("GeneratePassword failed: %v", err)
	}
	if len(pwd) != cfg.PasswordDefaultLen {
		t.Errorf("expected password length %d, got %d", cfg.PasswordDefaultLen, len(pwd))
	}

	buf := []byte{1, 2, 3, 4, 5}
	crypto.ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("expected byte %d to be zeroed, got %d", i, b)
		}
	}
}
