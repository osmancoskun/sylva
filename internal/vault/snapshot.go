package vault

import (
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
)

// Snapshot is a consistent ciphertext-only vault image. Revision protects
// whole-vault operations from concurrent writes; Generation invalidates old sessions.
type Snapshot struct {
	Revision   int64                `json:"revision"`
	Generation string               `json:"generation"`
	Salt       []byte               `json:"salt"`
	KeyCheck   *crypto.Envelope     `json:"key_check"`
	KDF        *config.CryptoConfig `json:"kdf,omitempty"`
	Records    []*EncryptedRecord   `json:"records"`
}
