// Package storage persists zero-knowledge EncryptedRecord envelopes and vault
// metadata (such as the Argon2id salt) without ever seeing plaintext secrets.
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/osman/sylva/internal/vault"
)

const (
	// MetadataKDFSalt is the metadata key for the vault-wide Argon2id salt.
	MetadataKDFSalt = "kdf_salt"
	// MetadataKeyCheck is the immutable encrypted master-key verifier.
	MetadataKeyCheck = "key_check_v1"
)

var (
	// ErrNotFound indicates that a record or metadata key does not exist.
	ErrNotFound = errors.New("storage: not found")

	// ErrConflict indicates a uniqueness or salt-mismatch conflict.
	ErrConflict = errors.New("storage: conflict")

	// ErrVersionConflict rejects a write based on an outdated record version.
	ErrVersionConflict = fmt.Errorf("%w: record changed; fetch it again before updating", ErrConflict)
)

// Store is the persistence contract used by both sylvad and the client cache.
type Store interface {
	Close() error
	Put(ctx context.Context, rec *vault.EncryptedRecord) error // insert-only; existing id or blind index returns ErrConflict
	Update(ctx context.Context, rec *vault.EncryptedRecord) error
	GetByID(ctx context.Context, id string) (*vault.EncryptedRecord, error)
	GetByBlindIndex(ctx context.Context, blindIndex string) (*vault.EncryptedRecord, error)
	List(ctx context.Context, secretType vault.SecretType) ([]*vault.EncryptedRecord, error)
	Delete(ctx context.Context, id string) error
	PutMetadata(ctx context.Context, key string, value []byte) error
	CreateMetadata(ctx context.Context, key string, value []byte) error // insert-only, atomic
	GetMetadata(ctx context.Context, key string) ([]byte, error)
	// Cache operations replace authoritative records without insert-only conflicts.
	Upsert(ctx context.Context, rec *vault.EncryptedRecord) error
	ReplaceRecords(ctx context.Context, secretType vault.SecretType, records []*vault.EncryptedRecord) error
	DeleteByBlindIndex(ctx context.Context, blindIndex string) error
}
