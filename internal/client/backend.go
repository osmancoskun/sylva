package client

import (
	"context"
	"fmt"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/gitbackend"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
)

// Backend is the ciphertext-only remote vault contract. Implementations must
// enforce record versions and atomically compare/replace whole-vault snapshots.
// Cache storage and plaintext encryption are deliberately outside this boundary.
type Backend interface {
	Close()
	Ping(context.Context) (*api.StatusResponse, error)
	GetSalt(context.Context) ([]byte, error)
	PutSalt(context.Context, []byte) error
	KDFConfig() *config.CryptoConfig
	GetKeyCheck(context.Context) (*crypto.Envelope, error)
	GetKeyCheckState(context.Context) (*api.KeyCheckBody, error)
	PutKeyCheck(context.Context, *crypto.Envelope) error
	SetGeneration(string)
	PutRecord(context.Context, *vault.EncryptedRecord) (*vault.EncryptedRecord, error)
	UpdateRecord(context.Context, *vault.EncryptedRecord) (*vault.EncryptedRecord, error)
	GetRecord(context.Context, string) (*vault.EncryptedRecord, error)
	GetRecordByBlindIndex(context.Context, string) (*vault.EncryptedRecord, error)
	ListRecords(context.Context, vault.SecretType) ([]*vault.EncryptedRecord, error)
	DeleteRecord(context.Context, string) error
	Snapshot(context.Context) (*vault.Snapshot, error)
	ReplaceVault(context.Context, *vault.Snapshot, *vault.Snapshot, bool) error
}

func NewBackend(cfg config.ClientConfig) (Backend, error) {
	switch cfg.Backend {
	case "", "self-hosted":
		return transport.NewClient(cfg)
	case "git":
		return gitbackend.New(cfg)
	default:
		return nil, fmt.Errorf("unsupported vault backend %q", cfg.Backend)
	}
}

// OpenForCommand pins Git reads to one freshly fetched commit for the lifetime
// of a CLI command. Writes still compare the exact remote head when publishing.
// Library callers using Open retain fresh reads on each backend operation.
func OpenForCommand(cfg config.ClientConfig) (*Vault, error) {
	v, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	if git, ok := v.remote.(*gitbackend.Client); ok {
		git.UseCommandSnapshot()
	}
	return v, nil
}
