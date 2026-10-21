// Package client implements high-level vault operations for the sylva CLI:
// unlocking with a master passphrase, initializing the shared Argon2id salt,
// and storing/resolving hierarchical login credentials.
package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/tree"
	"github.com/osman/sylva/internal/vault"
)

var (
	// ErrParentExists indicates a parent domain was found and the caller must choose inherit vs separate.
	ErrParentExists = errors.New("parent domain exists; pass --inherit or --separate")

	// ErrLocked indicates the vault has not been unlocked with a master passphrase.
	ErrLocked = errors.New("vault is locked")
)

// Vault is a client-side session over a remote sylvad store and optional local cache.
type Vault struct {
	cfg       config.ClientConfig
	remote    *transport.Client
	cache     storage.Store
	masterKey []byte
}

// Open constructs a Vault client. Unlock must be called before secret operations.
func Open(cfg config.ClientConfig) (*Vault, error) {
	v := &Vault{
		cfg:    cfg,
		remote: transport.NewClient(cfg),
	}
	if cfg.CacheEnabled {
		cache, err := storage.OpenSQLite(cfg.CachePath, cfg.SQLiteBusyTimeout)
		if err != nil {
			return nil, fmt.Errorf("open client cache: %w", err)
		}
		v.cache = cache
	}
	return v, nil
}

// Close releases the local cache handle, idle HTTP connections, and zeroes the master key.
func (v *Vault) Close() error {
	crypto.ZeroBytes(v.masterKey)
	v.masterKey = nil
	if v.remote != nil {
		v.remote.Close()
	}
	if v.cache != nil {
		return v.cache.Close()
	}
	return nil
}

// Remote returns the underlying transport client (used for ping).
func (v *Vault) Remote() *transport.Client {
	return v.remote
}

// Init ensures a vault-wide Argon2id salt exists on the server.
func (v *Vault) Init(ctx context.Context) ([]byte, error) {
	salt, err := v.remote.GetSalt(ctx)
	if err == nil {
		v.cacheSalt(ctx, salt)
		return salt, nil
	}

	salt, err = crypto.GenerateSalt(v.cfg.Crypto.KDFSaltLen)
	if err != nil {
		return nil, err
	}
	if err := v.remote.PutSalt(ctx, salt); err != nil {
		return nil, fmt.Errorf("initialize vault salt: %w", err)
	}
	v.cacheSalt(ctx, salt)
	return salt, nil
}

// Unlock derives the master key from the passphrase and the server-held salt.
func (v *Vault) Unlock(ctx context.Context, passphrase string) error {
	if strings.TrimSpace(passphrase) == "" {
		return errors.New("master passphrase cannot be empty (set SYLVA_MASTER_PASSPHRASE)")
	}
	salt, err := v.Init(ctx)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveKey([]byte(passphrase), salt, v.cfg.Crypto)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return v.UnlockWithKey(key)
}

// UnlockWithKey installs an already-derived master key (for example from the session agent).
func (v *Vault) UnlockWithKey(key []byte) error {
	if int(v.cfg.Crypto.KDFKeyLen) <= 0 || len(key) != int(v.cfg.Crypto.KDFKeyLen) {
		return fmt.Errorf("master key must be %d bytes", v.cfg.Crypto.KDFKeyLen)
	}
	copied := make([]byte, len(key))
	copy(copied, key)
	crypto.ZeroBytes(v.masterKey)
	v.masterKey = copied
	return nil
}

// CopyMasterKey returns a copy of the derived master key. The caller must zero it.
func (v *Vault) CopyMasterKey() ([]byte, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	out := make([]byte, len(v.masterKey))
	copy(out, v.masterKey)
	return out, nil
}

// LoginSet stores a login entry, optionally inheriting from a parent domain.
func (v *Vault) LoginSet(ctx context.Context, domain, username, password string, inherit, separate bool) (*tree.Resolution, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	if inherit && separate {
		return nil, errors.New("flags --inherit and --separate are mutually exclusive")
	}

	norm, err := tree.NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}

	dt, err := v.loginTree(ctx)
	if err != nil {
		return nil, err
	}

	ancestor, found, err := dt.FindNearestAncestor(norm)
	if err != nil {
		return nil, err
	}

	item := &vault.SecretItem{
		Type:       vault.SecretTypeLogin,
		Identifier: norm,
		Login: &vault.LoginPayload{
			Domain:   norm,
			Username: username,
			Password: password,
		},
	}

	if found {
		if ancestor == nil || ancestor.Login == nil {
			return nil, errors.New("parent domain exists but its login payload is missing")
		}
		if !inherit && !separate {
			return nil, fmt.Errorf("%w: %s", ErrParentExists, ancestor.Login.Domain)
		}
		if inherit {
			item.ParentID = ancestor.Login.Domain
			item.Login.InheritFromParent = true
			item.Login.ParentDomain = ancestor.Login.Domain
			item.Login.Password = ""
			if item.Login.Username == "" {
				item.Login.Username = ancestor.Login.Username
			}
		}
	}

	version := v.cfg.RecordInitialVersion
	if existing, getErr := v.getByIdentifier(ctx, vault.SecretTypeLogin, norm); getErr == nil {
		item.ID = existing.ID
		version = existing.Version + 1
		if unsealed, unsealErr := vault.Unseal(v.masterKey, existing); unsealErr == nil {
			item.CreatedAt = unsealed.CreatedAt
		}
	} else {
		id, genErr := newRecordID()
		if genErr != nil {
			return nil, genErr
		}
		item.ID = id
	}

	sealed, err := vault.Seal(v.masterKey, item, version)
	if err != nil {
		return nil, err
	}
	if err := v.putRecord(ctx, sealed); err != nil {
		return nil, err
	}

	if err := dt.Insert(item); err != nil {
		return nil, err
	}
	return dt.Resolve(norm, false)
}

// LoginGet resolves a login, optionally cascading up the domain tree.
func (v *Vault) LoginGet(ctx context.Context, domain string, cascade bool) (*tree.Resolution, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	dt, err := v.loginTree(ctx)
	if err != nil {
		return nil, err
	}
	return dt.Resolve(domain, cascade)
}

func (v *Vault) loginTree(ctx context.Context) (*tree.DomainTree, error) {
	recs, err := v.listRecords(ctx, vault.SecretTypeLogin)
	if err != nil {
		return nil, err
	}
	dt := tree.New()
	for _, rec := range recs {
		item, err := vault.Unseal(v.masterKey, rec)
		if err != nil {
			return nil, fmt.Errorf("unseal login %s: %w", rec.ID, err)
		}
		if err := dt.Insert(item); err != nil {
			return nil, err
		}
	}
	return dt, nil
}

func (v *Vault) putRecord(ctx context.Context, rec *vault.EncryptedRecord) error {
	if _, err := v.remote.PutRecord(ctx, rec); err != nil {
		return err
	}
	if v.cache != nil {
		_ = v.cache.Put(ctx, rec)
	}
	return nil
}

func (v *Vault) listRecords(ctx context.Context, secretType vault.SecretType) ([]*vault.EncryptedRecord, error) {
	recs, err := v.remote.ListRecords(ctx, secretType)
	if err == nil {
		if v.cache != nil {
			for _, rec := range recs {
				_ = v.cache.Put(ctx, rec)
			}
		}
		return recs, nil
	}
	if v.cache == nil {
		return nil, err
	}
	return v.cache.List(ctx, secretType)
}

func (v *Vault) getByIdentifier(ctx context.Context, secretType vault.SecretType, identifier string) (*vault.EncryptedRecord, error) {
	idx, err := vault.LookupBlindIndex(v.masterKey, secretType, identifier)
	if err != nil {
		return nil, err
	}
	rec, err := v.remote.GetRecordByBlindIndex(ctx, idx)
	if err == nil {
		if v.cache != nil {
			_ = v.cache.Put(ctx, rec)
		}
		return rec, nil
	}
	if v.cache == nil {
		return nil, err
	}
	return v.cache.GetByBlindIndex(ctx, idx)
}

func (v *Vault) cacheSalt(ctx context.Context, salt []byte) {
	if v.cache == nil {
		return
	}
	_ = v.cache.PutMetadata(ctx, storage.MetadataKDFSalt, salt)
}

func (v *Vault) requireUnlocked() error {
	if len(v.masterKey) == 0 {
		return ErrLocked
	}
	return nil
}

func newRecordID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate record id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
