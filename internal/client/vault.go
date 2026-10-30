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
	"sort"
	"strings"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/tree"
	"github.com/osman/sylva/internal/vault"
)

var (
	// ErrParentExists indicates a parent domain was found and the caller must choose inherit vs separate.
	ErrParentExists = errors.New("parent domain exists; pass --inherit or --separate")

	// ErrAlreadyExists indicates a secret with this type and identifier is already stored.
	ErrAlreadyExists = errors.New("secret already exists")

	// ErrLocked indicates the vault has not been unlocked with a master passphrase.
	ErrLocked = errors.New("vault is locked")

	// ErrAmbiguous indicates more than one secret type matches the identifier.
	ErrAmbiguous = errors.New("multiple secrets match this identifier")
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
	cfg.MaxBackupBytes = limits.OrDefault(cfg.MaxBackupBytes, limits.DefaultBackupBytes)
	if err := limits.Validate("max_backup_bytes", cfg.MaxBackupBytes); err != nil {
		return nil, err
	}
	remote, err := transport.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	v := &Vault{
		cfg:    cfg,
		remote: remote,
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
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("read vault salt: %w", err)
	}

	salt, err = crypto.GenerateSalt(v.cfg.Crypto.KDFSaltLen)
	if err != nil {
		return nil, err
	}
	if err := v.remote.PutSalt(ctx, salt); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return v.remote.GetSalt(ctx)
		}
		return nil, fmt.Errorf("initialize vault salt: %w", err)
	}
	v.cacheSalt(ctx, salt)
	return salt, nil
}

// Unlock derives the master key from the passphrase and the server-held salt.
func (v *Vault) Unlock(ctx context.Context, passphrase string) error {
	v.clearMasterKey()
	if strings.TrimSpace(passphrase) == "" {
		return errors.New("master passphrase cannot be empty")
	}
	salt, err := v.Init(ctx)
	if err != nil {
		return err
	}
	if kdf := v.remote.KDFConfig(); kdf != nil {
		if err := validateKDF(*kdf); err != nil {
			return err
		}
		v.cfg.Crypto = *kdf
	}
	key, err := crypto.DeriveKey([]byte(passphrase), salt, v.cfg.Crypto)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	if err := v.verifyKey(ctx, key, true); err != nil {
		return err
	}
	return v.installKey(key)
}

// UnlockWithKey verifies an agent key against this server before installing it.
// Only passphrase unlock may initialize or migrate a vault verifier.
func (v *Vault) UnlockWithKey(ctx context.Context, key []byte) error {
	v.clearMasterKey()
	if err := v.verifyKey(ctx, key, false); err != nil {
		return err
	}
	return v.installKey(key)
}

func (v *Vault) clearMasterKey() {
	crypto.ZeroBytes(v.masterKey)
	v.masterKey = nil
}

func (v *Vault) installKey(key []byte) error {
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

	if err := v.createRecord(ctx, item); err != nil {
		return nil, err
	}

	if err := dt.Insert(item); err != nil {
		return nil, err
	}
	return dt.Resolve(norm, false)
}

// GetValue copies the plaintext secret for identifier. An empty secretType
// probes password, domain, env, and ssh. Logins use the domain tree (including inherit).
func (v *Vault) GetValue(ctx context.Context, identifier string, secretType vault.SecretType, cascade bool, envVariable string) (vault.SecretType, string, error) {
	if err := v.requireUnlocked(); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(identifier) == "" {
		return "", "", errors.New("identifier is required")
	}
	if secretType != "" {
		value, err := v.valueOf(ctx, identifier, secretType, cascade, envVariable)
		return secretType, value, err
	}
	matches, err := v.ProbeValues(ctx, identifier, cascade, envVariable)
	if err != nil {
		return "", "", err
	}
	switch len(matches) {
	case 0:
		return "", "", fmt.Errorf("%w: no secret named %s", storage.ErrNotFound, identifier)
	case 1:
		return matches[0].Type, matches[0].Value, nil
	default:
		return "", "", fmt.Errorf("%w: %s", ErrAmbiguous, identifier)
	}
}

// SecretMatch is one probe hit for an identifier that exists as that type.
type SecretMatch struct {
	Type  vault.SecretType
	Value string
}

// ProbeValues returns every secret type that currently stores this identifier.
func (v *Vault) ProbeValues(ctx context.Context, identifier string, cascade bool, envVariable string) ([]SecretMatch, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	var matches []SecretMatch
	for _, candidate := range []vault.SecretType{
		vault.SecretTypeToken,
		vault.SecretTypeLogin,
		vault.SecretTypeEnv,
		vault.SecretTypeSSH,
	} {
		value, err := v.valueOf(ctx, identifier, candidate, cascade && candidate == vault.SecretTypeLogin, envVariable)
		if err == nil {
			matches = append(matches, SecretMatch{Type: candidate, Value: value})
			continue
		}
		if isMissingSecret(err) || candidate == vault.SecretTypeLogin {
			continue
		}
		return nil, err
	}
	return matches, nil
}

func isMissingSecret(err error) bool {
	return errors.Is(err, storage.ErrNotFound) || errors.Is(err, tree.ErrDomainNotFound) || errors.Is(err, tree.ErrEmptyDomain)
}

// GetSecret loads and unseals a secret by type and identifier.
func (v *Vault) GetSecret(ctx context.Context, secretType vault.SecretType, identifier string) (*vault.SecretItem, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	if secretType == vault.SecretTypeLogin {
		norm, err := tree.NormalizeDomain(identifier)
		if err != nil {
			return nil, err
		}
		identifier = norm
	}
	rec, err := v.getByIdentifier(ctx, secretType, identifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%w: no %s secret named %s", storage.ErrNotFound, secretLabel(secretType), identifier)
		}
		return nil, err
	}
	item, err := vault.Unseal(v.masterKey, rec)
	if err != nil {
		return nil, fmt.Errorf("unseal %s %s: %w", secretLabel(secretType), identifier, err)
	}
	return item, nil
}

func (v *Vault) valueOf(ctx context.Context, identifier string, secretType vault.SecretType, cascade bool, envVariable string) (string, error) {
	if secretType == vault.SecretTypeLogin {
		res, err := v.LoginGet(ctx, identifier, cascade)
		if err != nil {
			return "", err
		}
		if res.Item == nil || res.Item.Login == nil || res.Item.Login.Password == "" {
			return "", fmt.Errorf("resolved login for %s has no password", identifier)
		}
		return res.Item.Login.Password, nil
	}
	item, err := v.GetSecret(ctx, secretType, identifier)
	if err != nil {
		return "", err
	}
	return plaintextSecret(item, envVariable)
}

func plaintextSecret(item *vault.SecretItem, envVariable string) (string, error) {
	if item == nil {
		return "", errors.New("secret item is required")
	}
	switch item.Type {
	case vault.SecretTypeToken:
		if item.Token == nil || item.Token.Token == "" {
			return "", fmt.Errorf("password %s has no value", item.Identifier)
		}
		return item.Token.Token, nil
	case vault.SecretTypeSSH:
		if item.SSH == nil {
			return "", fmt.Errorf("ssh %s has no payload", item.Identifier)
		}
		if item.SSH.Passphrase != "" {
			return item.SSH.Passphrase, nil
		}
		if item.SSH.PrivateKey != "" {
			return item.SSH.PrivateKey, nil
		}
		return "", fmt.Errorf("ssh %s has no passphrase", item.Identifier)
	case vault.SecretTypeEnv:
		if item.Env == nil || len(item.Env.Variables) == 0 {
			return "", fmt.Errorf("env %s has no variables", item.Identifier)
		}
		vars := item.Env.Variables
		if envVariable != "" {
			value, ok := vars[envVariable]
			if !ok {
				return "", fmt.Errorf("env %s has no variable %s", item.Identifier, envVariable)
			}
			return value, nil
		}
		if value, ok := vars[item.Identifier]; ok {
			return value, nil
		}
		if len(vars) == 1 {
			for _, value := range vars {
				return value, nil
			}
		}
		return "", fmt.Errorf("env %s has multiple variables; pass one", item.Identifier)
	default:
		return "", fmt.Errorf("unsupported type %q", item.Type)
	}
}

func secretLabel(secretType vault.SecretType) string {
	switch secretType {
	case vault.SecretTypeToken:
		return "password"
	case vault.SecretTypeLogin:
		return "domain"
	case vault.SecretTypeEnv:
		return "env"
	case vault.SecretTypeSSH:
		return "ssh"
	default:
		return string(secretType)
	}
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

// NearestLoginAncestor returns the closest stored parent login, or nil if none exists.
func (v *Vault) NearestLoginAncestor(ctx context.Context, domain string) (*vault.SecretItem, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	dt, err := v.loginTree(ctx)
	if err != nil {
		return nil, err
	}
	ancestor, found, err := dt.FindNearestAncestor(domain)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return ancestor, nil
}

// PutSecret stores a sealed secret of any supported type.
func (v *Vault) PutSecret(ctx context.Context, item *vault.SecretItem) error {
	return v.createRecord(ctx, item)
}

// ListSecrets unseals stored secrets, optionally filtered by type. Payloads are included; the CLI must not print them.
func (v *Vault) ListSecrets(ctx context.Context, secretType vault.SecretType) ([]*vault.SecretItem, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	recs, err := v.listRecords(ctx, secretType)
	if err != nil {
		return nil, err
	}
	items := make([]*vault.SecretItem, 0, len(recs))
	for _, rec := range recs {
		item, err := vault.Unseal(v.masterKey, rec)
		if err != nil {
			return nil, fmt.Errorf("unseal %s: %w", rec.ID, err)
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		li, lj := secretLabel(items[i].Type), secretLabel(items[j].Type)
		if li != lj {
			return li < lj
		}
		return items[i].Identifier < items[j].Identifier
	})
	return items, nil
}

// DeleteSecret removes the stored secret of this type and identifier.
func (v *Vault) DeleteSecret(ctx context.Context, secretType vault.SecretType, identifier string) error {
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	if secretType == vault.SecretTypeLogin {
		norm, err := tree.NormalizeDomain(identifier)
		if err != nil {
			return err
		}
		identifier = norm
	}
	rec, err := v.getByIdentifier(ctx, secretType, identifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w: no %s secret named %s", storage.ErrNotFound, secretLabel(secretType), identifier)
		}
		return err
	}
	if err := v.remote.DeleteRecord(ctx, rec.ID); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			v.clearMasterKey()
			v.disableCache()
		}
		if errors.Is(err, storage.ErrNotFound) {
			v.cacheForget(ctx, rec.BlindIndex)
		}
		return err
	}
	v.cacheForget(ctx, rec.BlindIndex)
	return nil
}

// UpdateSecret writes a previously read item only if its source version is
// still current. It never retries a stale payload against a newer revision.
func (v *Vault) UpdateSecret(ctx context.Context, item *vault.SecretItem) error {
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	if item == nil {
		return errors.New("secret item is required")
	}
	if item.ID == "" || item.Version <= 0 {
		return errors.New("read the secret before updating it; its ID and version are required")
	}
	if item.Type == vault.SecretTypeLogin {
		norm, err := tree.NormalizeDomain(item.Identifier)
		if err != nil {
			return err
		}
		item.Identifier = norm
		if item.Login != nil {
			item.Login.Domain = norm
		}
	}
	sealed, err := vault.Seal(v.masterKey, item, item.Version+1)
	if err != nil {
		return err
	}
	if _, err := v.remote.UpdateRecord(ctx, sealed); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			v.clearMasterKey()
			v.disableCache()
		}
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrVersionConflict) {
			v.cacheForget(ctx, sealed.BlindIndex)
		}
		return err
	}
	v.cacheReplace(ctx, sealed)
	item.Version = sealed.Version
	return nil
}

// SecretExists reports whether a secret of this type and identifier is already stored.
func (v *Vault) SecretExists(ctx context.Context, secretType vault.SecretType, identifier string) (bool, error) {
	if err := v.requireUnlocked(); err != nil {
		return false, err
	}
	if secretType == vault.SecretTypeLogin {
		norm, err := tree.NormalizeDomain(identifier)
		if err != nil {
			return false, err
		}
		identifier = norm
	}
	_, err := v.getByIdentifier(ctx, secretType, identifier)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// AlreadyExists returns a typed error for a duplicate secret of this kind.
func AlreadyExists(secretType vault.SecretType, identifier string) error {
	switch secretType {
	case vault.SecretTypeLogin:
		return fmt.Errorf("%w: a password already exists for domain %s", ErrAlreadyExists, identifier)
	case vault.SecretTypeToken:
		return fmt.Errorf("%w: a password already exists for %s", ErrAlreadyExists, identifier)
	case vault.SecretTypeEnv:
		return fmt.Errorf("%w: an env secret already exists for %s", ErrAlreadyExists, identifier)
	case vault.SecretTypeSSH:
		return fmt.Errorf("%w: an ssh secret already exists for %s", ErrAlreadyExists, identifier)
	default:
		return fmt.Errorf("%w: a secret already exists for %s", ErrAlreadyExists, identifier)
	}
}

func (v *Vault) createRecord(ctx context.Context, item *vault.SecretItem) error {
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	if item == nil {
		return errors.New("secret item is required")
	}
	exists, err := v.SecretExists(ctx, item.Type, item.Identifier)
	if err != nil {
		return err
	}
	if exists {
		return AlreadyExists(item.Type, item.Identifier)
	}
	id, err := newRecordID()
	if err != nil {
		return err
	}
	item.ID = id
	sealed, err := vault.Seal(v.masterKey, item, v.cfg.RecordInitialVersion)
	if err != nil {
		return err
	}
	if err := v.putRecord(ctx, sealed); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			v.clearMasterKey()
			v.disableCache()
			return err
		}
		if errors.Is(err, storage.ErrConflict) {
			return AlreadyExists(item.Type, item.Identifier)
		}
		return err
	}
	item.Version = sealed.Version
	return nil
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
	v.cacheReplace(ctx, rec)
	return nil
}

func (v *Vault) cacheReplace(ctx context.Context, rec *vault.EncryptedRecord) {
	if v.cache == nil {
		return
	}
	if err := v.cache.Upsert(ctx, rec); err != nil {
		v.disableCache()
	}
}

func (v *Vault) listRecords(ctx context.Context, secretType vault.SecretType) ([]*vault.EncryptedRecord, error) {
	recs, err := v.remote.ListRecords(ctx, secretType)
	if err == nil {
		if v.cache != nil {
			if err := v.cache.ReplaceRecords(ctx, secretType, recs); err != nil {
				v.disableCache()
			}
		}
		return recs, nil
	}
	if v.cache == nil || !canReadCache(ctx, err) {
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
		v.cacheReplace(ctx, rec)
		return rec, nil
	}
	if errors.Is(err, storage.ErrNotFound) {
		v.cacheForget(ctx, idx)
		return nil, err
	}
	if v.cache == nil || !canReadCache(ctx, err) {
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
