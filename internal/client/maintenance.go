package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/vault"
)

const backupFormat = "sylva-backup-v1"

type backupHeader struct {
	Format string              `json:"format"`
	KDF    config.CryptoConfig `json:"kdf"`
	Salt   []byte              `json:"salt"`
}
type backupFile struct {
	backupHeader
	Envelope *crypto.Envelope `json:"envelope"`
}

// Bound untrusted backup/server KDF parameters before allocating memory.
func validateKDF(kdf config.CryptoConfig) error {
	if kdf.KDFTime < 1 || kdf.KDFTime > 10 || kdf.KDFThreads < 1 || kdf.KDFThreads > 64 || kdf.KDFMemoryKB < 8*uint32(kdf.KDFThreads) || kdf.KDFMemoryKB > 1024*1024 || kdf.KDFKeyLen != 32 || kdf.KDFSaltLen < 16 || kdf.KDFSaltLen > 64 {
		return errors.New("unsupported or unsafe vault KDF parameters")
	}
	return nil
}

func newGeneration() (string, error) {
	b, err := crypto.GenerateSalt(32)
	return hex.EncodeToString(b), err
}

func checkSnapshot(key []byte, snapshot *vault.Snapshot) ([]*vault.SecretItem, error) {
	if snapshot == nil || len(snapshot.Salt) < 16 || snapshot.KeyCheck == nil || snapshot.Records == nil {
		return nil, errors.New("incomplete vault snapshot")
	}
	checkKey, err := crypto.DeriveSubkey(key, keyCheckPurpose)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(checkKey)
	if err := verifyKeyCheck(checkKey, snapshot.KeyCheck); err != nil {
		return nil, err
	}
	items := make([]*vault.SecretItem, 0, len(snapshot.Records))
	ids := map[string]bool{}
	indexes := map[string]bool{}
	for _, rec := range snapshot.Records {
		if rec == nil || rec.Version < 1 || ids[rec.ID] || indexes[rec.BlindIndex] {
			return nil, errors.New("invalid or duplicate snapshot record")
		}
		item, err := vault.Unseal(key, rec)
		if err != nil {
			return nil, err
		}
		if err := item.Validate(); err != nil {
			return nil, err
		}
		index, err := vault.LookupBlindIndex(key, item.Type, item.Identifier)
		if err != nil {
			return nil, err
		}
		if item.ID != rec.ID || item.Type != rec.Type || index != rec.BlindIndex {
			return nil, errors.New("snapshot record identity mismatch")
		}
		ids[rec.ID] = true
		indexes[rec.BlindIndex] = true
		items = append(items, item)
	}
	return items, nil
}

func (v *Vault) checkedSnapshot(ctx context.Context) (*vault.Snapshot, []*vault.SecretItem, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, nil, err
	}
	snapshot, err := v.remote.Snapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	items, err := checkSnapshot(v.masterKey, snapshot)
	if err != nil {
		return nil, nil, err
	}
	if snapshot.KDF == nil {
		kdf := v.cfg.Crypto
		snapshot.KDF = &kdf
	}
	if err := validateKDF(*snapshot.KDF); err != nil {
		return nil, nil, err
	}
	return snapshot, items, nil
}

// ChangePassphrase re-encrypts a consistent snapshot locally and commits the
// entire replacement with a revision precondition. No partial rotation is visible.
func (v *Vault) ChangePassphrase(ctx context.Context, newPassphrase string) error {
	if strings.TrimSpace(newPassphrase) == "" {
		return errors.New("new master passphrase cannot be empty")
	}
	snapshot, items, err := v.checkedSnapshot(ctx)
	if err != nil {
		return err
	}
	salt, err := crypto.GenerateSalt(snapshot.KDF.KDFSaltLen)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveKey([]byte(newPassphrase), salt, *snapshot.KDF)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	checkKey, err := crypto.DeriveSubkey(key, keyCheckPurpose)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(checkKey)
	check, err := crypto.Encrypt(checkKey, []byte(keyCheckPlaintext), []byte(keyCheckPurpose))
	if err != nil {
		return err
	}
	generation, err := newGeneration()
	if err != nil {
		return err
	}
	next := &vault.Snapshot{Salt: salt, KeyCheck: check, KDF: snapshot.KDF, Generation: generation, Records: []*vault.EncryptedRecord{}}
	for _, item := range items {
		if item.Version == int(^uint(0)>>1) {
			return errors.New("record version exhausted")
		}
		rec, err := vault.Seal(key, item, item.Version+1)
		if err != nil {
			return err
		}
		next.Records = append(next.Records, rec)
	}
	if err := v.remote.ReplaceVault(ctx, snapshot, next, false); err != nil {
		return err
	}
	v.disableCache()
	v.cfg.Crypto = *snapshot.KDF
	v.remote.SetGeneration(generation)
	return v.installKey(key)
}

// Backup writes an authenticated encrypted archive without replacing an existing file.
func (v *Vault) Backup(ctx context.Context, path string) error {
	snapshot, _, err := v.checkedSnapshot(ctx)
	if err != nil {
		return err
	}
	header := backupHeader{Format: backupFormat, KDF: *snapshot.KDF, Salt: snapshot.Salt}
	aad, err := json.Marshal(header)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(plain)
	key, err := crypto.DeriveSubkey(v.masterKey, backupFormat)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	env, err := crypto.Encrypt(key, plain, aad)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".sylva-backup-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(&limits.Writer{Writer: file, Scope: "backup", Limit: v.cfg.MaxBackupBytes, Setting: "max_backup_bytes"}).Encode(backupFile{backupHeader: header, Envelope: env}); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil {
		return fmt.Errorf("publish backup without overwriting: %w", err)
	}
	return nil
}

// Restore authenticates the whole archive before contacting the target and
// installs it only into an uninitialized vault. Existing vaults are never overwritten.
func (v *Vault) Restore(ctx context.Context, path, passphrase string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > v.cfg.MaxBackupBytes {
		return &limits.SizeError{Scope: "backup", Setting: "max_backup_bytes", Limit: v.cfg.MaxBackupBytes}
	}
	raw, err := limits.Read(file, v.cfg.MaxBackupBytes, "backup", "max_backup_bytes")
	if err != nil {
		return err
	}
	var archive backupFile
	if err := json.Unmarshal(raw, &archive); err != nil {
		return err
	}
	if archive.Format != backupFormat || len(archive.Salt) < 16 || len(archive.Salt) > 64 || archive.Envelope == nil {
		return errors.New("unsupported or incomplete backup")
	}
	if err := validateKDF(archive.KDF); err != nil {
		return err
	}
	key, err := crypto.DeriveKey([]byte(passphrase), archive.Salt, archive.KDF)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	backupKey, err := crypto.DeriveSubkey(key, backupFormat)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(backupKey)
	aad, err := json.Marshal(archive.backupHeader)
	if err != nil {
		return err
	}
	plain, err := crypto.Decrypt(backupKey, archive.Envelope, aad)
	if err != nil {
		return ErrInvalidPassphrase
	}
	defer crypto.ZeroBytes(plain)
	var snapshot vault.Snapshot
	if err := json.Unmarshal(plain, &snapshot); err != nil {
		return err
	}
	if snapshot.KDF == nil || *snapshot.KDF != archive.KDF || !bytes.Equal(snapshot.Salt, archive.Salt) {
		return errors.New("backup parameters do not match vault")
	}
	if _, err := checkSnapshot(key, &snapshot); err != nil {
		return err
	}
	target, err := v.remote.Snapshot(ctx)
	if err != nil {
		return err
	}
	if len(target.Records) != 0 || target.KeyCheck != nil {
		return errors.New("restore requires an uninitialized target vault")
	}
	snapshot.Generation, err = newGeneration()
	if err != nil {
		return err
	}
	if err := v.remote.ReplaceVault(ctx, target, &snapshot, true); err != nil {
		return err
	}
	v.disableCache()
	v.cfg.Crypto = archive.KDF
	v.remote.SetGeneration(snapshot.Generation)
	return v.installKey(key)
}
