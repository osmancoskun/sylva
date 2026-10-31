package client

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func (v *Vault) finishUnlock(ctx context.Context, key []byte) error {
	if err := v.installKey(key); err != nil {
		return err
	}
	if err := v.UseProfile(ctx, v.cfg.Profile); err != nil {
		v.clearMasterKey()
		return err
	}
	return nil
}

// UseProfile changes only the record namespace, retaining the root session key.
func (v *Vault) UseProfile(ctx context.Context, name string) error {
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	name, err := config.NormalizeProfileName(name)
	if err != nil {
		return err
	}
	profile := &vault.ProfilePayload{Name: config.DefaultProfile}
	if name != config.DefaultProfile {
		profile, err = v.resolveProfile(ctx, name)
		if err != nil {
			return err
		}
	}
	v.profileID, v.cfg.Profile = profile.ID, name
	return nil
}

func (v *Vault) resolveProfile(ctx context.Context, name string) (*vault.ProfilePayload, error) {
	identifier := vault.ProfileIdentifier(name)
	index, err := vault.LookupBlindIndex(v.masterKey, vault.SecretTypeProfile, identifier)
	if err != nil {
		return nil, err
	}
	rec, err := v.remote.GetRecordByBlindIndex(ctx, index)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	item, err := vault.Unseal(v.masterKey, rec)
	if err != nil {
		return nil, err
	}
	if err := item.Validate(); err != nil {
		return nil, err
	}
	if rec.BlindIndex != index || item.Type != vault.SecretTypeProfile || item.Profile == nil || item.Profile.Name != name {
		return nil, errors.New("invalid profile descriptor")
	}
	return item.Profile, nil
}

// CreateProfile adds a root-encrypted descriptor. Concurrent duplicate names
// conflict through the same blind-index uniqueness rule as ordinary records.
func (v *Vault) CreateProfile(ctx context.Context, name string) error {
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	name, err := config.NormalizeProfileName(name)
	if err != nil {
		return err
	}
	if name == config.DefaultProfile {
		return fmt.Errorf("%w: profile default already exists", ErrAlreadyExists)
	}
	if _, err := v.resolveProfile(ctx, name); err == nil {
		return fmt.Errorf("%w: profile %s already exists", ErrAlreadyExists, name)
	} else if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	id, err := newRecordID()
	if err != nil {
		return err
	}
	recordID, err := newRecordID()
	if err != nil {
		return err
	}
	item := &vault.SecretItem{ID: recordID, Type: vault.SecretTypeProfile, Identifier: vault.ProfileIdentifier(name), Profile: &vault.ProfilePayload{ID: id, Name: name}}
	rec, err := vault.Seal(v.masterKey, item, v.cfg.RecordInitialVersion)
	if err != nil {
		return err
	}
	if err := v.putRecord(ctx, rec); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			v.clearMasterKey()
			v.disableCache()
		}
		return err
	}
	return nil
}

func (v *Vault) ListProfiles(ctx context.Context) ([]vault.ProfilePayload, error) {
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	records, err := v.remote.ListRecords(ctx, vault.SecretTypeProfile)
	if err != nil {
		return nil, err
	}
	profiles := []vault.ProfilePayload{{Name: config.DefaultProfile}}
	ids, names := map[string]bool{"": true}, map[string]bool{config.DefaultProfile: true}
	for _, rec := range records {
		item, err := vault.Unseal(v.masterKey, rec)
		if err != nil {
			return nil, err
		}
		if err := item.Validate(); err != nil {
			return nil, err
		}
		if item.Type != vault.SecretTypeProfile || item.Profile == nil {
			return nil, errors.New("invalid profile descriptor")
		}
		profile := *item.Profile
		index, err := vault.LookupBlindIndex(v.masterKey, vault.SecretTypeProfile, item.Identifier)
		if err != nil {
			return nil, err
		}
		if rec.BlindIndex != index || ids[profile.ID] || names[profile.Name] {
			return nil, errors.New("duplicate or invalid profile descriptor")
		}
		ids[profile.ID], names[profile.Name] = true, true
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	return profiles, nil
}

func (v *Vault) filterProfileRecords(records []*vault.EncryptedRecord) []*vault.EncryptedRecord {
	out := []*vault.EncryptedRecord{}
	for _, rec := range records {
		if rec != nil && rec.ProfileID == v.profileID && rec.Type != vault.SecretTypeProfile {
			out = append(out, rec)
		}
	}
	return out
}
