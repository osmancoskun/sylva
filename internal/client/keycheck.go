package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

// ErrInvalidPassphrase also covers corrupted verification data. Neither case
// may install a key or fall back to cached records.
var ErrInvalidPassphrase = errors.New("incorrect master passphrase or damaged vault verification data")

const keyCheckPurpose = "sylva-vault-key-check-v1"
const keyCheckPlaintext = "sylva master key verified v1"

// NeedsPassphraseSetup reports whether this is an empty vault without a verifier.
// Network errors are returned, never interpreted as a new vault.
func (v *Vault) NeedsPassphraseSetup(ctx context.Context) (bool, error) {
	_, err := v.remote.GetKeyCheck(ctx)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return false, err
	}
	recs, err := v.remote.ListRecords(ctx, "")
	return len(recs) == 0, err
}

func (v *Vault) verifyKey(ctx context.Context, key []byte, allowInitialize bool) error {
	checkKey, err := crypto.DeriveSubkey(key, keyCheckPurpose)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(checkKey)
	state, err := v.remote.GetKeyCheckState(ctx)
	if err == nil {
		if err := verifyKeyCheck(checkKey, &state.Envelope); err != nil {
			return err
		}
		v.remote.SetGeneration(state.Generation)
		return nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("read vault key verifier: %w", err)
	}
	if !allowInitialize {
		return errors.New("vault key verifier is missing; run sylva unlock with the master passphrase")
	}

	// Upgrade legacy vaults only after authenticating every existing record.
	// Use the server directly: cached or partial data cannot establish a key.
	recs, err := v.remote.ListRecords(ctx, "")
	if err != nil {
		return fmt.Errorf("verify existing vault: %w", err)
	}
	for _, rec := range recs {
		if _, err := vault.Unseal(key, rec); err != nil {
			return ErrInvalidPassphrase
		}
	}
	env, err := crypto.Encrypt(checkKey, []byte(keyCheckPlaintext), []byte(keyCheckPurpose))
	if err != nil {
		return err
	}
	if err := v.remote.PutKeyCheck(ctx, env); err != nil {
		if !errors.Is(err, storage.ErrConflict) {
			return fmt.Errorf("initialize vault key verifier: %w", err)
		}
		// A concurrent first unlock may have established a different key.
		state, err = v.remote.GetKeyCheckState(ctx)
		if err != nil {
			return fmt.Errorf("read initialized vault key verifier: %w", err)
		}
		if err := verifyKeyCheck(checkKey, &state.Envelope); err != nil {
			return err
		}
		v.remote.SetGeneration(state.Generation)
		return nil
	}
	return nil
}

func verifyKeyCheck(key []byte, env *crypto.Envelope) error {
	plain, err := crypto.Decrypt(key, env, []byte(keyCheckPurpose))
	if err != nil {
		return ErrInvalidPassphrase
	}
	defer crypto.ZeroBytes(plain)
	if !bytes.Equal(plain, []byte(keyCheckPlaintext)) {
		return ErrInvalidPassphrase
	}
	return nil
}
