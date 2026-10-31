package gitbackend

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func (c *Client) Ping(ctx context.Context) (*api.StatusResponse, error) {
	if err := c.withView(ctx, false, func(context.Context, *view) error { return nil }); err != nil {
		return nil, err
	}
	return &api.StatusResponse{Status: "ok", Service: "git", Version: c.cfg.Version, Timestamp: time.Now().UTC()}, nil
}

func (c *Client) Snapshot(ctx context.Context) (*vault.Snapshot, error) { return c.transact(ctx, nil) }

func (c *Client) GetSalt(ctx context.Context) ([]byte, error) {
	var salt []byte
	err := c.withView(ctx, false, func(_ context.Context, v *view) error {
		if len(v.meta.Salt) == 0 {
			return storage.ErrNotFound
		}
		salt = append([]byte{}, v.meta.Salt...)
		return nil
	})
	return salt, err
}

var errUnchanged = errors.New("git vault unchanged")

func (c *Client) PutSalt(ctx context.Context, salt []byte) error {
	err := c.withView(ctx, true, func(_ context.Context, v *view) error {
		if len(v.meta.Salt) != 0 {
			if bytes.Equal(v.meta.Salt, salt) {
				return errUnchanged
			}
			return storage.ErrConflict
		}
		v.meta.Salt = append([]byte{}, salt...)
		kdf := c.cfg.Crypto
		v.meta.KDF = &kdf
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

func (c *Client) GetKeyCheck(ctx context.Context) (*crypto.Envelope, error) {
	state, err := c.GetKeyCheckState(ctx)
	if err != nil {
		return nil, err
	}
	return &state.Envelope, nil
}

func (c *Client) GetKeyCheckState(ctx context.Context) (*api.KeyCheckBody, error) {
	state := new(api.KeyCheckBody)
	err := c.withView(ctx, false, func(_ context.Context, v *view) error {
		if v.meta.KeyCheck == nil {
			return storage.ErrNotFound
		}
		check := v.meta.KeyCheck
		*state = api.KeyCheckBody{Envelope: crypto.Envelope{Nonce: append([]byte{}, check.Nonce...), Ciphertext: append([]byte{}, check.Ciphertext...)}, Generation: v.meta.Generation}
		return nil
	})
	return state, err
}

func (c *Client) PutKeyCheck(ctx context.Context, check *crypto.Envelope) error {
	return c.withView(ctx, true, func(_ context.Context, v *view) error {
		if v.meta.KeyCheck != nil {
			return storage.ErrConflict
		}
		if len(v.meta.Salt) == 0 || check == nil {
			return errors.New("initialize the Git vault salt before its verifier")
		}
		v.meta.KeyCheck = check
		return nil
	})
}

func (c *Client) ListRecords(ctx context.Context, kind vault.SecretType) ([]*vault.EncryptedRecord, error) {
	out := []*vault.EncryptedRecord{}
	err := c.withView(ctx, false, func(ctx context.Context, v *view) error {
		for _, index := range sortedIndexes(v.index) {
			rec, err := c.record(ctx, v, index)
			if err != nil {
				return err
			}
			if kind == "" || kind == rec.Type {
				out = append(out, cloneRecord(rec))
			}
		}
		return nil
	})
	return out, err
}

func cloneRecord(rec *vault.EncryptedRecord) *vault.EncryptedRecord {
	copy := *rec
	copy.Envelope.Nonce = append([]byte{}, rec.Envelope.Nonce...)
	copy.Envelope.Ciphertext = append([]byte{}, rec.Envelope.Ciphertext...)
	return &copy
}

func (c *Client) GetRecord(ctx context.Context, id string) (*vault.EncryptedRecord, error) {
	out := new(vault.EncryptedRecord)
	err := c.withView(ctx, false, func(ctx context.Context, v *view) error {
		index, ok := v.index[id]
		if !ok {
			return storage.ErrNotFound
		}
		rec, err := c.record(ctx, v, index)
		if err == nil {
			*out = *cloneRecord(rec)
		}
		return err
	})
	return out, err
}

func (c *Client) GetRecordByBlindIndex(ctx context.Context, index string) (*vault.EncryptedRecord, error) {
	out := new(vault.EncryptedRecord)
	err := c.withView(ctx, false, func(ctx context.Context, v *view) error {
		rec, err := c.record(ctx, v, index)
		if err == nil {
			*out = *cloneRecord(rec)
		}
		return err
	})
	return out, err
}

func (c *Client) PutRecord(ctx context.Context, rec *vault.EncryptedRecord) (*vault.EncryptedRecord, error) {
	if rec == nil {
		return nil, errors.New("encrypted record cannot be nil")
	}
	err := c.withView(ctx, true, func(_ context.Context, v *view) error {
		if _, exists := v.index[rec.ID]; exists {
			return storage.ErrConflict
		}
		if _, exists := v.files[rec.BlindIndex]; exists {
			return storage.ErrConflict
		}
		if _, exists := v.loaded[rec.BlindIndex]; exists {
			return storage.ErrConflict
		}
		v.index[rec.ID] = rec.BlindIndex
		v.loaded[rec.BlindIndex], v.dirty[rec.BlindIndex] = cloneRecord(rec), cloneRecord(rec)
		return nil
	})
	return rec, err
}

func (c *Client) UpdateRecord(ctx context.Context, rec *vault.EncryptedRecord) (*vault.EncryptedRecord, error) {
	if rec == nil {
		return nil, errors.New("encrypted record cannot be nil")
	}
	err := c.withView(ctx, true, func(ctx context.Context, v *view) error {
		index, exists := v.index[rec.ID]
		if !exists {
			return storage.ErrNotFound
		}
		old, err := c.record(ctx, v, index)
		if err != nil {
			return err
		}
		if rec.Version <= 1 || old.Version != rec.Version-1 {
			return storage.ErrVersionConflict
		}
		if rec.BlindIndex != index {
			if _, exists := v.files[rec.BlindIndex]; exists {
				return storage.ErrConflict
			}
			if _, exists := v.loaded[rec.BlindIndex]; exists {
				return storage.ErrConflict
			}
			delete(v.files, index)
			delete(v.loaded, index)
			delete(v.dirty, index)
		}
		v.index[rec.ID] = rec.BlindIndex
		v.loaded[rec.BlindIndex], v.dirty[rec.BlindIndex] = cloneRecord(rec), cloneRecord(rec)
		return nil
	})
	return rec, err
}

func (c *Client) DeleteRecord(ctx context.Context, id string) error {
	return c.withView(ctx, true, func(_ context.Context, v *view) error {
		index, exists := v.index[id]
		if !exists {
			return storage.ErrNotFound
		}
		delete(v.index, id)
		delete(v.files, index)
		delete(v.loaded, index)
		delete(v.dirty, index)
		return nil
	})
}

func (c *Client) ReplaceVault(ctx context.Context, expected, next *vault.Snapshot, emptyOnly bool) error {
	if expected == nil || next == nil || next.Generation == "" || next.Generation == expected.Generation || next.KeyCheck == nil || next.KDF == nil || len(next.Salt) < 16 {
		return errors.New("incomplete Git replacement snapshot")
	}
	if err := c.validate(next); err != nil {
		return err
	}
	return c.withView(ctx, true, func(_ context.Context, v *view) error {
		if v.meta.Revision != expected.Revision || v.meta.Generation != expected.Generation {
			return storage.ErrVaultChanged
		}
		if emptyOnly && (len(v.index) != 0 || v.meta.KeyCheck != nil) {
			return storage.ErrConflict
		}
		revision := v.meta.Revision
		v.replace(next)
		v.meta.Revision = revision
		return nil
	})
}
