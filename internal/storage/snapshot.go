package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/vault"
)

type generationKey struct{}

func WithGeneration(ctx context.Context, generation string) context.Context {
	return context.WithValue(ctx, generationKey{}, generation)
}

func (s *SQLiteStore) execGuarded(ctx context.Context, query string, args ...any) (sql.Result, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	generation, _ := ctx.Value(generationKey{}).(string)
	guard, err := tx.ExecContext(ctx, `UPDATE vault_state SET revision=revision WHERE id=1 AND generation=?`, generation)
	if err != nil {
		return nil, err
	}
	n, err := guard.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrVaultChanged
	}
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *SQLiteStore) Snapshot(ctx context.Context, records bool) (*vault.Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := &vault.Snapshot{Records: []*vault.EncryptedRecord{}}
	if err := tx.QueryRowContext(ctx, `SELECT revision,generation FROM vault_state WHERE id=1`).Scan(&out.Revision, &out.Generation); err != nil {
		return nil, err
	}
	metadata := func(key string) ([]byte, error) {
		var b []byte
		err := tx.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key=?`, key).Scan(&b)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return b, err
	}
	if out.Salt, err = metadata(MetadataKDFSalt); err != nil {
		return nil, err
	}
	raw, err := metadata(MetadataKeyCheck)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		out.KeyCheck = new(crypto.Envelope)
		if err := json.Unmarshal(raw, out.KeyCheck); err != nil {
			return nil, err
		}
	}
	raw, err = metadata(MetadataKDFConfig)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		out.KDF = new(config.CryptoConfig)
		if err := json.Unmarshal(raw, out.KDF); err != nil {
			return nil, err
		}
	}
	if records {
		rows, err := tx.QueryContext(ctx, `SELECT id,type,blind_index,parent_blind_index,nonce,ciphertext,version,created_at,updated_at,profile_id FROM records ORDER BY id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			rec, err := scanRecord(rows)
			if err != nil {
				return nil, err
			}
			out.Records = append(out.Records, rec)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// ReplaceVault commits records, salt, verifier and generation together, or none.
func (s *SQLiteStore) ReplaceVault(ctx context.Context, revision int64, generation string, next *vault.Snapshot, emptyOnly bool) error {
	if next == nil || next.Generation == "" || len(next.Salt) < 16 || len(next.Salt) > 64 || next.KeyCheck == nil || len(next.KeyCheck.Nonce) != 12 || len(next.KeyCheck.Ciphertext) < 16 || next.KDF == nil || next.Records == nil {
		return errors.New("incomplete vault snapshot")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE vault_state SET generation=?,revision=revision+1 WHERE id=1 AND revision=? AND generation=?`, next.Generation, revision, generation)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrVaultChanged
	}
	if emptyOnly {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM records)+(SELECT count(*) FROM metadata WHERE key=?)`, MetadataKeyCheck).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("%w: restore requires an uninitialized vault", ErrConflict)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM records`); err != nil {
		return err
	}
	for _, rec := range next.Records {
		if rec == nil {
			return errors.New("nil record in snapshot")
		}
		if _, err := tx.ExecContext(ctx, insertRecordSQL, recordArgs(rec)...); err != nil {
			return err
		}
	}
	keyCheck, err := json.Marshal(next.KeyCheck)
	if err != nil {
		return err
	}
	kdf, err := json.Marshal(next.KDF)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		key   string
		value []byte
	}{{MetadataKDFSalt, next.Salt}, {MetadataKeyCheck, keyCheck}, {MetadataKDFConfig, kdf}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, entry.key, entry.value); err != nil {
			return err
		}
	}
	return tx.Commit()
}
