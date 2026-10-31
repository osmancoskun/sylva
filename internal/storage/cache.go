package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/osman/sylva/internal/vault"
)

const insertRecordSQL = `INSERT INTO records (
	id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at, profile_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func recordArgs(rec *vault.EncryptedRecord) []any {
	return []any{rec.ID, string(rec.Type), rec.BlindIndex, rec.ParentBlindIndex,
		rec.Envelope.Nonce, rec.Envelope.Ciphertext, rec.Version,
		rec.CreatedAt.UTC().Format(time.RFC3339Nano), rec.UpdatedAt.UTC().Format(time.RFC3339Nano), rec.ProfileID}
}

// Upsert caches an authoritative record, including a newly created ID for a
// previously deleted identifier. Server-side inserts must continue to use Put.
func (s *SQLiteStore) Upsert(ctx context.Context, rec *vault.EncryptedRecord) error {
	if rec == nil {
		return errors.New("encrypted record cannot be nil")
	}
	_, err := s.db.ExecContext(ctx, insertRecordSQL+`
		ON CONFLICT(blind_index) DO UPDATE SET
		id=excluded.id, type=excluded.type, parent_blind_index=excluded.parent_blind_index,
		nonce=excluded.nonce, ciphertext=excluded.ciphertext, version=excluded.version,
		created_at=excluded.created_at, updated_at=excluded.updated_at, profile_id=excluded.profile_id
	`, recordArgs(rec)...)
	return err
}

// ReplaceRecords atomically replaces a complete server snapshot. A filtered
// snapshot replaces only that type, leaving all other cached types untouched.
func (s *SQLiteStore) ReplaceRecords(ctx context.Context, secretType vault.SecretType, records []*vault.EncryptedRecord) error {
	return s.replaceRecords(ctx, nil, secretType, records)
}

func (s *SQLiteStore) ReplaceProfileRecords(ctx context.Context, profile string, kind vault.SecretType, records []*vault.EncryptedRecord) error {
	return s.replaceRecords(ctx, &profile, kind, records)
}

func (s *SQLiteStore) replaceRecords(ctx context.Context, profile *string, secretType vault.SecretType, records []*vault.EncryptedRecord) error {
	for _, rec := range records {
		if rec == nil || (secretType != "" && rec.Type != secretType) || (profile != nil && rec.ProfileID != *profile) {
			return errors.New("invalid record in cache snapshot")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `DELETE FROM records WHERE 1=1`
	var args []any
	if secretType != "" {
		query += ` AND type=?`
		args = append(args, string(secretType))
	}
	if profile != nil {
		query += ` AND profile_id=?`
		args = append(args, *profile)
	}
	_, err = tx.ExecContext(ctx, query, args...)

	if err != nil {
		return err
	}
	for _, rec := range records {
		if _, err := tx.ExecContext(ctx, insertRecordSQL, recordArgs(rec)...); err != nil {
			return fmt.Errorf("cache snapshot record: %w", err)
		}
	}
	return tx.Commit()
}

// DeleteByBlindIndex forgets a server-confirmed missing identifier. Missing
// cached entries are already consistent, so this operation is idempotent.
func (s *SQLiteStore) DeleteByBlindIndex(ctx context.Context, blindIndex string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM records WHERE blind_index = ?`, blindIndex)
	return err
}
