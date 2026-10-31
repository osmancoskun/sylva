package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/vault"
)

const schema = `
CREATE TABLE IF NOT EXISTS records (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	blind_index TEXT NOT NULL UNIQUE,
	parent_blind_index TEXT NOT NULL DEFAULT '',
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	version INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	profile_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_records_type ON records(type);

CREATE TABLE IF NOT EXISTS metadata (
	key TEXT PRIMARY KEY,
	value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_state (
	id INTEGER PRIMARY KEY CHECK (id=1),
	revision INTEGER NOT NULL,
	generation TEXT NOT NULL
);
INSERT OR IGNORE INTO vault_state VALUES (1,0,'');
`

// SQLiteStore is a file-backed Store implementation.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (or creates) a SQLite database at path using the given busy timeout.
func OpenSQLite(path string, busyTimeout time.Duration) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite database path cannot be empty")
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create sqlite directory %s: %w", dir, err)
		}
	}

	busyMS := busyTimeout.Milliseconds()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", filepath.ToSlash(path), busyMS)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate sqlite schema: %w", err)
	}
	if err := migrateProfiles(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	for _, table := range []string{"records", "metadata"} {
		for _, operation := range []string{"INSERT", "UPDATE", "DELETE"} {
			q := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS revision_%s_%s AFTER %s ON %s BEGIN UPDATE vault_state SET revision=revision+1 WHERE id=1; END`, table, operation, operation, table)
			if _, err := db.Exec(q); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("create revision trigger: %w", err)
			}
		}
	}

	return &SQLiteStore{db: db}, nil
}

// Close releases the underlying database handle.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Put inserts an encrypted record. Existing IDs or blind indexes return ErrConflict.
func (s *SQLiteStore) Put(ctx context.Context, rec *vault.EncryptedRecord) error {
	if rec == nil {
		return errors.New("encrypted record cannot be nil")
	}

	if _, err := s.GetByID(ctx, rec.ID); err == nil {
		return fmt.Errorf("%w: record already exists", ErrConflict)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	if _, err := s.GetByBlindIndex(ctx, rec.BlindIndex); err == nil {
		return fmt.Errorf("%w: record already exists", ErrConflict)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	_, err := s.execGuarded(ctx, `
		INSERT INTO records (
			id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at, profile_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rec.ID, string(rec.Type), rec.BlindIndex, rec.ParentBlindIndex, rec.Envelope.Nonce, rec.Envelope.Ciphertext, rec.Version, rec.CreatedAt.UTC().Format(time.RFC3339Nano), rec.UpdatedAt.UTC().Format(time.RFC3339Nano), rec.ProfileID)
	if err != nil {
		if isUniqueConstraint(err) {
			return fmt.Errorf("%w: record already exists", ErrConflict)
		}
		return fmt.Errorf("put record %s: %w", rec.ID, err)
	}
	return nil
}

// Update atomically replaces version N with N+1. Stale or skipped versions
// return ErrVersionConflict; missing IDs return ErrNotFound.
func (s *SQLiteStore) Update(ctx context.Context, rec *vault.EncryptedRecord) error {
	if rec == nil {
		return errors.New("encrypted record cannot be nil")
	}

	if rec.Version <= 1 {
		return ErrVersionConflict
	}

	res, err := s.execGuarded(ctx, `
		UPDATE records SET
			type=?,
			blind_index=?,
			parent_blind_index=?,
			nonce=?,
			ciphertext=?,
			version=?,
			updated_at=?
		WHERE id=? AND version=? AND profile_id=?
	`, string(rec.Type), rec.BlindIndex, rec.ParentBlindIndex, rec.Envelope.Nonce, rec.Envelope.Ciphertext, rec.Version, rec.UpdatedAt.UTC().Format(time.RFC3339Nano), rec.ID, rec.Version-1, rec.ProfileID)
	if err != nil {
		if isUniqueConstraint(err) {
			return fmt.Errorf("%w: record already exists", ErrConflict)
		}
		return fmt.Errorf("update record %s: %w", rec.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.GetByID(ctx, rec.ID); err != nil {
			return err
		}
		return ErrVersionConflict
	}
	return nil
}

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "constraint")
}

// GetByID loads a record by its client-generated identifier.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*vault.EncryptedRecord, error) {
	return s.scanOne(s.db.QueryRowContext(ctx, `
		SELECT id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at, profile_id
		FROM records WHERE id = ?
	`, id))
}

// GetByBlindIndex loads a record by its HMAC blind index.
func (s *SQLiteStore) GetByBlindIndex(ctx context.Context, blindIndex string) (*vault.EncryptedRecord, error) {
	return s.scanOne(s.db.QueryRowContext(ctx, `
		SELECT id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at, profile_id
		FROM records WHERE blind_index = ?
	`, blindIndex))
}

// List returns all records, optionally filtered by secret type.
func (s *SQLiteStore) List(ctx context.Context, kind vault.SecretType) ([]*vault.EncryptedRecord, error) {
	return s.list(ctx, kind, nil)
}

func (s *SQLiteStore) ListProfile(ctx context.Context, profile string, kind vault.SecretType) ([]*vault.EncryptedRecord, error) {
	return s.list(ctx, kind, &profile)
}

func (s *SQLiteStore) list(ctx context.Context, kind vault.SecretType, profile *string) ([]*vault.EncryptedRecord, error) {
	query := `SELECT id,type,blind_index,parent_blind_index,nonce,ciphertext,version,created_at,updated_at,profile_id FROM records WHERE 1=1`
	var args []any
	if kind != "" {
		query += ` AND type=?`
		args = append(args, string(kind))
	}
	if profile != nil {
		query += ` AND profile_id=?`
		args = append(args, *profile)
	}
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY updated_at DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list records: %w", err)
	}
	defer rows.Close()
	var out []*vault.EncryptedRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Delete removes a record by ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	res, err := s.execGuarded(ctx, `DELETE FROM records WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete record %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PutMetadata stores an opaque metadata value. Existing keys are overwritten.
func (s *SQLiteStore) PutMetadata(ctx context.Context, key string, value []byte) error {
	_, err := s.execGuarded(ctx, `
		INSERT INTO metadata (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value
	`, key, value)
	if err != nil {
		return fmt.Errorf("put metadata %s: %w", key, err)
	}
	return nil
}

// CreateMetadata initializes metadata without replacing an existing value.
func (s *SQLiteStore) CreateMetadata(ctx context.Context, key string, value []byte) error {
	_, err := s.execGuarded(ctx, `INSERT INTO metadata (key, value) VALUES (?, ?)`, key, value)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	return err
}

// GetMetadata loads an opaque metadata value.
func (s *SQLiteStore) GetMetadata(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get metadata %s: %w", key, err)
	}
	return value, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *SQLiteStore) scanOne(row rowScanner) (*vault.EncryptedRecord, error) {
	rec, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return rec, err
}

func scanRecord(row rowScanner) (*vault.EncryptedRecord, error) {
	var (
		rec              vault.EncryptedRecord
		typ              string
		created, updated string
		nonce, ct        []byte
	)
	if err := row.Scan(&rec.ID, &typ, &rec.BlindIndex, &rec.ParentBlindIndex, &nonce, &ct, &rec.Version, &created, &updated, &rec.ProfileID); err != nil {
		return nil, err
	}
	rec.Type = vault.SecretType(typ)
	rec.Envelope = crypto.Envelope{Nonce: nonce, Ciphertext: ct}

	var err error
	rec.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		rec.CreatedAt, err = time.Parse(time.RFC3339, created)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
	}
	rec.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		rec.UpdatedAt, err = time.Parse(time.RFC3339, updated)
		if err != nil {
			return nil, fmt.Errorf("parse updated_at: %w", err)
		}
	}
	return &rec, nil
}
