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
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_type ON records(type);

CREATE TABLE IF NOT EXISTS metadata (
	key TEXT PRIMARY KEY,
	value BLOB NOT NULL
);
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

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO records (
			id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rec.ID, string(rec.Type), rec.BlindIndex, rec.ParentBlindIndex, rec.Envelope.Nonce, rec.Envelope.Ciphertext, rec.Version, rec.CreatedAt.UTC().Format(time.RFC3339Nano), rec.UpdatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		if isUniqueConstraint(err) {
			return fmt.Errorf("%w: record already exists", ErrConflict)
		}
		return fmt.Errorf("put record %s: %w", rec.ID, err)
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
		SELECT id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at
		FROM records WHERE id = ?
	`, id))
}

// GetByBlindIndex loads a record by its HMAC blind index.
func (s *SQLiteStore) GetByBlindIndex(ctx context.Context, blindIndex string) (*vault.EncryptedRecord, error) {
	return s.scanOne(s.db.QueryRowContext(ctx, `
		SELECT id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at
		FROM records WHERE blind_index = ?
	`, blindIndex))
}

// List returns all records, optionally filtered by secret type.
func (s *SQLiteStore) List(ctx context.Context, secretType vault.SecretType) ([]*vault.EncryptedRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if secretType == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at
			FROM records ORDER BY updated_at DESC
		`)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, type, blind_index, parent_blind_index, nonce, ciphertext, version, created_at, updated_at
			FROM records WHERE type = ? ORDER BY updated_at DESC
		`, string(secretType))
	}
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM records WHERE id = ?`, id)
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
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO metadata (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value
	`, key, value)
	if err != nil {
		return fmt.Errorf("put metadata %s: %w", key, err)
	}
	return nil
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
	if err := row.Scan(&rec.ID, &typ, &rec.BlindIndex, &rec.ParentBlindIndex, &nonce, &ct, &rec.Version, &created, &updated); err != nil {
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
