package storage

import (
	"database/sql"
	"fmt"
)

// Migrate in a write transaction so simultaneous client/cache/server opens
// cannot race the column check. Existing envelopes remain byte-for-byte intact.
func migrateProfiles(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE vault_state SET revision=revision WHERE id=1`); err != nil {
		return err
	}
	rows, err := tx.Query(`PRAGMA table_info(records)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			_ = rows.Close()
			return err
		}
		if name == "profile_id" {
			found = true
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	if !found {
		if _, err := tx.Exec(`ALTER TABLE records ADD COLUMN profile_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("migrate record profiles: %w", err)
		}
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_records_profile_type ON records(profile_id,type)`); err != nil {
		return err
	}
	return tx.Commit()
}
