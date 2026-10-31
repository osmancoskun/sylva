package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
)

func runPasswd(cfg config.ClientConfig) error {
	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	first, err := promptMasterPassphrase("New master passphrase: ")
	if err != nil {
		return err
	}
	second, err := promptMasterPassphrase("Confirm new master passphrase: ")
	if err != nil {
		return err
	}
	if first != second {
		return errors.New("master passphrases do not match")
	}
	if strings.TrimSpace(first) == "" {
		return errors.New("master passphrase cannot be empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), max(cfg.Timeout, time.Minute))
	defer cancel()
	if err := v.ChangePassphrase(ctx, first); err != nil {
		return err
	}
	if err := runLock(cfg); err != nil {
		return fmt.Errorf("master passphrase changed, but local session cleanup failed: %w", err)
	}
	fmt.Println("Master passphrase changed. Run sylva unlock with the new passphrase on each device.")
	return nil
}

func runBackup(cfg config.ClientConfig, path string) error {
	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), max(cfg.Timeout, time.Minute))
	defer cancel()
	if err := v.Backup(ctx, path); err != nil {
		return err
	}
	fmt.Printf("Encrypted backup saved to %s\n", path)
	return nil
}

func runRestore(cfg config.ClientConfig, path string) error {
	passphrase := cfg.MasterPassphrase
	if strings.TrimSpace(passphrase) == "" {
		var err error
		passphrase, err = promptMasterPassphrase("Backup master passphrase: ")
		if err != nil {
			return err
		}
	}
	v, err := sylva.OpenForCommand(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), max(cfg.Timeout, time.Minute))
	defer cancel()
	if err := v.Restore(ctx, path, passphrase); err != nil {
		return err
	}
	if err := runLock(cfg); err != nil {
		return fmt.Errorf("vault restored, but local session cleanup failed: %w", err)
	}
	fmt.Println("Vault restored. Run sylva unlock with the backup's master passphrase.")
	return nil
}
