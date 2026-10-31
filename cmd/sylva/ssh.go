package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/sshunlock"
	"golang.org/x/crypto/ssh"
)

func sshRegistration(cfg config.ClientConfig) (path, endpoint string) {
	endpoint = sshunlock.Endpoint(cfg.ServerURL, cfg.APIPrefix)
	if cfg.Backend == "git" {
		endpoint = "git\x00" + cfg.GitRemote + "\x00" + cfg.GitBranch
	}
	return sshunlock.Path(cfg.SSHUnlockDir, endpoint), endpoint
}

func runSSH(cfg config.ClientConfig, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sylva ssh add <ed25519-public-key-file> | status | remove")
	}
	path, endpoint := sshRegistration(cfg)
	switch args[0] {
	case "add":
		if len(args) != 2 {
			return errors.New("usage: sylva ssh add <ed25519-public-key-file>")
		}
		return registerSSH(cfg, args[1], path, endpoint)
	case "status":
		if len(args) != 1 {
			return errors.New("usage: sylva ssh status")
		}
		fingerprint, err := sshunlock.Fingerprint(path, endpoint)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No SSH unlock key registered for this server on this device")
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Printf("SSH unlock key: %s\nLocal registration: %s\n", fingerprint, path)
		return nil
	case "remove":
		if len(args) != 1 {
			return errors.New("usage: sylva ssh remove")
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Println("Local SSH unlock registration removed; run sylva lock to close an open session")
		return nil
	default:
		return errors.New("usage: sylva ssh add <ed25519-public-key-file> | status | remove")
	}
}

func registerSSH(cfg config.ClientConfig, publicKeyPath, path, endpoint string) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("SSH unlock is already registered; use sylva ssh remove before replacing it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	publicKey, err := readSSHUnlockPublicKey(publicKeyPath)
	if err != nil {
		return err
	}
	v, err := sylva.OpenForCommand(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	setup, err := v.NeedsPassphraseSetup(ctx)
	cancel()
	if err != nil {
		return err
	}
	if setup {
		return errors.New("initialize the master passphrase with sylva unlock before adding an SSH key")
	}
	// Enrollment always verifies the master passphrase, even if a Sylva session
	// is already open. An existing SSH credential cannot enroll another one.
	passphrase := cfg.MasterPassphrase
	if passphrase == "" {
		passphrase, err = promptMasterPassphrase("Master passphrase: ")
		if err != nil {
			return err
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), cfg.Timeout)
	err = v.Unlock(ctx, passphrase)
	cancel()
	if err != nil {
		return err
	}
	if err := enrollVerifiedSSH(cfg, v, publicKey, path, endpoint); err != nil {
		return err
	}
	fmt.Println("SSH unlock registered for this server on this device. Use sylva unlock --ssh.")
	return nil
}

func readSSHUnlockPublicKey(path string) (ssh.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16*1024+1))
	if err != nil {
		return nil, err
	}
	return sshunlock.ParsePublicKey(raw)
}

// The caller must authenticate the master passphrase before enrollment.
func enrollVerifiedSSH(cfg config.ClientConfig, v *sylva.Vault, publicKey ssh.PublicKey, path, endpoint string) error {
	key, err := v.CopyMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	signer, connection, err := sshunlock.Connect(os.Getenv("SSH_AUTH_SOCK"), max(time.Minute, cfg.Timeout))
	if err != nil {
		return err
	}
	defer connection.Close()
	return sshunlock.Register(path, endpoint, publicKey, key, signer)
}

// Setup can reuse a registration only after master-passphrase authentication,
// proving agent access and checking that it unwraps the same verified vault key.
// Explicit `ssh add` retains its refusal to replace an existing registration.
func ensureVerifiedSSH(cfg config.ClientConfig, v *sylva.Vault, publicKey ssh.PublicKey, path, endpoint string) error {
	fingerprint, err := sshunlock.Fingerprint(path, endpoint)
	if errors.Is(err, os.ErrNotExist) {
		if err := enrollVerifiedSSH(cfg, v, publicKey, path, endpoint); err != nil {
			return fmt.Errorf("register SSH key (retry with sylva ssh add <public-key-file>): %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read existing SSH registration (use sylva ssh remove before registering it again): %w", err)
	}
	if fingerprint != ssh.FingerprintSHA256(publicKey) {
		return errors.New("SSH unlock already uses a different key; use sylva ssh remove before registering another key")
	}
	verifiedKey, err := v.CopyMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(verifiedKey)
	signer, connection, err := sshunlock.Connect(os.Getenv("SSH_AUTH_SOCK"), max(time.Minute, cfg.Timeout))
	if err != nil {
		return err
	}
	defer connection.Close()
	registeredKey, err := sshunlock.Open(path, endpoint, signer)
	if err != nil {
		return fmt.Errorf("verify existing SSH unlock (check ssh-agent; re-register with sylva ssh remove and sylva ssh add if needed): %w", err)
	}
	defer crypto.ZeroBytes(registeredKey)
	if subtle.ConstantTimeCompare(verifiedKey, registeredKey) != 1 {
		return errors.New("existing SSH registration does not match the current vault key; re-register with sylva ssh remove and sylva ssh add <public-key-file>")
	}
	return nil
}

func runUnlockCommand(cfg config.ClientConfig, args []string) error {
	if len(args) == 0 {
		return runUnlock(cfg)
	}
	if len(args) == 1 && args[0] == "--ssh" {
		return runUnlockSSH(cfg)
	}
	return errors.New("usage: sylva unlock [--ssh]")
}

func runUnlockSSH(cfg config.ClientConfig) error {
	if !cfg.AgentEnabled {
		return errors.New("SSH unlock requires agent_enabled=true to keep the unlocked session")
	}
	v, err := sylva.OpenForCommand(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	path, endpoint := sshRegistration(cfg)
	if _, err := sshunlock.Fingerprint(path, endpoint); err != nil {
		return fmt.Errorf("read SSH unlock registration (use sylva ssh add first): %w", err)
	}
	signer, connection, err := sshunlock.Connect(os.Getenv("SSH_AUTH_SOCK"), max(time.Minute, cfg.Timeout))
	if err != nil {
		return err
	}
	defer connection.Close()
	key, err := sshunlock.Open(path, endpoint, signer)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := v.UnlockWithKey(ctx, key); err != nil {
		return fmt.Errorf("verify SSH-unwrapped key with server (after a master passphrase change, register SSH again): %w", err)
	}
	return publishSessionKey(cfg, v)
}
