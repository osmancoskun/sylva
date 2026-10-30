package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/osman/sylva/internal/agent"
	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
)

func openUnlocked(cfg config.ClientConfig) (*sylva.Vault, error) {
	v, err := sylva.Open(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.AgentEnabled {
		if ac, err := agent.DialWithLimit(cfg.AgentSocketPath, cfg.Timeout, cfg.AgentMaxRequestBytes); err == nil {
			key, keyErr := ac.MasterKey()
			if errors.Is(keyErr, agent.ErrCleanupIncomplete) {
				_ = v.Close()
				return nil, keyErr
			}
			if keyErr == nil {
				ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
				err := v.UnlockWithKey(ctx, key)
				cancel()
				if err != nil {
					crypto.ZeroBytes(key)
					_ = v.Close()
					return nil, err
				}
				crypto.ZeroBytes(key)
				return v, nil
			}
		}
	}

	passphrase, err := resolvePassphrase(cfg, v)
	if err != nil {
		_ = v.Close()
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := v.Unlock(ctx, passphrase); err != nil {
		_ = v.Close()
		return nil, err
	}
	return v, nil
}

func resolvePassphrase(cfg config.ClientConfig, v *sylva.Vault) (string, error) {
	if cfg.AgentEnabled {
		if ac, err := agent.DialWithLimit(cfg.AgentSocketPath, cfg.Timeout, cfg.AgentMaxRequestBytes); err == nil {
			if _, err := ac.Status(); err != nil {
				return "", err
			}
		} else if !agentAbsent(err) {
			return "", err
		}
	}
	if strings.TrimSpace(cfg.MasterPassphrase) != "" {
		return cfg.MasterPassphrase, nil
	}
	if cfg.KeyringEnabled {
		kr := agent.NewKeyring(true, cfg.KeyringService, cfg.KeyringUser)
		secret, err := kr.Get()
		if err == nil && strings.TrimSpace(secret) != "" {
			return secret, nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	setup, err := v.NeedsPassphraseSetup(ctx)
	if err != nil {
		return "", fmt.Errorf("check vault setup: %w", err)
	}
	label := "Master passphrase: "
	if setup {
		label = "New master passphrase: "
	}
	passphrase, err := promptMasterPassphrase(label)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(passphrase) == "" {
		return "", errors.New("master passphrase cannot be empty")
	}
	if setup {
		confirmation, err := promptMasterPassphrase("Confirm master passphrase: ")
		if err != nil {
			return "", err
		}
		if passphrase != confirmation {
			return "", errors.New("master passphrases do not match")
		}
	}
	return passphrase, nil
}

func runUnlock(cfg config.ClientConfig) error {
	v, err := sylva.Open(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	passphrase, err := resolvePassphrase(cfg, v)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := v.Unlock(ctx, passphrase); err != nil {
		return err
	}

	if cfg.KeyringEnabled {
		kr := agent.NewKeyring(true, cfg.KeyringService, cfg.KeyringUser)
		if err := kr.Set(passphrase); err != nil {
			return fmt.Errorf("store passphrase in keyring: %w", err)
		}
	}

	if !cfg.AgentEnabled {
		fmt.Println("Vault unlocked for this process")
		return nil
	}

	ac, err := ensureAgent(cfg)
	if err != nil {
		return fmt.Errorf("start session agent: %w", err)
	}
	key, err := v.CopyMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	if err := ac.Unlock(key); err != nil {
		return err
	}
	fmt.Println("Session unlocked")
	return nil
}

func runLock(cfg config.ClientConfig) error {
	var kr agent.Keyring
	if cfg.KeyringEnabled {
		kr = agent.NewKeyring(true, cfg.KeyringService, cfg.KeyringUser)
	}
	var lockAgent func() error
	if cfg.AgentEnabled {
		lockAgent = func() error {
			ac, err := agent.DialWithLimit(cfg.AgentSocketPath, cfg.Timeout, cfg.AgentMaxRequestBytes)
			if err != nil {
				if agentAbsent(err) {
					return nil
				}
				return fmt.Errorf("contact session agent: %w", err)
			}
			return ac.Lock()
		}
	}
	if err := lockSession(kr, lockAgent); err != nil {
		return fmt.Errorf("session cleanup incomplete: %w", err)
	}
	fmt.Println("Session locked")
	return nil
}

func agentAbsent(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// A failed persistent-key deletion must never skip the in-memory key wipe.
func lockSession(kr agent.Keyring, lockAgent func() error) error {
	var keyringErr, agentErr error
	if kr != nil {
		if err := kr.Delete(); err != nil {
			keyringErr = fmt.Errorf("clear keyring: %w", err)
		}
	}
	if lockAgent != nil {
		if err := lockAgent(); err != nil {
			agentErr = fmt.Errorf("lock agent: %w", err)
		}
	}
	return errors.Join(keyringErr, agentErr)
}

func runAgent(cfg config.ClientConfig) error {
	log, closer, err := newAgentLogger(cfg)
	if err != nil {
		return err
	}
	defer closer()

	clip, err := clipboard.NewManager(cfg.ClipboardBackend, cfg.ClipboardFile, cfg.ClipboardClearAfter)
	if err != nil {
		log.Error("initialize agent clipboard", slog.Any("error", err))
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = agent.Serve(ctx, cfg.AgentSocketPath, clip, log, agent.Options{IdleTimeout: cfg.AgentIdleTimeout, RequestTimeout: cfg.AgentRequestTimeout, MaxRequestBytes: cfg.AgentMaxRequestBytes, MaxConnections: cfg.AgentMaxConnections, OnLock: func() error {
		return agent.NewKeyring(cfg.KeyringEnabled, cfg.KeyringService, cfg.KeyringUser).Delete()
	}})
	if err != nil {
		log.Error("session agent exited", slog.Any("error", err))
		return err
	}
	log.Info("session agent stopped")
	return nil
}

func newAgentLogger(cfg config.ClientConfig) (*slog.Logger, func(), error) {
	writers := []io.Writer{os.Stderr}
	var file *os.File
	if path := strings.TrimSpace(cfg.AgentLogPath); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, nil, fmt.Errorf("create agent log directory: %w", err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open agent log: %w", err)
		}
		file = f
		writers = append(writers, f)
	}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(writers...), &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	return logger, func() {
		if file != nil {
			_ = file.Close()
		}
	}, nil
}

func copyToClipboard(cfg config.ClientConfig, secretType, identifier, secret string) error {
	if cfg.AgentEnabled {
		ac, err := ensureAgent(cfg)
		if err != nil {
			return fmt.Errorf("clipboard copy needs the session agent: %w", err)
		}
		if err := ac.Copy(secret, secretType, identifier); err != nil {
			return err
		}
		fmt.Printf("Copied to clipboard (clears in %s)\n", cfg.ClipboardClearAfter)
		return nil
	}

	clip, err := clipboard.NewManager(cfg.ClipboardBackend, cfg.ClipboardFile, cfg.ClipboardClearAfter)
	if err != nil {
		return err
	}
	defer clip.Close()
	if clip.HoldsUntilClear() {
		return errors.New("os clipboard requires SYLVA_AGENT_ENABLED=true so `sylva get` can exit while the session agent holds the selection")
	}
	if err := clip.Copy(secret); err != nil {
		return err
	}
	fmt.Printf("Copied to clipboard (clears in %s)\n", cfg.ClipboardClearAfter)
	return nil
}

func ensureAgent(cfg config.ClientConfig) (*agent.Client, error) {
	if ac, err := agent.DialWithLimit(cfg.AgentSocketPath, cfg.Timeout, cfg.AgentMaxRequestBytes); err == nil {
		return ac, nil
	}
	if err := startDetachedAgent(cfg); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(cfg.Timeout)
	var last error
	for time.Now().Before(deadline) {
		ac, err := agent.DialWithLimit(cfg.AgentSocketPath, 50*time.Millisecond, cfg.AgentMaxRequestBytes)
		if err == nil {
			return ac, nil
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	if last == nil {
		last = agent.ErrUnavailable
	}
	if path := strings.TrimSpace(cfg.AgentLogPath); path != "" {
		return nil, fmt.Errorf("session agent did not become ready; see %s: %w", path, last)
	}
	return nil, last
}
