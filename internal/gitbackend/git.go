// Package gitbackend stores ciphertext-only records in a dedicated Git branch. Every write is one commit published with an exact branch-head lease.
// Remote trees are never checked out, merged, or executed.
package gitbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/vault"
)

const snapshotFile = "sylva-vault.json"
const format = "sylva-git-v2"
const legacyFormat = "sylva-git-v1"
const metadataFile = "vault.json"

type document struct {
	Format   string            `json:"format"`
	Snapshot *vault.Snapshot   `json:"snapshot"`
	Index    map[string]string `json:"index"`
}

type Client struct {
	mu         sync.Mutex
	command    bool
	current    *view
	cfg        config.ClientConfig
	git        string
	ref        string
	generation atomic.Value
	kdf        atomic.Pointer[config.CryptoConfig]
}

func New(cfg config.ClientConfig) (*Client, error) {
	if cfg.GitCacheDir == "" {
		cfg.GitCacheDir = ".sylva/git"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Timeout < 0 {
		return nil, errors.New("git timeout must be positive")
	}
	if err := validateRemote(cfg.GitRemote); err != nil {
		return nil, err
	}
	branch := cfg.GitBranch
	if branch == "" || strings.HasPrefix(branch, "-") || strings.ContainsAny(branch, " ~^:?*[\\\t\r\n\x00") || strings.Contains(branch, "..") || strings.Contains(branch, "@{") {
		return nil, errors.New("invalid git_branch")
	}
	for _, part := range strings.Split(branch, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".lock") {
			return nil, errors.New("invalid git_branch")
		}
	}
	cfg.MaxBodyBytes = limits.OrDefault(cfg.MaxBodyBytes, limits.DefaultBodyBytes)
	cfg.MaxVaultBytes = limits.OrDefault(cfg.MaxVaultBytes, limits.DefaultVaultBytes)
	if err := limits.Validate("max_body_bytes", cfg.MaxBodyBytes); err != nil {
		return nil, err
	}
	if err := limits.Validate("max_vault_bytes", cfg.MaxVaultBytes); err != nil {
		return nil, err
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("the git backend requires the Git executable")
	}
	return &Client{cfg: cfg, git: git, ref: "refs/heads/" + branch}, nil
}

func validateRemote(remote string) error {
	if remote == "" || strings.HasPrefix(remote, "-") || strings.ContainsAny(remote, "\r\n\x00") {
		return errors.New("git_remote must be an SSH/HTTPS URL or an absolute local repository path")
	}
	if filepath.IsAbs(remote) {
		return nil // Local bare repositories are useful for private/offline installations.
	}
	if strings.Contains(remote, "://") {
		u, err := url.Parse(remote)
		if err != nil || (u.Scheme != "ssh" && u.Scheme != "https" && u.Scheme != "file") || u.Path == "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("git_remote supports SSH, HTTPS and local file URLs only")
		}
		if u.Scheme != "file" && u.Hostname() == "" {
			return errors.New("git_remote requires a host")
		}
		if u.Scheme == "file" && (u.Host != "" || !filepath.IsAbs(u.Path)) {
			return errors.New("file Git remotes must be absolute local paths")
		}
		if u.User != nil {
			if _, password := u.User.Password(); password || u.Scheme != "ssh" {
				return errors.New("do not put credentials in git_remote; use SSH or a Git credential helper")
			}
		}
		return nil
	}
	// Restrict scp-style remotes to user@host:path, avoiding remote helpers and
	// option-like hostnames. SSH host aliases in ~/.ssh/config are supported.
	host, path, ok := strings.Cut(remote, ":")
	user, hostname, hasUser := strings.Cut(host, "@")
	if !ok || !hasUser || user == "" || hostname == "" || path == "" || strings.HasPrefix(hostname, "-") || strings.ContainsAny(host, " /\\\t") {
		return errors.New("use an SSH URL, user@host:path, HTTPS URL or absolute local path for git_remote")
	}
	return nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = nil
}
func (c *Client) SetGeneration(generation string) { c.generation.Store(generation) }
func (c *Client) KDFConfig() *config.CryptoConfig { return c.kdf.Load() }

func (c *Client) validate(s *vault.Snapshot) error {
	if s == nil || s.Revision < 0 || s.Records == nil || (len(s.Salt) != 0 && (len(s.Salt) < 16 || len(s.Salt) > 64)) {
		return errors.New("invalid Git vault snapshot")
	}
	if s.KeyCheck != nil && (len(s.Salt) == 0 || len(s.KeyCheck.Nonce) != 12 || len(s.KeyCheck.Ciphertext) < 16) {
		return errors.New("invalid Git vault verifier")
	}
	ids, indexes := map[string]bool{}, map[string]bool{}
	for _, rec := range s.Records {
		if rec == nil || rec.ID == "" || rec.BlindIndex == "" || rec.Type == "" || rec.Version < 1 || len(rec.Envelope.Nonce) != 12 || len(rec.Envelope.Ciphertext) < 16 || ids[rec.ID] || indexes[rec.BlindIndex] {
			return errors.New("invalid or duplicate Git vault record")
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if int64(len(raw)) > c.cfg.MaxBodyBytes {
			return &limits.SizeError{Scope: "Git record", Setting: "max_body_bytes", Limit: c.cfg.MaxBodyBytes}
		}
		ids[rec.ID], indexes[rec.BlindIndex] = true, true
	}
	return nil
}

func (c *Client) run(ctx context.Context, directory string, input io.Reader, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("git command is required")
	}
	base := []string{
		"--no-replace-objects",
		"--git-dir=" + directory,
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
		"-c", "commit.gpgSign=false",
		"-c", "protocol.allow=never",
		"-c", "protocol.ssh.allow=always",
		"-c", "protocol.https.allow=always",
		"-c", "protocol.file.allow=always",
		"-c", "http.sslVerify=true",
		"-c", "http.followRedirects=false",
	}
	cmd := exec.CommandContext(ctx, c.git, append(base, args...)...)
	configureProcess(cmd)
	cmd.Dir = directory
	cmd.WaitDelay = time.Second
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "GIT_") && name != "LC_ALL" {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "LC_ALL=C", "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes", "GIT_AUTHOR_NAME=Sylva", "GIT_AUTHOR_EMAIL=sylva@localhost", "GIT_COMMITTER_NAME=Sylva", "GIT_COMMITTER_EMAIL=sylva@localhost")
	cmd.Stdin = input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limits.Writer{Writer: &stdout, Limit: c.cfg.MaxVaultBytes, Scope: "Git response", Setting: "max_vault_bytes"}
	cmd.Stderr = &limits.Writer{Writer: &stderr, Limit: 64 << 10, Scope: "Git diagnostics", Setting: "max_vault_bytes"}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		detail := strings.TrimSpace(stderr.String())
		if args[0] == "push" {
			detail += " " + strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("git %s failed: %w: %s", args[0], err, detail)
	}
	return stdout.Bytes(), nil
}
