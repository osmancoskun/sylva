package gitbackend

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/leakcheck"
	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestMain(m *testing.M) { leakcheck.Verify(m) }

func testClient(t *testing.T) *Client {
	t.Helper()
	config.IsolateProcessEnv(t)
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.GitRemote = filepath.Join(t.TempDir(), "remote.git")
	cfg.GitBranch = "main"
	if output, err := exec.Command("git", "init", "--bare", cfg.GitRemote).CombinedOutput(); err != nil {
		t.Fatalf("init disposable remote: %v %s", err, output)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConcurrentGitWritersCannotOverwriteEachOther(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		name := "branch creation"
		if initialized {
			name = "existing branch"
		}
		t.Run(name, func(t *testing.T) {
			a := testClient(t)
			other := a.cfg
			other.GitCacheDir = filepath.Join(t.TempDir(), "cache")
			b, err := New(other)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if initialized {
				if err := a.PutSalt(ctx, make([]byte, 16)); err != nil {
					t.Fatal(err)
				}
			}
			before, err := a.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ready := make(chan struct{}, 2)
			release := make(chan struct{})
			defer close(release)
			results := make(chan error, 2)
			for i, c := range []*Client{a, b} {
				go func() {
					_, err := c.transact(ctx, func(s *vault.Snapshot) error {
						ready <- struct{}{}
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
						s.Salt = make([]byte, 16)
						s.Salt[0] = byte(i + 1)
						return nil
					})
					results <- err
				}()
			}
			for range 2 {
				select {
				case <-ready:
				case err := <-results:
					t.Fatalf("writer failed before reaching shared parent: %v", err)
				case <-ctx.Done():
					t.Fatal("writers did not read their common parent")
				}
			}
			release <- struct{}{}
			release <- struct{}{}
			success, conflicts := 0, 0
			for range 2 {
				err := <-results
				if err == nil {
					success++
				} else if errors.Is(err, storage.ErrConflict) {
					conflicts++
				} else {
					t.Fatal(err)
				}
			}
			if success != 1 || conflicts != 1 {
				t.Fatalf("success=%d conflicts=%d; expected exactly one accepted commit", success, conflicts)
			}
			after, err := a.Snapshot(ctx)
			if err != nil || after.Revision != before.Revision+1 {
				t.Fatalf("branch was not updated exactly once: %v", err)
			}
		})
	}
}

func TestGitRejectsUnsafeRemotesAndRefNames(t *testing.T) {
	c := testClient(t)
	for _, remote := range []string{"http://example.com/repo", "git://example.com/repo", "ext::sh -c bad", "-upload-pack=bad", "https://user:password@example.com/repo", "ssh://host/repo?query", "git@-host:path"} {
		cfg := c.cfg
		cfg.GitRemote = remote
		if _, err := New(cfg); err == nil {
			t.Fatalf("accepted unsafe Git remote %q", remote)
		}
	}
	for _, branch := range []string{"-bad", "../main", "main.lock", "main:other", "main\nother", "main/*", "main//other"} {
		cfg := c.cfg
		cfg.GitBranch = branch
		if _, err := New(cfg); err == nil {
			t.Fatalf("accepted invalid branch %q", branch)
		}
	}
}

func TestGitRejectsOversizedWritesWithoutCreatingBranch(t *testing.T) {
	c := testClient(t)
	c.cfg.MaxVaultBytes = 32
	if err := c.PutSalt(context.Background(), make([]byte, 16)); !errors.Is(err, limits.ErrExceeded) {
		t.Fatalf("oversized snapshot accepted: %v", err)
	}
	c.cfg.MaxVaultBytes = limits.DefaultVaultBytes
	s, err := c.Snapshot(context.Background())
	if err != nil || len(s.Salt) != 0 {
		t.Fatalf("failed write published a partial vault: %v", err)
	}
}

func TestGitRefusesToReplaceAnUnrelatedRepository(t *testing.T) {
	c := testClient(t)
	run := func(input string, args ...string) string {
		t.Helper()
		base := []string{"--git-dir=" + c.cfg.GitRemote, "-c", "user.name=Test", "-c", "user.email=test@localhost"}
		cmd := exec.Command("git", append(base, args...)...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("prepare unrelated repository: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	blob := run("unrelated project", "hash-object", "-w", "--stdin")
	tree := run("100644 blob "+blob+"\tREADME\n", "mktree")
	head := run("Unrelated commit\n", "commit-tree", tree)
	run("", "update-ref", "refs/heads/main", head)
	if err := c.PutSalt(context.Background(), make([]byte, 16)); err == nil {
		t.Fatal("initialized a vault over an unrelated branch")
	}
	if got := run("", "rev-parse", "refs/heads/main"); got != head {
		t.Fatal("unrelated branch was modified")
	}
}
