package gitbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func testRecord(id, digit string) *vault.EncryptedRecord {
	return &vault.EncryptedRecord{ID: id, BlindIndex: strings.Repeat(digit, 64), Type: vault.SecretTypeToken, Version: 1,
		Envelope: crypto.Envelope{Nonce: make([]byte, 12), Ciphertext: make([]byte, 16)}}
}

func remoteGit(t *testing.T, c *Client, input string, args ...string) string {
	t.Helper()
	base := []string{"--git-dir=" + c.cfg.GitRemote, "-c", "user.name=Test", "-c", "user.email=test@localhost"}
	cmd := exec.Command("git", append(base, args...)...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("remote Git: %v %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func traceGit(t *testing.T, c *Client) func() []string {
	t.Helper()
	directory := t.TempDir()
	log := filepath.Join(directory, "commands")
	wrapper := filepath.Join(directory, "git")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nexec %q \"$@\"\n", log, c.git)
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	c.git = wrapper
	return func() []string {
		raw, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
}

func TestCommandFetchesOnceAndReadsOnlyRequestedRecord(t *testing.T) {
	writer := testClient(t)
	ctx := context.Background()
	if err := writer.PutSalt(ctx, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	first, second := testRecord("one", "1"), testRecord("two", "2")
	for _, rec := range []*vault.EncryptedRecord{first, second} {
		if _, err := writer.PutRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	c, err := New(writer.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.UseCommandSnapshot()
	commands := traceGit(t, c)
	if _, err := c.GetSalt(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetKeyCheckState(ctx); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := c.GetRecordByBlindIndex(ctx, first.BlindIndex); err != nil {
			t.Fatal(err)
		}
	}
	fetches, reads := 0, 0
	for _, line := range commands() {
		if strings.Contains(line, " fetch ") {
			fetches++
		}
		if strings.Contains(line, " cat-file ") {
			reads++
		}
		if strings.Contains(line, " ls-remote ") || strings.Contains(line, " init ") {
			t.Fatalf("repeated repository setup: %s", line)
		}
	}
	if fetches != 1 || reads != 2 {
		t.Fatalf("fetches=%d blob reads=%d, want one fetch, metadata and requested record", fetches, reads)
	}
	before := remoteGit(t, writer, "", "rev-parse", "main:"+recordPath(second.BlindIndex))
	updated := cloneRecord(first)
	updated.Version++
	updated.Envelope.Ciphertext[0] = 1
	if _, err := c.UpdateRecord(ctx, updated); err != nil {
		t.Fatal(err)
	}
	after := remoteGit(t, writer, "", "rev-parse", "main:"+recordPath(second.BlindIndex))
	if before != after {
		t.Fatal("updating one record rewrote another record's blob")
	}
	changes := remoteGit(t, writer, "", "diff-tree", "--no-commit-id", "--name-only", "-r", "main")
	want := recordPath(first.BlindIndex) + "\n" + metadataFile
	if changes != want {
		t.Fatalf("changed files %q, want %q", changes, want)
	}
	fetches = 0
	for _, line := range commands() {
		if strings.Contains(line, " fetch ") {
			fetches++
		}
	}
	if fetches != 1 {
		t.Fatalf("write repeated the command's fetch: %d", fetches)
	}
	// A new CLI command must contact the remote despite the persistent cache.
	next, err := New(writer.cfg)
	if err != nil {
		t.Fatal(err)
	}
	next.UseCommandSnapshot()
	if err := os.Rename(writer.cfg.GitRemote, writer.cfg.GitRemote+".offline"); err != nil {
		t.Fatal(err)
	}
	if _, err := next.GetRecordByBlindIndex(ctx, first.BlindIndex); err == nil {
		t.Fatal("read stale cache after a failed fresh fetch")
	}
}

func TestLegacyVaultMigratesAtomicallyOnFirstWrite(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	rec := testRecord("legacy-id", "a")
	snapshot := &vault.Snapshot{Revision: 9, Salt: bytes.Repeat([]byte{3}, 16), Records: []*vault.EncryptedRecord{rec}}
	raw, err := json.Marshal(document{Format: legacyFormat, Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	blob := remoteGit(t, c, string(raw), "hash-object", "-w", "--stdin")
	tree := remoteGit(t, c, "100644 blob "+blob+"\t"+snapshotFile+"\n", "mktree")
	head := remoteGit(t, c, "Legacy vault\n", "commit-tree", tree)
	remoteGit(t, c, "", "update-ref", "refs/heads/main", head)
	got, err := c.GetRecordByBlindIndex(ctx, rec.BlindIndex)
	if err != nil || !bytes.Equal(got.Envelope.Ciphertext, rec.Envelope.Ciphertext) {
		t.Fatalf("legacy read: %v", err)
	}
	if current := remoteGit(t, c, "", "rev-parse", "main"); current != head {
		t.Fatal("reading migrated the remote")
	}
	if _, err := c.PutRecord(ctx, testRecord("new-id", "b")); err != nil {
		t.Fatal(err)
	}
	files := remoteGit(t, c, "", "ls-tree", "-r", "--name-only", "main")
	if strings.Contains(files, snapshotFile) || !strings.Contains(files, metadataFile) || !strings.Contains(files, recordPath(rec.BlindIndex)) {
		t.Fatalf("invalid migration layout: %s", files)
	}
	if parent := remoteGit(t, c, "", "rev-parse", "main^"); parent != head {
		t.Fatal("migration was not one commit on the original head")
	}
	got, err = c.GetRecordByBlindIndex(ctx, rec.BlindIndex)
	if err != nil || !bytes.Equal(got.Envelope.Ciphertext, rec.Envelope.Ciphertext) {
		t.Fatalf("migration changed existing ciphertext: %v", err)
	}
	s, err := c.Snapshot(ctx)
	if err != nil || s.Revision != 10 || len(s.Records) != 2 {
		t.Fatalf("migration revision/records: %v", err)
	}
}

func TestPinnedCommandsSharingCacheCannotOverwrite(t *testing.T) {
	a := testClient(t)
	ctx := context.Background()
	if err := a.PutSalt(ctx, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	b, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.UseCommandSnapshot()
	b.UseCommandSnapshot()
	for _, c := range []*Client{a, b} {
		if _, err := c.GetSalt(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.PutRecord(ctx, testRecord("a", "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PutRecord(ctx, testRecord("b", "b")); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("stale command overwrote current head: %v", err)
	}
}

func TestCacheLockHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.lock")
	first, err := lockRepository(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second, err := lockRepository(ctx, path)
	if second != nil {
		_ = second.Close()
		t.Fatal("acquired a lock already held by another client")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock cancellation: %v", err)
	}
}
