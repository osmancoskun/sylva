package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/transport"
	"github.com/osman/sylva/internal/vault"
)

func TestDeleteConfirmationHasIndependentRequestTimeout(t *testing.T) {
	config.IsolateProcessEnv(t)
	sc, err := config.LoadServerConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "vault.db"), sc.SQLiteBusyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	srv := transport.NewServer(sc, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { done <- srv.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	cfg.ServerURL = "http://" + ln.Addr().String()
	cfg.CacheEnabled = false
	cfg.AgentEnabled = false
	cfg.KeyringEnabled = false
	cfg.MasterPassphrase = "delete-test-passphrase"
	cfg.Crypto.KDFMemoryKB = 1024
	cfg.Crypto.KDFTime = 1
	cfg.Crypto.KDFThreads = 1
	cfg.Timeout = time.Second
	v, err := sylva.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Unlock(ctx, cfg.MasterPassphrase); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		args      []string
		reply     string
		ambiguous bool
		deleted   bool
	}{
		{name: "slow-confirm", args: []string{"password"}, reply: "yes\n", deleted: true},
		{name: "slow-decline", args: []string{"password"}, reply: "n\n"},
		{name: "input-eof", args: []string{"password"}},
		{name: "skip-confirm", args: []string{"password", "--yes"}, deleted: true},
		{name: "auto-type", reply: "y\n", deleted: true},
		{name: "slow-type-selection", reply: "yes\n", ambiguous: true, deleted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.name
			if err := v.PutSecret(ctx, &vault.SecretItem{
				ID: id, Type: vault.SecretTypeToken, Identifier: id,
				Token: &vault.TokenPayload{Name: id, Token: "test-secret"},
			}); err != nil {
				t.Fatal(err)
			}
			if tc.ambiguous {
				if err := v.PutSecret(ctx, &vault.SecretItem{
					ID: id + "-ssh", Type: vault.SecretTypeSSH, Identifier: id,
					SSH: &vault.SSHPayload{Name: id, PrivateKey: "test-key"},
				}); err != nil {
					t.Fatal(err)
				}
			}
			output := runDeleteWithDelayedInput(t, cfg, append([]string{id}, tc.args...), tc.reply, tc.ambiguous)
			exists, err := v.SecretExists(ctx, vault.SecretTypeToken, id)
			if err != nil || exists == tc.deleted {
				t.Fatalf("deleted=%v, exists=%v err=%v", tc.deleted, exists, err)
			}
			if strings.Contains(output, "Deleted password ") != tc.deleted {
				t.Fatalf("unexpected success output: %q", output)
			}
			if tc.ambiguous {
				if exists, err := v.SecretExists(ctx, vault.SecretTypeSSH, id); err != nil || !exists {
					t.Fatalf("unselected SSH secret was affected: exists=%v err=%v", exists, err)
				}
			}
		})
	}
}

// Respond only after observing each prompt, so the delay exercises user wait
// time rather than connection setup. No real terminal or clipboard is touched.
func runDeleteWithDelayedInput(t *testing.T, cfg config.ClientConfig, args []string, reply string, selectType bool) string {
	t.Helper()
	in, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	defer input.Close()
	output, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	defer out.Close()
	previousIn, previousOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = in, out
	defer func() { os.Stdin, os.Stdout = previousIn, previousOut }()
	type result struct {
		text string
		err  error
	}
	read := make(chan result, 1)
	go func() {
		var captured strings.Builder
		var replyErr error
		b := make([]byte, 1)
		for {
			_, err := output.Read(b)
			if err != nil {
				read <- result{captured.String(), replyErr}
				return
			}
			captured.Write(b)
			if selectType && strings.HasSuffix(captured.String(), "Type: ") {
				time.Sleep(cfg.Timeout + 100*time.Millisecond)
				_, replyErr = io.WriteString(input, "1\n")
			}
			if strings.HasSuffix(captured.String(), "[y/N] ") {
				time.Sleep(cfg.Timeout + 100*time.Millisecond)
				if replyErr == nil {
					_, replyErr = io.WriteString(input, reply)
				}
				_ = input.Close()
			}
		}
	}()
	err = runDelete(cfg, args)
	_ = out.Close()
	got := <-read
	if err != nil {
		t.Fatalf("delete after user input: %v (output: %q)", err, got.text)
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	return got.text
}
