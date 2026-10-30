package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
	"github.com/osman/sylva/internal/api"
)

type runningAgent struct {
	socket string
	client *agent.Client
	cancel context.CancelFunc
	done   chan error
}

func startAgent(t *testing.T, socket string, opt agent.Options) *runningAgent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a := &runningAgent{socket: socket, cancel: cancel, done: make(chan error, 1)}
	go func() { a.done <- agent.Serve(ctx, socket, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), opt) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-a.done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("agent did not stop")
		}
	})
	a.client = waitDial(t, socket, 2*time.Second)
	return a
}

func rawConnection(t *testing.T, socket string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSecondAgentPreservesLiveSession(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	a := startAgent(t, socket, agent.Options{})
	key := bytes.Repeat([]byte{7}, 32)
	if err := a.client.Unlock(key); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		if err := agent.Serve(context.Background(), socket, nil, nil); !errors.Is(err, agent.ErrAlreadyRunning) {
			t.Fatalf("second agent: %v", err)
		}
	}
	got, err := a.client.MasterKey()
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("second start replaced live session: %v", err)
	}
	for _, path := range []string{socket, socket + ".lock"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe permissions: %s %v", path, info.Mode())
		}
	}
}

func TestSimultaneousStartsHaveOneWinner(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const count = 8
	results := make(chan error, count)
	start := make(chan struct{})
	for range count {
		go func() { <-start; results <- agent.Serve(ctx, socket, nil, nil) }()
	}
	close(start)
	for range count - 1 {
		select {
		case err := <-results:
			if !errors.Is(err, agent.ErrAlreadyRunning) {
				t.Fatalf("contender: %v", err)
			}
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("contenders did not finish")
		}
	}
	client := waitDial(t, socket, time.Second)
	if _, err := client.Status(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-results:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("winner did not stop")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket remained after shutdown: %v", err)
	}
	if _, err := os.Stat(socket + ".lock"); err != nil {
		t.Fatal("lock inode should remain for future starts")
	}
}

func TestStaleSocketIsRecoveredButOtherFilesArePreserved(t *testing.T) {
	t.Run("stale socket", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "agent.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		ln.SetUnlinkOnClose(false)
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		a := startAgent(t, socket, agent.Options{})
		if _, err := a.client.Status(); err != nil {
			t.Fatal(err)
		}
	})
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "regular file", true: "symlink"}[symlink], func(t *testing.T) {
			dir := t.TempDir()
			socket := filepath.Join(dir, "agent.sock")
			target := socket
			if symlink {
				target = filepath.Join(dir, "important")
			}
			if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			if symlink {
				if err := os.Symlink(target, socket); err != nil {
					t.Fatal(err)
				}
			}
			if err := agent.Serve(context.Background(), socket, nil, nil); err == nil {
				t.Fatal("non-socket path accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "preserve" {
				t.Fatal("startup changed unrelated file")
			}
		})
	}
}

func TestLiveLegacySocketIsNotReplaced(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "legacy.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := agent.Serve(context.Background(), socket, nil, nil); !errors.Is(err, agent.ErrAlreadyRunning) {
		t.Fatalf("live legacy socket: %v", err)
	}
	if _, err := os.Stat(socket); err != nil {
		t.Fatal("legacy socket was removed")
	}
}

func TestShutdownDoesNotRemoveReplacementSocketPath(t *testing.T) {
	a := startAgent(t, filepath.Join(t.TempDir(), "agent.sock"), agent.Options{})
	if err := os.Remove(a.socket); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.socket, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.cancel()
	select {
	case err := <-a.done:
		a.done <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not stop")
	}
	got, err := os.ReadFile(a.socket)
	if err != nil || string(got) != "replacement" {
		t.Fatal("shutdown removed replacement file")
	}
}

func TestAgentDoesNotFollowLockSymlink(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "agent.sock")
	target := filepath.Join(dir, "important")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, socket+".lock"); err != nil {
		t.Fatal(err)
	}
	if err := agent.Serve(context.Background(), socket, nil, nil); err == nil {
		t.Fatal("lock symlink accepted")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "preserve" {
		t.Fatal("lock symlink changed its target")
	}
}

func TestAgentRequestDeadlineClosesPartialFrames(t *testing.T) {
	a := startAgent(t, filepath.Join(t.TempDir(), "agent.sock"), agent.Options{RequestTimeout: 100 * time.Millisecond})
	c := rawConnection(t, a.socket)
	if _, err := io.WriteString(c, `{"op":`); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := c.Read(b[:])
	var timeout net.Error
	if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("partial request remained open: %v", err)
	}
	if _, err := a.client.Status(); err != nil {
		t.Fatalf("partial request broke agent: %v", err)
	}
}

func TestInvalidFramesCannotMutateSession(t *testing.T) {
	a := startAgent(t, filepath.Join(t.TempDir(), "agent.sock"), agent.Options{MaxRequestBytes: 256})
	key := bytes.Repeat([]byte{1}, 32)
	if err := a.client.Unlock(key); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{strings.Repeat(" ", 256), " {}"} {
		c := rawConnection(t, a.socket)
		payload, err := json.Marshal(api.AgentRequest{Op: api.AgentOpUnlock, Key: bytes.Repeat([]byte{2}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(append(append(payload, extra...), '\n')); err != nil {
			t.Fatal(err)
		}
		var resp api.AgentResponse
		if err := json.NewDecoder(c).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if resp.OK || resp.Error == "" {
			t.Fatal("invalid frame accepted")
		}
		_ = c.Close()
		got, err := a.client.MasterKey()
		if err != nil || !bytes.Equal(got, key) {
			t.Fatal("rejected frame changed key")
		}
	}
}

func TestConnectionLimitAndShutdownWaitForWorkers(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	a := startAgent(t, filepath.Join(t.TempDir(), "agent.sock"), agent.Options{MaxConnections: 1, OnLock: func() error { once.Do(func() { close(started); <-release }); return nil }})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	requestDone := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			err := a.client.Lock()
			select {
			case <-started:
				requestDone <- err
				return
			default:
			}
			if time.Now().After(deadline) {
				requestDone <- err
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start")
	}
	c := rawConnection(t, a.socket)
	var b [1]byte
	_, err := c.Read(b[:])
	var timeout net.Error
	if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("excess connection stayed open: %v", err)
	}
	a.cancel()
	select {
	case err := <-a.done:
		a.done <- err
		t.Fatal("Serve returned while a worker was active")
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not stop")
	}
}

func TestShutdownClosesIdleConnections(t *testing.T) {
	a := startAgent(t, filepath.Join(t.TempDir(), "agent.sock"), agent.Options{RequestTimeout: time.Hour})
	conns := make([]net.Conn, 0, 8)
	for range 8 {
		c := rawConnection(t, a.socket)
		if _, err := io.WriteString(c, `{"op":`); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	a.cancel()
	for _, c := range conns {
		var b [1]byte
		_, err := c.Read(b[:])
		var timeout net.Error
		if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
			t.Fatalf("shutdown left connection open: %v", err)
		}
	}
}
