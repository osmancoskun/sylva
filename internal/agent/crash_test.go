package agent_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/osman/sylva/internal/agent"
)

func TestAgentCrashReleasesLockAndStaleSocket(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "agent.sock")
	cmd := exec.Command(exe, "-test.run=^TestAgentCrashProbe$")
	cmd.Env = append(os.Environ(), "SYLVA_AGENT_CRASH_PROBE="+socket)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "agent-ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child agent failed to start")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("child agent startup timed out")
	}
	if err := agent.Serve(context.Background(), socket, nil, nil); !errors.Is(err, agent.ErrAlreadyRunning) {
		t.Fatalf("cross-process lock: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	a := startAgent(t, socket, agent.Options{})
	if _, err := a.client.Status(); err != nil {
		t.Fatalf("restart after crash: %v", err)
	}
}

func TestAgentCrashProbe(t *testing.T) {
	socket := os.Getenv("SYLVA_AGENT_CRASH_PROBE")
	if socket == "" {
		return
	}
	done := make(chan error, 1)
	go func() {
		done <- agent.Serve(context.Background(), socket, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	_ = waitDial(t, socket, 2*time.Second)
	fmt.Println("agent-ready")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
