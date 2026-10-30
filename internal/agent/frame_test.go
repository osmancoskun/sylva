package agent

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/limits"
)

func TestFrameLimitAndTerminator(t *testing.T) {
	frame := `{"op":"status"}` + "\n"
	var req api.AgentRequest
	if err := readFrame(strings.NewReader(frame), int64(len(frame)), &req); err != nil || req.Op != api.AgentOpStatus {
		t.Fatalf("exact frame: %v", err)
	}
	if err := readFrame(strings.NewReader(frame), int64(len(frame)-1), &req); !errors.Is(err, limits.ErrExceeded) {
		t.Fatalf("frame overflow: %v", err)
	}
	if err := readFrame(strings.NewReader(strings.TrimSuffix(frame, "\n")), int64(len(frame)), &req); err == nil {
		t.Fatal("unterminated frame accepted")
	}
}

func TestHandlerWriteDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	s := &Server{requestTimeout: 50 * time.Millisecond, maxRequestBytes: 256, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan struct{})
	go func() { defer close(done); s.handle(server) }()
	if _, err := io.WriteString(client, `{"op":"status"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	// Never read the response: even a blocked writer must exit on its deadline.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked response writer did not stop")
	}
}
