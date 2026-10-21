// Package agent implements the local session daemon: an in-memory master-key
// holder over a unix socket, optional OS keyring persistence, and clipboard
// auto-clear scheduling that outlives individual CLI invocations.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/crypto"
)

var (
	// ErrUnavailable indicates the session agent socket could not be reached.
	ErrUnavailable = errors.New("session agent is not running")

	// ErrLocked indicates the agent is running but has no master key.
	ErrLocked = errors.New("session agent is locked")
)

// Server holds an unlocked master key in memory and serves local CLI clients.
type Server struct {
	socketPath string
	clip       *clipboard.Manager
	log        *slog.Logger

	mu             sync.Mutex
	key            []byte
	copyType       string
	copyIdentifier string
}

// Serve listens on the configured unix socket until ctx is cancelled.
func Serve(ctx context.Context, socketPath string, clip *clipboard.Manager, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("create agent socket directory: %w", err)
	}
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on agent socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod agent socket: %w", err)
	}

	srv := &Server{socketPath: socketPath, clip: clip, log: log}
	defer srv.wipe()
	defer os.Remove(socketPath)
	if clip != nil {
		clip.NotifyCleared(func() {
			log.Info("clipboard cleared", srv.copiedTarget()...)
		})
		defer clip.Close()
	}
	log.Info("session agent listening", slog.String("socket", socketPath))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go srv.handle(conn)
	}
}

func (s *Server) copiedTarget() []any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clipboardTargetAttrs(s.copyType, s.copyIdentifier)
}

func (s *Server) setCopiedTarget(secretType, identifier string) {
	s.mu.Lock()
	s.copyType = secretType
	s.copyIdentifier = identifier
	s.mu.Unlock()
}

func clipboardTargetAttrs(secretType, identifier string) []any {
	var attrs []any
	if secretType != "" {
		attrs = append(attrs, slog.String("type", secretType))
	}
	if identifier != "" {
		attrs = append(attrs, slog.String("identifier", identifier))
	}
	return attrs
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	var req api.AgentRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(api.AgentResponse{Error: "invalid agent request"})
		return
	}

	var resp api.AgentResponse
	switch req.Op {
	case api.AgentOpStatus:
		s.mu.Lock()
		resp = api.AgentResponse{OK: true, Unlocked: len(s.key) > 0}
		s.mu.Unlock()
	case api.AgentOpUnlock:
		if len(req.Key) == 0 {
			resp = api.AgentResponse{Error: "master key cannot be empty"}
			break
		}
		s.mu.Lock()
		crypto.ZeroBytes(s.key)
		s.key = append([]byte(nil), req.Key...)
		s.mu.Unlock()
		s.log.Info("session unlocked")
		resp = api.AgentResponse{OK: true, Unlocked: true}
	case api.AgentOpLock:
		s.wipe()
		s.log.Info("session locked")
		resp = api.AgentResponse{OK: true, Unlocked: false}
	case api.AgentOpMasterKey:
		s.mu.Lock()
		if len(s.key) == 0 {
			s.mu.Unlock()
			resp = api.AgentResponse{Error: ErrLocked.Error()}
			break
		}
		resp = api.AgentResponse{OK: true, Unlocked: true, Key: append([]byte(nil), s.key...)}
		s.mu.Unlock()
	case api.AgentOpCopy:
		if s.clip == nil {
			resp = api.AgentResponse{Error: "clipboard manager is not configured"}
			break
		}
		s.setCopiedTarget(req.Type, req.Identifier)
		if err := s.clip.Copy(req.Secret); err != nil {
			resp = api.AgentResponse{Error: err.Error()}
			break
		}
		s.log.Info("secret copied to clipboard", clipboardTargetAttrs(req.Type, req.Identifier)...)
		resp = api.AgentResponse{OK: true}
	case api.AgentOpScheduleClear:
		if s.clip == nil {
			resp = api.AgentResponse{Error: "clipboard manager is not configured"}
			break
		}
		s.clip.ScheduleClear(req.Secret)
		resp = api.AgentResponse{OK: true}
	default:
		resp = api.AgentResponse{Error: fmt.Sprintf("unknown agent op %q", req.Op)}
	}

	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	crypto.ZeroBytes(s.key)
	s.key = nil
}
