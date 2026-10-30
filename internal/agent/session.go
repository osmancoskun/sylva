// Package agent implements the local session daemon: an in-memory master-key
// holder over a unix socket, optional OS keyring persistence, and clipboard
// auto-clear scheduling that outlives individual CLI invocations.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/limits"
)

var (
	// ErrUnavailable indicates the session agent socket could not be reached.
	ErrUnavailable = errors.New("session agent is not running")

	// ErrLocked indicates the agent is running but has no master key.
	ErrLocked = errors.New("session agent is locked")

	// ErrAlreadyRunning leaves the active agent and its unlocked key untouched.
	ErrAlreadyRunning = errors.New("session agent is already running")
)

// Server holds an unlocked master key in memory and serves local CLI clients.
type Server struct {
	socketPath string
	clip       *clipboard.Manager
	log        *slog.Logger

	mu              sync.Mutex
	key             []byte
	copyType        string
	copyIdentifier  string
	idleTimeout     time.Duration
	expires         time.Time
	onLock          func() error
	requestTimeout  time.Duration
	maxRequestBytes int64
}

const (
	DefaultRequestTimeout        = 5 * time.Second
	DefaultMaxRequestBytes int64 = 1 << 20
	DefaultMaxConnections        = 64
)

type Options struct {
	IdleTimeout time.Duration
	// OnLock must return promptly; shutdown waits for callbacks and workers.
	OnLock          func() error
	RequestTimeout  time.Duration
	MaxRequestBytes int64
	MaxConnections  int
}

func normalizeOptions(o Options) (Options, error) {
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 15 * time.Minute
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = DefaultRequestTimeout
	}
	if o.MaxRequestBytes == 0 {
		o.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if o.MaxConnections == 0 {
		o.MaxConnections = DefaultMaxConnections
	}
	if o.IdleTimeout < 0 || o.RequestTimeout < 0 || o.MaxConnections < 1 {
		return o, errors.New("agent timeouts and connection limit must be positive")
	}
	if err := limits.Validate("agent_max_request_bytes", o.MaxRequestBytes); err != nil {
		return o, err
	}
	return o, nil
}

// Serve listens on the configured unix socket until ctx is cancelled.
func Serve(ctx context.Context, socketPath string, clip *clipboard.Manager, log *slog.Logger, options ...Options) (retErr error) {
	if log == nil {
		log = slog.Default()
	}
	var opt Options
	if len(options) > 0 {
		opt = options[0]
	}
	opt, err := normalizeOptions(opt)
	if err != nil {
		return err
	}
	ln, release, err := listenAgent(socketPath)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	if clip != nil {
		defer clip.Close()
	}
	srv := &Server{socketPath: socketPath, clip: clip, log: log, idleTimeout: opt.IdleTimeout, onLock: opt.OnLock, requestTimeout: opt.RequestTimeout, maxRequestBytes: opt.MaxRequestBytes}
	defer srv.wipe()
	stopIdle := make(chan struct{})
	idleDone := make(chan struct{})
	go func() {
		defer close(idleDone)
		interval := min(srv.idleTimeout/4, time.Second)
		ticker := time.NewTicker(max(interval, time.Millisecond))
		defer ticker.Stop()
		for {
			select {
			case <-stopIdle:
				return
			case <-ticker.C:
				srv.mu.Lock()
				srv.expireLocked()
				srv.mu.Unlock()
			}
		}
	}()
	defer func() { close(stopIdle); <-idleDone }()
	if clip != nil {
		clip.NotifyCleared(func() {
			log.Info("clipboard cleared", srv.copiedTarget()...)
		})
	}
	log.Info("session agent listening", slog.String("socket", socketPath))

	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	var activeMu sync.Mutex
	active := make(map[net.Conn]struct{})
	slots := make(chan struct{}, opt.MaxConnections)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		_ = ln.Close()
		activeMu.Lock()
		for conn := range active {
			_ = conn.Close()
		}
		activeMu.Unlock()
	}()
	defer func() { cancel(); <-shutdownDone; workers.Wait() }()

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
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		activeMu.Lock()
		if ctx.Err() != nil {
			activeMu.Unlock()
			<-slots
			_ = conn.Close()
			return nil
		}
		active[conn] = struct{}{}
		workers.Add(1)
		activeMu.Unlock()
		go func() {
			defer workers.Done()
			defer func() { activeMu.Lock(); delete(active, conn); activeMu.Unlock(); <-slots }()
			srv.handle(conn)
		}()
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

	if err := conn.SetDeadline(time.Now().Add(s.requestTimeout)); err != nil {
		return
	}
	var req api.AgentRequest
	defer func() { crypto.ZeroBytes(req.Key) }()
	if err := readFrame(conn, s.maxRequestBytes, &req); err != nil {
		message := "invalid agent request"
		if errors.Is(err, limits.ErrExceeded) {
			message = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(api.AgentResponse{Error: message})
		return
	}

	var resp api.AgentResponse
	defer func() { crypto.ZeroBytes(resp.Key) }()
	switch req.Op {
	case api.AgentOpStatus:
		s.mu.Lock()
		s.expireLocked()
		resp = api.AgentResponse{OK: true, Unlocked: len(s.key) > 0}
		s.mu.Unlock()
	case api.AgentOpUnlock:
		if len(req.Key) != 32 {
			resp = api.AgentResponse{Error: "master key must be 32 bytes"}
			break
		}
		s.mu.Lock()
		crypto.ZeroBytes(s.key)
		s.key = append([]byte(nil), req.Key...)
		s.expires = time.Now().Add(s.idleTimeout)
		s.mu.Unlock()
		s.log.Info("session unlocked")
		resp = api.AgentResponse{OK: true, Unlocked: true}
	case api.AgentOpLock:
		s.wipe()
		s.log.Info("session locked")
		resp = api.AgentResponse{OK: true, Unlocked: false}
	case api.AgentOpMasterKey:
		s.mu.Lock()
		s.expireLocked()
		if len(s.key) == 0 {
			s.mu.Unlock()
			resp = api.AgentResponse{Error: ErrLocked.Error()}
			break
		}
		resp = api.AgentResponse{OK: true, Unlocked: true, Key: append([]byte(nil), s.key...)}
		s.expires = time.Now().Add(s.idleTimeout)
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
		resp = api.AgentResponse{Error: "unknown agent operation"}
	}

	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	crypto.ZeroBytes(s.key)
	s.key = nil
	s.expires = time.Time{}
	if s.clip != nil {
		_ = s.clip.Clear()
	}
	if s.onLock != nil {
		if err := s.onLock(); err != nil {
			s.log.Error("clear keyring on lock", "error", err)
		}
	}
}

// Caller holds mu. Status probes do not extend the session deadline.
func (s *Server) expireLocked() {
	if len(s.key) > 0 && !time.Now().Before(s.expires) {
		crypto.ZeroBytes(s.key)
		s.key = nil
		s.expires = time.Time{}
		if s.clip != nil {
			_ = s.clip.Clear()
		}
		if s.onLock != nil {
			if err := s.onLock(); err != nil {
				s.log.Error("clear keyring on auto-lock", "error", err)
			}
		}
		s.log.Info("session automatically locked")
	}
}
