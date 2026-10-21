// Package transport implements the HTTP server and client communication layer
// between sylva clients and the sylvad daemon, supporting standard HTTP,
// optional mTLS, and optional Tailscale networking.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/osman/sylva/internal/config"
)

// StatusResponse represents the payload returned by the server health/ping endpoint.
type StatusResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Version   string    `json:"version"`
	MTLS      bool      `json:"mtls_enabled"`
	Tailscale bool      `json:"tailscale_enabled"`
	Timestamp time.Time `json:"timestamp"`
}

// Server wraps the HTTP server and routing for the sylvad daemon.
type Server struct {
	cfg        config.ServerConfig
	httpServer *http.Server
	logger     *slog.Logger
	startedAt  time.Time
}

// NewServer creates and configures a new transport Server instance.
func NewServer(cfg config.ServerConfig, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:       cfg,
		logger:    logger,
		startedAt: time.Now().UTC(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ping", s.handlePing)
	mux.HandleFunc("GET /healthz", s.handlePing)

	s.httpServer = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           s.loggingMiddleware(mux),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	return s
}

// Start begins listening and serving requests until the provided context is canceled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.ListenAddr, err)
	}

	return s.Serve(ctx, ln)
}

// Serve accepts incoming connections on the provided listener and performs a
// graceful shutdown when ctx is canceled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)

	go func() {
		s.logger.Info("server listening",
			slog.String("service", s.cfg.ServiceName),
			slog.String("addr", ln.Addr().String()),
			slog.Bool("mtls", s.cfg.EnableMTLS),
			slog.Bool("tailscale", s.cfg.EnableTailscale),
		)
		if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down server gracefully", slog.String("service", s.cfg.ServiceName))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		Status:    "ok",
		Service:   s.cfg.ServiceName,
		Version:   s.cfg.Version,
		MTLS:      s.cfg.EnableMTLS,
		Tailscale: s.cfg.EnableTailscale,
		Timestamp: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("request handled",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
			slog.Duration("duration", time.Since(start)),
		)
	})
}
