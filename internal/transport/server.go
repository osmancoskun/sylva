// Package transport implements the HTTP server and client communication layer
// between sylva clients and the sylvad daemon, supporting standard HTTP,
// optional mTLS, and optional Tailscale networking.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
)

// StatusResponse is an alias for the catalog ping payload so existing callers
// keep compiling against the transport package.
type StatusResponse = api.StatusResponse

// Server wraps the HTTP server and routing for the sylvad daemon.
type Server struct {
	cfg        config.ServerConfig
	store      storage.Store
	httpServer *http.Server
	logger     *slog.Logger
	startedAt  time.Time
	tsClose    func() error
}

// NewServer creates and configures a new transport Server instance.
func NewServer(cfg config.ServerConfig, store storage.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:       cfg,
		store:     store,
		logger:    logger,
		startedAt: time.Now().UTC(),
	}

	prefix := strings.TrimRight(cfg.APIPrefix, "/")
	mux := http.NewServeMux()
	handlers := map[string]http.HandlerFunc{
		api.EndpointPing:         s.handlePing,
		api.EndpointHealthz:      s.handlePing,
		api.EndpointPutRecord:    s.handlePutRecord,
		api.EndpointUpdateRecord: s.handleUpdateRecord,
		api.EndpointGetRecord:    s.handleGetRecordByID,
		api.EndpointDeleteRecord: s.handleDeleteRecord,
		api.EndpointListRecords:  s.handleListRecords,
		api.EndpointGetSalt:      s.handleGetSalt,
		api.EndpointPutSalt:      s.handlePutSalt,
	}
	for _, ep := range api.HTTPEndpoints() {
		h, ok := handlers[ep.Name]
		if !ok {
			panic("transport: missing handler for API endpoint " + ep.Name)
		}
		mux.HandleFunc(ep.Pattern(prefix), h)
	}

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

func (s *Server) listenTLS(ln net.Listener) (net.Listener, error) {
	tlsCfg, err := serverTLSConfig(s.cfg)
	if err != nil {
		return nil, err
	}
	s.httpServer.TLSConfig = tlsCfg
	return tls.NewListener(ln, tlsCfg), nil
}

// Start begins listening and serving requests until the provided context is canceled.
func (s *Server) Start(ctx context.Context) error {
	var ln net.Listener
	var err error
	if s.cfg.EnableTailscale {
		ln, s.tsClose, err = openTailscaleListener(ctx, s.cfg, s.logger)
		if err != nil {
			return err
		}
		// Same-host CLI traffic to the tsnet IP hairpins through kernel
		// tailscale0 and usually times out. Also bind loopback for local sylva.
		loopAddr := net.JoinHostPort("127.0.0.1", s.cfg.Port)
		localLn, localErr := net.Listen("tcp", loopAddr)
		if localErr != nil {
			s.logger.Warn("tailscale local loopback listen failed",
				slog.String("addr", loopAddr),
				slog.Any("error", localErr),
			)
		} else {
			s.logger.Info("also listening", slog.String("addr", localLn.Addr().String()))
			ln = mergeListeners(ln, localLn)
		}
	} else {
		ln, err = net.Listen("tcp", s.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", s.cfg.ListenAddr, err)
		}
	}

	return s.Serve(ctx, ln)
}

func (s *Server) closeTailscale() {
	if s.tsClose == nil {
		return
	}
	if err := s.tsClose(); err != nil {
		s.logger.Error("tailscale close", slog.Any("error", err))
	}
	s.tsClose = nil
}

// Serve accepts incoming connections on the provided listener and performs a
// graceful shutdown when ctx is canceled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer s.closeTailscale()

	serveLn := ln
	if s.cfg.EnableMTLS {
		tlsLn, err := s.listenTLS(ln)
		if err != nil {
			return err
		}
		serveLn = tlsLn
	}

	errCh := make(chan error, 1)

	go func() {
		s.logger.Info("server listening",
			slog.String("service", s.cfg.ServiceName),
			slog.String("addr", ln.Addr().String()),
			slog.Bool("mtls", s.cfg.EnableMTLS),
			slog.Bool("tailscale", s.cfg.EnableTailscale),
		)
		if err := s.httpServer.Serve(serveLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		s.closeTailscale()
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	resp := api.StatusResponse{
		Status:    "ok",
		Service:   s.cfg.ServiceName,
		Version:   s.cfg.Version,
		MTLS:      s.cfg.EnableMTLS,
		Tailscale: s.cfg.EnableTailscale,
		Timestamp: time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, resp)
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
