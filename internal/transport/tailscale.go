package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/osman/sylva/internal/config"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type tailscaleListener struct {
	net.Listener
	status func(context.Context) (*ipnstate.Status, error)
}

// TailscaleDNSName reads the identity of this embedded node, not the host's
// tailscaled. Fetch on demand so account/name changes do not use a stale name.
func (l *tailscaleListener) TailscaleDNSName(ctx context.Context) (string, error) {
	status, err := l.status(ctx)
	if err != nil {
		return "", err
	}
	if status == nil || status.BackendState != "Running" || status.Self == nil {
		return "", nil
	}
	return strings.TrimSuffix(strings.TrimSpace(status.Self.DNSName), "."), nil
}

// openTailscaleListener joins a tailnet and returns a listener plus a closer
// for the embedded node. Tests replace this to avoid a live Tailscale control plane.
var openTailscaleListener = listenOnTailnet

// SetTailscaleListenerForTest swaps the tsnet listen hook. The returned function restores it.
func SetTailscaleListenerForTest(fn func(context.Context, config.ServerConfig, *slog.Logger) (net.Listener, func() error, error)) func() {
	prev := openTailscaleListener
	openTailscaleListener = fn
	return func() { openTailscaleListener = prev }
}

func listenOnTailnet(ctx context.Context, cfg config.ServerConfig, logger *slog.Logger) (net.Listener, func() error, error) {
	if cfg.TailscaleNode == "" || cfg.TailscaleStateDir == "" {
		return nil, nil, fmt.Errorf("tailscale enabled but SYLVA_TAILSCALE_NODE and SYLVA_TAILSCALE_STATE_DIR are required")
	}
	if err := os.MkdirAll(cfg.TailscaleStateDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create tailscale state dir %s: %w", cfg.TailscaleStateDir, err)
	}

	ts := &tsnet.Server{
		Hostname:      cfg.TailscaleNode,
		Dir:           cfg.TailscaleStateDir,
		AdvertiseTags: cfg.TailscaleTags,
		Logf: func(format string, args ...any) {
			logger.Info("tsnet " + strings.TrimSpace(fmt.Sprintf(format, args...)))
		},
		UserLogf: func(format string, args ...any) {
			logger.Info("tsnet " + strings.TrimSpace(fmt.Sprintf(format, args...)))
		},
	}
	if cfg.TailscaleAuthKey != "" {
		ts.AuthKey = cfg.TailscaleAuthKey
	}

	logger.Info("connecting to tailnet",
		slog.String("hostname", cfg.TailscaleNode),
		slog.Bool("authkey", cfg.TailscaleAuthKey != ""),
		slog.Any("tags", cfg.TailscaleTags),
	)

	status, err := ts.Up(ctx)
	if err != nil {
		_ = ts.Close()
		return nil, nil, fmt.Errorf("tailscale up: %w", err)
	}

	ln, err := ts.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		_ = ts.Close()
		return nil, nil, fmt.Errorf("tailscale listen :%s: %w", cfg.Port, err)
	}
	lc, err := ts.LocalClient()
	if err != nil {
		_ = ln.Close()
		_ = ts.Close()
		return nil, nil, fmt.Errorf("tailscale local status client: %w", err)
	}

	if status != nil {
		logger.Info("joined tailnet",
			slog.String("hostname", cfg.TailscaleNode),
			slog.Any("tailscale_ips", status.TailscaleIPs),
		)
	}
	return &tailscaleListener{Listener: ln, status: lc.Status}, ts.Close, nil
}
