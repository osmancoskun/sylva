package transport

import (
	"context"
	"errors"
	"testing"

	"tailscale.com/ipn/ipnstate"
)

func TestEmbeddedTailnetIdentityRequiresJoinedSelf(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *ipnstate.Status
		want   string
	}{
		{name: "nil status"},
		{name: "no self", status: &ipnstate.Status{BackendState: "Running"}},
		{name: "not joined", status: &ipnstate.Status{BackendState: "NeedsLogin", Self: &ipnstate.PeerStatus{DNSName: "stale.tail-example.ts.net."}}},
		{name: "joined", status: &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{DNSName: "actual-node-2.tail-example.ts.net."}}, want: "actual-node-2.tail-example.ts.net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln := &tailscaleListener{status: func(context.Context) (*ipnstate.Status, error) {
				return tc.status, nil
			}}
			got, err := ln.TailscaleDNSName(context.Background())
			if err != nil || got != tc.want {
				t.Fatalf("name=%q err=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestEmbeddedTailnetIdentityRefreshAndCancellation(t *testing.T) {
	status := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{DNSName: "first.tail-example.ts.net."}}
	ln := &tailscaleListener{status: func(ctx context.Context) (*ipnstate.Status, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return status, nil
	}}
	if got, err := ln.TailscaleDNSName(context.Background()); err != nil || got != "first.tail-example.ts.net" {
		t.Fatalf("initial name=%q err=%v", got, err)
	}
	status.Self.DNSName = "renamed.tail-example.ts.net."
	if got, err := ln.TailscaleDNSName(context.Background()); err != nil || got != "renamed.tail-example.ts.net" {
		t.Fatalf("stale name=%q err=%v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := ln.TailscaleDNSName(ctx); !errors.Is(err, context.Canceled) || got != "" {
		t.Fatalf("canceled lookup returned name=%q err=%v", got, err)
	}
}
