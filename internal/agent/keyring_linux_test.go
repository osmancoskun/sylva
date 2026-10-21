package agent_test

import (
	"testing"

	"github.com/osman/sylva/internal/agent"
)

func TestKernelKeyringRoundTrip(t *testing.T) {
	kr := agent.NewKeyring(true, "sylva-test", t.Name())
	t.Cleanup(func() { _ = kr.Delete() })

	if _, err := kr.Get(); err == nil {
		t.Fatal("expected empty kernel keyring entry")
	}
	if err := kr.Set("kernel-passphrase"); err != nil {
		t.Skipf("kernel keyring unavailable: %v", err)
	}
	got, err := kr.Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "kernel-passphrase" {
		t.Fatalf("got %q", got)
	}
	if err := kr.Set("rotated"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = kr.Get()
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got != "rotated" {
		t.Fatalf("got %q after update", got)
	}
	if err := kr.Delete(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := kr.Get(); err == nil {
		t.Fatal("expected empty kernel keyring after delete")
	}
}
