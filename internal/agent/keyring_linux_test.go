package agent_test

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"

	"github.com/osman/sylva/internal/agent"
	"golang.org/x/sys/unix"
)

func TestKernelKeyringRoundTrip(t *testing.T) {
	kr := agent.NewKeyring(true, "sylva-test", t.Name()+"-"+strconv.Itoa(os.Getpid()))
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

// CI runners may have a session keyring without a link to the user keyring.
// Use a child process so replacing the session cannot affect other tests.
func TestKernelKeyringIsolatedSession(t *testing.T) {
	const childEnv = "SYLVA_TEST_ISOLATED_KEYRING"
	if os.Getenv(childEnv) == "1" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if _, err := unix.KeyctlJoinSessionKeyring("sylva-test-" + strconv.Itoa(os.Getpid())); err != nil {
			t.Skipf("session keyring unavailable: %v", err)
		}
		TestKernelKeyringRoundTrip(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelKeyringIsolatedSession$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated session: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
