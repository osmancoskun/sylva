package leakcheck_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/osman/sylva/internal/leakcheck"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func TestLeakedWorkerFailsSuite(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestLeakedWorkerProbe$")
	cmd.Env = append(os.Environ(), "SYLVA_LEAKCHECK_PROBE=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("suite accepted a leaked application worker")
	}
	if !strings.Contains(string(out), "goleak:") || !strings.Contains(string(out), "TestLeakedWorkerProbe") {
		t.Fatalf("subprocess failed without detecting the leaked worker: %v\n%s", err, out)
	}
}

func TestLeakedWorkerProbe(t *testing.T) {
	if os.Getenv("SYLVA_LEAKCHECK_PROBE") != "1" {
		return
	}
	started := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		close(started)
		<-stop
	}()
	<-started
}
