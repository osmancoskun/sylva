// Package leakcheck fails tests when goroutines are still running afterwards.
// It uses the Go runtime stack dump rather than a third-party leak detector.
package leakcheck

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Verify runs the test suite and fails if unexpected goroutines remain.
func Verify(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if leftover := leftoverGoroutines(); len(leftover) > 0 {
			fmt.Fprintf(os.Stderr, "leakcheck: %d goroutine(s) still running:\n\n%s\n", len(leftover), strings.Join(leftover, "\n\n"))
			code = 1
		}
	}
	os.Exit(code)
}

func leftoverGoroutines() []string {
	for i := 0; i < 50; i++ {
		runtime.Gosched()
		runtime.GC()
		time.Sleep(2 * time.Millisecond)
	}

	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}

	var leftover []string
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if stack == "" || ignoreStack(stack) {
			continue
		}
		leftover = append(leftover, stack)
	}
	return leftover
}

func ignoreStack(stack string) bool {
	if strings.Contains(stack, "github.com/osman/sylva/internal/leakcheck") {
		return true
	}
	ignores := []string{
		"runtime.goexit",
		"runtime.main",
		"runtime.ensureSigM",
		"runtime.updateMaxProcsGoroutine",
		"os/signal.signal_recv",
		"os/signal.loop",
		"testing.Main",
		"testing.(*M).Run",
		"testing.tRunner",
		"created by os/signal.Notify",
		"created by runtime.",
		"created by testing.",
	}
	for _, ign := range ignores {
		if strings.Contains(stack, ign) {
			return true
		}
	}
	return false
}
