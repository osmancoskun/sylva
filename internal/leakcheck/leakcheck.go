// Package leakcheck fails tests when application goroutines remain after cleanup.
package leakcheck

import (
	"testing"

	"go.uber.org/goleak"
)

// Verify runs the suite and checks for leaked goroutines. Do not broadly ignore
// test-created goroutines: they include the application's servers and workers.
func Verify(m *testing.M) {
	goleak.VerifyTestMain(m)
}
