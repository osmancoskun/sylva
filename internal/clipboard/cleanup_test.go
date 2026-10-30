package clipboard

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type cleanupBackend struct {
	value                       string
	readErr, clearErr, closeErr error
	closes                      int
}

func (b *cleanupBackend) Write(s string) error  { b.value = s; return nil }
func (b *cleanupBackend) Read() (string, error) { return b.value, b.readErr }
func (b *cleanupBackend) Clear() error {
	if b.clearErr == nil {
		b.value = ""
	}
	return b.clearErr
}
func (b *cleanupBackend) Close() error { b.closes++; return b.closeErr }

func TestFailedAutomaticClearDoesNotReportSuccess(t *testing.T) {
	for _, readFailure := range []bool{false, true} {
		t.Run(map[bool]string{true: "read", false: "clear"}[readFailure], func(t *testing.T) {
			failure := errors.New("backend unavailable")
			b := &cleanupBackend{}
			if readFailure {
				b.readErr = failure
			} else {
				b.clearErr = failure
			}
			m := &Manager{backend: b, after: 10 * time.Millisecond}
			defer m.Close()
			var cleared atomic.Int32
			failed := make(chan error, 1)
			m.NotifyCleared(func() { cleared.Add(1) })
			m.NotifyClearFailed(func(err error) { failed <- err })
			if err := m.Copy("synthetic secret"); err != nil {
				t.Fatal(err)
			}
			m.Wait()
			select {
			case err := <-failed:
				if !errors.Is(err, failure) {
					t.Fatal(err)
				}
			default:
				t.Fatal("failure was not reported")
			}
			if cleared.Load() != 0 || !errors.Is(m.ClearError(), failure) {
				t.Fatal("failed clear was reported as success")
			}
			b.readErr = nil
			b.clearErr = nil
			if err := m.Clear(); err != nil {
				t.Fatal(err)
			}
			if m.ClearError() != nil {
				t.Fatal("successful retry did not reset failure")
			}
		})
	}
}

func TestClosePreservesClearAndReleaseErrors(t *testing.T) {
	clearErr := errors.New("clear failed")
	closeErr := errors.New("release failed")
	b := &cleanupBackend{clearErr: clearErr, closeErr: closeErr}
	m := &Manager{backend: b, after: 10 * time.Millisecond}
	if err := m.Copy("synthetic secret"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	for range 2 {
		err := m.Close()
		if !errors.Is(err, clearErr) || !errors.Is(err, closeErr) {
			t.Fatalf("cleanup errors lost: %v", err)
		}
	}
	if b.closes != 1 {
		t.Fatal("backend released more than once")
	}
	if err := m.ScheduleClear("late"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed manager accepted scheduling: %v", err)
	}
}

type cleanupHolder struct {
	err   error
	calls int
}

func (h *cleanupHolder) Close() error { h.calls++; return h.err }

func TestOSClipboardReleaseFailureIsRetryable(t *testing.T) {
	failure := errors.New("release failed")
	h := &cleanupHolder{err: failure}
	b := &osBackend{kind: "test", text: "synthetic secret", hold: h}
	b.owned.Store(true)
	if err := b.Clear(); !errors.Is(err, failure) {
		t.Fatal("release failure hidden")
	}
	if b.hold == nil || b.text == "" || !b.owned.Load() {
		t.Fatal("failed release reported a cleared clipboard")
	}
	if err := b.Write("new secret"); !errors.Is(err, failure) {
		t.Fatal("failed release allowed replacement")
	}
	h.err = nil
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	if b.hold != nil || b.text != "" || b.owned.Load() {
		t.Fatal("successful retry did not release clipboard")
	}
}
