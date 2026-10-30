// Package clipboard copies secrets to a backend clipboard and clears them
// after a configured duration if the clipboard contents have not changed.
package clipboard

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// BackendAuto selects an available OS clipboard, returning an error if none is available.
	BackendAuto = "auto"
	// BackendOS talks to the compositor clipboard over X11 or Wayland sockets.
	BackendOS = "os"
	// BackendMemory keeps the clipboard in process memory (tests and headless).
	BackendMemory = "memory"
	// BackendFile stores the clipboard in a local file.
	BackendFile = "file"
)

var ErrClosed = errors.New("clipboard manager is closed")

// Backend is a clipboard storage target.
type Backend interface {
	Write(text string) error
	Read() (string, error)
	Clear() error
	Close() error
}

// Manager writes secrets and schedules an automatic clear.
type Manager struct {
	backend Backend
	after   time.Duration

	mu          sync.Mutex
	gen         uint64
	done        chan struct{}
	stop        chan struct{}
	cleared     func()
	clearFailed func(error)
	clearErr    error
	closed      bool
	workers     sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

// NewManager constructs a clipboard manager for the configured backend.
func NewManager(backend, filePath string, clearAfter time.Duration) (*Manager, error) {
	if clearAfter <= 0 {
		return nil, errors.New("clipboard clear duration must be positive")
	}
	b, err := newBackend(backend, filePath)
	if err != nil {
		return nil, err
	}
	return &Manager{backend: b, after: clearAfter}, nil
}

func newBackend(backend, filePath string) (Backend, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case BackendMemory:
		return newMemory(), nil
	case BackendFile:
		if strings.TrimSpace(filePath) == "" {
			return nil, errors.New("clipboard file backend requires SYLVA_CLIPBOARD_FILE")
		}
		return newFile(filePath)
	case BackendOS, BackendAuto:
		return newOS()
	default:
		return nil, fmt.Errorf("unknown clipboard backend %q (expected auto, os, memory, file)", backend)
	}
}

// Copy writes text and schedules a clear after the configured duration.
func (m *Manager) Copy(text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if err := m.backend.Write(text); err != nil {
		return err
	}
	m.scheduleLocked(text)
	return nil
}

// ScheduleClear waits the configured duration and clears the clipboard if it
// still holds the original secret. It does not write.
func (m *Manager) ScheduleClear(text string) error {
	return m.schedule(text)
}

func (m *Manager) schedule(text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.scheduleLocked(text)
	return nil
}

func (m *Manager) scheduleLocked(text string) {
	m.gen++
	gen := m.gen
	done := make(chan struct{})
	m.done = done
	if m.stop != nil {
		close(m.stop)
	}
	stop := make(chan struct{})
	m.stop = stop
	after := m.after
	m.workers.Add(1)

	go func() {
		defer m.workers.Done()
		timer := time.NewTimer(after)
		defer timer.Stop()
		defer close(done)
		select {
		case <-timer.C:
			m.clearIfUnchanged(gen, text)
		case <-stop:
		}
	}()
}

func (m *Manager) clearIfUnchanged(gen uint64, original string) {
	m.mu.Lock()
	fn := m.cleared
	if m.closed || m.gen != gen {
		m.mu.Unlock()
		return
	}
	current, err := m.backend.Read()
	if err == nil && current != original {
		m.mu.Unlock()
		return
	}
	clearErr := m.backend.Clear()
	if err != nil {
		err = fmt.Errorf("read clipboard before clearing: %w", err)
	}
	m.clearErr = errors.Join(err, clearErr)
	failure := m.clearFailed
	result := m.clearErr
	m.mu.Unlock()
	if result != nil {
		if failure != nil {
			failure(result)
		}
	} else if fn != nil {
		fn()
	}
}

// NotifyClearFailed observes automatic clear failures outside the manager lock.
// Like NotifyCleared, callbacks must not call Close or Wait on this manager.
func (m *Manager) NotifyClearFailed(fn func(error)) {
	m.mu.Lock()
	m.clearFailed = fn
	m.mu.Unlock()
}

// ClearError preserves a failed cleanup until a subsequent clear succeeds.
func (m *Manager) ClearError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clearErr
}

// NotifyCleared registers a callback invoked after an automatic clipboard clear.
// The callback must return and must not call Close or Wait on this manager.
func (m *Manager) NotifyCleared(fn func()) {
	m.mu.Lock()
	m.cleared = fn
	m.mu.Unlock()
}

// Read returns the current clipboard contents.
func (m *Manager) Read() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", ErrClosed
	}
	return m.backend.Read()
}

// Clear wipes the clipboard immediately.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.gen++
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
	}
	m.clearErr = m.backend.Clear()
	return m.clearErr
}

// Wait blocks until the latest scheduled clear has finished.
func (m *Manager) Wait() {
	m.mu.Lock()
	done := m.done
	m.mu.Unlock()
	if done != nil {
		<-done
	}
}

// ClearAfter returns the configured auto-clear duration.
func (m *Manager) ClearAfter() time.Duration {
	return m.after
}

// Close prevents new copies, joins clear workers/callbacks, and releases the
// backend. Repeated calls return the same result.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.gen++
		if m.stop != nil {
			close(m.stop)
			m.stop = nil
		}
		m.mu.Unlock()
		m.workers.Wait()
		m.mu.Lock()
		clearErr := m.clearErr
		m.mu.Unlock()
		m.closeErr = errors.Join(clearErr, m.backend.Close())
	})
	return m.closeErr
}

// HoldsUntilClear reports whether this process must stay alive to keep the
// system clipboard populated (X11/Wayland selection ownership).
func (m *Manager) HoldsUntilClear() bool {
	_, ok := m.backend.(*osBackend)
	return ok
}
