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
	// BackendAuto uses the OS clipboard when available and otherwise memory.
	BackendAuto = "auto"
	// BackendOS talks to the compositor clipboard over X11 or Wayland sockets.
	BackendOS = "os"
	// BackendMemory keeps the clipboard in process memory (tests and headless).
	BackendMemory = "memory"
	// BackendFile stores the clipboard in a local file.
	BackendFile = "file"
)

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

	mu      sync.Mutex
	gen     uint64
	done    chan struct{}
	stop    chan struct{}
	cleared func()
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
	case BackendOS:
		return newOS()
	case BackendAuto:
		if b, err := newOS(); err == nil {
			return b, nil
		}
		return newMemory(), nil
	default:
		return nil, fmt.Errorf("unknown clipboard backend %q (expected auto, os, memory, file)", backend)
	}
}

// Copy writes text and schedules a clear after the configured duration.
func (m *Manager) Copy(text string) error {
	if err := m.backend.Write(text); err != nil {
		return err
	}
	m.schedule(text)
	return nil
}

// ScheduleClear waits the configured duration and clears the clipboard if it
// still holds the original secret. It does not write.
func (m *Manager) ScheduleClear(text string) {
	m.schedule(text)
}

func (m *Manager) schedule(text string) {
	m.mu.Lock()
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
	m.mu.Unlock()

	go func() {
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
	if m.gen != gen {
		m.mu.Unlock()
		return
	}
	current, err := m.backend.Read()
	if err == nil && current != original {
		m.mu.Unlock()
		return
	}
	_ = m.backend.Clear()
	m.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// NotifyCleared registers a callback invoked after an automatic clipboard clear.
func (m *Manager) NotifyCleared(fn func()) {
	m.mu.Lock()
	m.cleared = fn
	m.mu.Unlock()
}

// Read returns the current clipboard contents.
func (m *Manager) Read() (string, error) {
	return m.backend.Read()
}

// Clear wipes the clipboard immediately.
func (m *Manager) Clear() error {
	m.mu.Lock()
	m.gen++
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
	}
	m.mu.Unlock()
	return m.backend.Clear()
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

// Close releases OS clipboard ownership and backend resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	m.gen++
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
	}
	m.mu.Unlock()
	return m.backend.Close()
}

// HoldsUntilClear reports whether this process must stay alive to keep the
// system clipboard populated (X11/Wayland selection ownership).
func (m *Manager) HoldsUntilClear() bool {
	_, ok := m.backend.(*osBackend)
	return ok
}
