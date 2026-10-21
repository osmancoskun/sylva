package clipboard

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

type memoryBackend struct {
	mu    sync.Mutex
	value string
}

func newMemory() *memoryBackend {
	return &memoryBackend{}
}

func (m *memoryBackend) Write(text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value = text
	return nil
}

func (m *memoryBackend) Read() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.value, nil
}

func (m *memoryBackend) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value = ""
	return nil
}

func (m *memoryBackend) Close() error { return nil }

type fileBackend struct {
	path string
}

func newFile(path string) (*fileBackend, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create clipboard directory: %w", err)
	}
	return &fileBackend{path: path}, nil
}

func (f *fileBackend) Write(text string) error {
	return os.WriteFile(f.path, []byte(text), 0o600)
}

func (f *fileBackend) Read() (string, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func (f *fileBackend) Clear() error {
	return os.WriteFile(f.path, nil, 0o600)
}

func (f *fileBackend) Close() error { return nil }

type osBackend struct {
	mu    sync.Mutex
	kind  string
	text  string
	owned atomic.Bool
	hold  clipboardHolder
}

type clipboardHolder interface {
	Close() error
}

func (o *osBackend) Write(text string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeLocked()
	hold, err := startOSClipboard(o.kind, text, func() { o.owned.Store(false) })
	if err != nil {
		return err
	}
	o.hold = hold
	o.text = text
	o.owned.Store(true)
	return nil
}

func (o *osBackend) Read() (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.owned.Load() {
		return "", nil
	}
	return o.text, nil
}

func (o *osBackend) Clear() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeLocked()
	o.text = ""
	o.owned.Store(false)
	return nil
}

func (o *osBackend) Close() error {
	return o.Clear()
}

func (o *osBackend) closeLocked() {
	if o.hold != nil {
		_ = o.hold.Close()
		o.hold = nil
	}
}
