package agent

import (
	"errors"
)

// Keyring persists the master passphrase in the OS login session store.
type Keyring interface {
	Set(secret string) error
	Get() (string, error)
	Delete() error
}

var errKeyringEmpty = errors.New("keyring entry is empty")

// NewKeyring returns an OS-backed keyring when enabled, otherwise a no-op store.
func NewKeyring(enabled bool, service, user string) Keyring {
	if !enabled {
		return noopKeyring{}
	}
	return newOSKeyring(service, user)
}

type noopKeyring struct{}

func (noopKeyring) Set(string) error { return nil }
func (noopKeyring) Get() (string, error) {
	return "", errKeyringEmpty
}
func (noopKeyring) Delete() error { return nil }

// MemoryKeyring is an in-process keyring used by tests.
type MemoryKeyring struct {
	secret string
	set    bool
}

func (m *MemoryKeyring) Set(secret string) error {
	m.secret = secret
	m.set = true
	return nil
}

func (m *MemoryKeyring) Get() (string, error) {
	if !m.set {
		return "", errKeyringEmpty
	}
	return m.secret, nil
}

func (m *MemoryKeyring) Delete() error {
	m.secret = ""
	m.set = false
	return nil
}
