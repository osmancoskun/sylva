//go:build !linux

package agent

import (
	"fmt"
	"runtime"
)

type osKeyring struct{}

func newOSKeyring(service, user string) Keyring {
	return osKeyring{}
}

func (osKeyring) Set(string) error {
	return fmt.Errorf("os keyring uses the Linux kernel keyring and is not supported on %s", runtime.GOOS)
}

func (osKeyring) Get() (string, error) {
	return "", errKeyringEmpty
}

func (osKeyring) Delete() error { return nil }
