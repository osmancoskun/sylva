package agent

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	keyctlGetKeyringID = 0
	keyctlUpdate       = 2
	keyctlUnlink       = 9
	keyctlRead         = 11
	keyTypeUser        = "user"
)

// Linux keyctl special keyring IDs are negative; convert at runtime so the
// sign-extended uintptr reaches the kernel (a constant conversion overflows).
var keySpecUserKeyring = int32(-4)

type osKeyring struct {
	service string
	user    string
}

func newOSKeyring(service, user string) Keyring {
	return osKeyring{service: service, user: user}
}

func (k osKeyring) description() string {
	return k.service + ":" + k.user
}

func (k osKeyring) Set(secret string) error {
	if err := ensureUserKeyring(); err != nil {
		return err
	}
	payload := []byte(secret)
	desc := k.description()
	serial, err := requestUserKey(desc)
	if err == nil {
		if _, err := keyctl(keyctlUpdate, uintptr(serial), payloadPtr(payload), uintptr(len(payload)), 0); err != nil {
			return fmt.Errorf("kernel keyring update: %w", err)
		}
		return nil
	}
	if _, err := addUserKey(desc, payload); err != nil {
		return fmt.Errorf("kernel keyring store: %w", err)
	}
	return nil
}

func (k osKeyring) Get() (string, error) {
	if err := ensureUserKeyring(); err != nil {
		return "", errKeyringEmpty
	}
	serial, err := requestUserKey(k.description())
	if err != nil {
		return "", errKeyringEmpty
	}
	n, err := keyctl(keyctlRead, uintptr(serial), 0, 0, 0)
	if err != nil || n == 0 {
		return "", errKeyringEmpty
	}
	buf := make([]byte, n)
	got, err := keyctl(keyctlRead, uintptr(serial), payloadPtr(buf), uintptr(len(buf)), 0)
	if err != nil || got == 0 {
		return "", errKeyringEmpty
	}
	if got < n {
		buf = buf[:got]
	}
	return string(buf), nil
}

func (k osKeyring) Delete() error {
	if err := ensureUserKeyring(); err != nil {
		return nil
	}
	serial, err := requestUserKey(k.description())
	if err != nil {
		return nil
	}
	_, _ = keyctl(keyctlUnlink, uintptr(serial), uintptr(keySpecUserKeyring), 0, 0)
	return nil
}

func ensureUserKeyring() error {
	_, err := keyctl(keyctlGetKeyringID, uintptr(keySpecUserKeyring), 1, 0, 0)
	if err != nil {
		return fmt.Errorf("kernel user keyring: %w", err)
	}
	return nil
}

func addUserKey(description string, payload []byte) (int32, error) {
	typ, err := syscall.BytePtrFromString(keyTypeUser)
	if err != nil {
		return 0, err
	}
	desc, err := syscall.BytePtrFromString(description)
	if err != nil {
		return 0, err
	}
	r1, _, errno := syscall.Syscall6(
		syscall.SYS_ADD_KEY,
		uintptr(unsafe.Pointer(typ)),
		uintptr(unsafe.Pointer(desc)),
		payloadPtr(payload),
		uintptr(len(payload)),
		uintptr(keySpecUserKeyring),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int32(r1), nil
}

func requestUserKey(description string) (int32, error) {
	typ, err := syscall.BytePtrFromString(keyTypeUser)
	if err != nil {
		return 0, err
	}
	desc, err := syscall.BytePtrFromString(description)
	if err != nil {
		return 0, err
	}
	r1, _, errno := syscall.Syscall6(
		syscall.SYS_REQUEST_KEY,
		uintptr(unsafe.Pointer(typ)),
		uintptr(unsafe.Pointer(desc)),
		0,
		uintptr(keySpecUserKeyring),
		0,
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int32(r1), nil
}

func keyctl(cmd int, arg2, arg3, arg4, arg5 uintptr) (uintptr, error) {
	r1, _, errno := syscall.Syscall6(syscall.SYS_KEYCTL, uintptr(cmd), arg2, arg3, arg4, arg5, 0)
	if errno != 0 {
		return 0, errno
	}
	return r1, nil
}

func payloadPtr(payload []byte) uintptr {
	if len(payload) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&payload[0]))
}
