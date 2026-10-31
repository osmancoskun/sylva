package agent

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	keyctlUpdate = 2
	keyctlUnlink = 9
	keyctlRead   = 11
	keyTypeUser  = "user"
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
	return deleteUserKey(k.description(), ensureUserKeyring, requestUserKey, func(serial int32) error {
		_, err := keyctl(keyctlUnlink, uintptr(serial), uintptr(keySpecUserKeyring), 0, 0)
		return err
	})
}

func deleteUserKey(description string, ensure func() error, lookup func(string) (int32, error), unlink func(int32) error) error {
	if err := ensure(); err != nil {
		return fmt.Errorf("access kernel keyring for deletion: %w", err)
	}
	serial, err := lookup(description)
	if errors.Is(err, syscall.ENOKEY) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find kernel keyring entry for deletion: %w", err)
	}
	if err := unlink(serial); err != nil {
		return fmt.Errorf("delete kernel keyring entry: %w", err)
	}
	return nil
}

func ensureUserKeyring() error {
	serial, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, true)
	if err != nil {
		return fmt.Errorf("kernel user keyring: %w", err)
	}
	// User keys grant read/update access through possession. A non-login
	// session may not possess the user keyring until it is linked here.
	if _, err := unix.KeyctlInt(unix.KEYCTL_LINK, serial, unix.KEY_SPEC_SESSION_KEYRING, 0, 0); err != nil {
		return fmt.Errorf("link kernel user keyring to session: %w", err)
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
	// request_key searches the thread/process/session keyrings, which may not
	// contain a link to the user keyring (for example on CI runners).
	serial, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, keyTypeUser, description, 0)
	return int32(serial), err
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
