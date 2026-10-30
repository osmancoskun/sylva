package agent

import (
	"errors"
	"syscall"
	"testing"
)

func TestKeyringDeletionReportsFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		ensure, lookup, unlink error
		want                   error
		wantLookup, wantUnlink bool
	}{
		"missing":         {lookup: syscall.ENOKEY, wantLookup: true},
		"success":         {wantLookup: true, wantUnlink: true},
		"access denied":   {ensure: syscall.EPERM, want: syscall.EPERM},
		"search denied":   {lookup: syscall.EACCES, want: syscall.EACCES, wantLookup: true},
		"unlink denied":   {unlink: syscall.EACCES, want: syscall.EACCES, wantLookup: true, wantUnlink: true},
		"unlink lost key": {unlink: syscall.ENOKEY, want: syscall.ENOKEY, wantLookup: true, wantUnlink: true},
	} {
		t.Run(name, func(t *testing.T) {
			looked, unlinked := false, false
			err := deleteUserKey("test", func() error { return tc.ensure }, func(string) (int32, error) { looked = true; return 17, tc.lookup }, func(serial int32) error {
				unlinked = true
				if serial != 17 {
					t.Fatal("wrong key removed")
				}
				return tc.unlink
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("delete: %v want %v", err, tc.want)
			}
			if looked != tc.wantLookup || unlinked != tc.wantUnlink {
				t.Fatalf("lookup=%v unlink=%v", looked, unlinked)
			}
		})
	}
}
