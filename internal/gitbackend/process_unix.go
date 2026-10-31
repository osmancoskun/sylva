//go:build unix

package gitbackend

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// A timed-out Git operation must also stop its SSH/credential-helper children.
// Only the process group created for this command is signaled.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
