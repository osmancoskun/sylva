//go:build !unix

package gitbackend

import "os/exec"

func configureProcess(cmd *exec.Cmd) {}
