//go:build unix

package main

import (
	"os"
	"strings"
	"syscall"

	"github.com/osman/sylva/internal/config"
)

func startDetachedAgent(cfg config.ClientConfig) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{exe, "agent"}
	if path := strings.TrimSpace(cfg.ConfigPath); path != "" {
		args = []string{exe, "-env", path, "agent"}
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	_, err = syscall.ForkExec(exe, args, &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: []uintptr{null.Fd(), null.Fd(), null.Fd()},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	return err
}
