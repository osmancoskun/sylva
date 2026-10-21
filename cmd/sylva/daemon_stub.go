//go:build !unix

package main

import (
	"fmt"
	"runtime"

	"github.com/osman/sylva/internal/config"
)

func startDetachedAgent(config.ClientConfig) error {
	return fmt.Errorf("starting the session agent in the background is not supported on %s", runtime.GOOS)
}
