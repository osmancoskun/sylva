//go:build !unix

package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func readSecretMasked(fd int) (string, error) {
	b, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	for range b {
		fmt.Fprint(os.Stdout, "*")
	}
	return string(b), nil
}
