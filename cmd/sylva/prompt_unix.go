//go:build unix

package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func readSecretMasked(fd int) (string, error) {
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer term.Restore(fd, state)

	var buf []byte
	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		switch b[0] {
		case '\r', '\n':
			return string(buf), nil
		case 3: // Ctrl-C
			return "", fmt.Errorf("interrupted")
		case 127, 8: // backspace
			if len(buf) == 0 {
				continue
			}
			buf = buf[:len(buf)-1]
			fmt.Fprint(os.Stdout, "\b \b")
		default:
			if b[0] < 32 {
				continue
			}
			buf = append(buf, b[0])
			fmt.Fprint(os.Stdout, "*")
		}
	}
}
