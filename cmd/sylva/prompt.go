package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

var stdinMu sync.Mutex

func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stdout, label)
	stdinMu.Lock()
	defer stdinMu.Unlock()
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func promptYesNo(label string) (bool, error) {
	ans, err := promptLine(label + " [y/N] ")
	if err != nil {
		return false, err
	}
	ans = strings.ToLower(ans)
	return ans == "y" || ans == "yes", nil
}

func promptSecret(label string) (string, error) {
	fmt.Fprint(os.Stdout, label)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		stdinMu.Lock()
		defer stdinMu.Unlock()
		s, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(s, "\r\n"), nil
	}
	secret, err := readSecretMasked(fd)
	fmt.Fprintln(os.Stdout)
	return secret, err
}

func promptSecretConfirm() (string, error) {
	first, err := promptSecret("Password: ")
	if err != nil {
		return "", err
	}
	second, err := promptSecret("Confirm password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passwords do not match")
	}
	if first == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return first, nil
}
