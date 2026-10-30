// Package limits bounds encoded transfers before they are decoded or published.
package limits

import (
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	DefaultBodyBytes   int64 = 1 << 20
	DefaultVaultBytes  int64 = 64 << 20
	DefaultBackupBytes int64 = 128 << 20
)

var ErrExceeded = errors.New("payload exceeds size limit")

type SizeError struct {
	Scope   string
	Setting string
	Limit   int64
}

func (e *SizeError) Error() string {
	return fmt.Sprintf("%s exceeds %s limit (%d bytes)", e.Scope, e.Setting, e.Limit)
}
func (e *SizeError) Unwrap() error { return ErrExceeded }

func Validate(setting string, n int64) error {
	if n <= 0 || n == math.MaxInt64 {
		return fmt.Errorf("%s must be a positive byte count smaller than %d", setting, int64(math.MaxInt64))
	}
	return nil
}

func OrDefault(n, fallback int64) int64 {
	if n == 0 {
		return fallback
	}
	return n
}

// Read probes one byte beyond the limit, so truncated JSON is never decoded.
func Read(r io.Reader, n int64, scope, setting string) ([]byte, error) {
	if err := Validate(setting, n); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, &SizeError{Scope: scope, Setting: setting, Limit: n}
	}
	return b, nil
}

// Writer refuses bytes beyond the limit, including JSON encoding overhead.
type Writer struct {
	Writer  io.Writer
	Limit   int64
	Setting string
	Scope   string
	written int64
}

func (w *Writer) Write(p []byte) (int, error) {
	if err := Validate(w.Setting, w.Limit); err != nil {
		return 0, err
	}
	if int64(len(p)) > w.Limit-w.written {
		return 0, &SizeError{Scope: w.Scope, Setting: w.Setting, Limit: w.Limit}
	}
	n, err := w.Writer.Write(p)
	w.written += int64(n)
	return n, err
}
