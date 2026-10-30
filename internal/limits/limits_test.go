package limits_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/osman/sylva/internal/limits"
)

func TestReadExactLimitAndOverflow(t *testing.T) {
	got, err := limits.Read(strings.NewReader("1234"), 4, "response", "test_limit")
	if err != nil || string(got) != "1234" {
		t.Fatalf("exact limit: %q %v", got, err)
	}
	got, err = limits.Read(strings.NewReader("12345"), 4, "response", "test_limit")
	if !errors.Is(err, limits.ErrExceeded) || got != nil {
		t.Fatalf("overflow returned partial data: %q %v", got, err)
	}
}

func TestWriterNeverPublishesBeyondLimit(t *testing.T) {
	var dst bytes.Buffer
	w := &limits.Writer{Writer: &dst, Limit: 4, Scope: "backup", Setting: "test_limit"}
	if _, err := w.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write([]byte("5")); n != 0 || !errors.Is(err, limits.ErrExceeded) {
		t.Fatalf("overflow: %d %v", n, err)
	}
	if dst.String() != "1234" {
		t.Fatal("writer exceeded limit")
	}
}
