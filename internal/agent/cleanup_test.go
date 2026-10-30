package agent

import (
	"bytes"
	"errors"
	"testing"
)

func TestCleanupFailureStillZeroesSessionKey(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	failure := errors.New("keyring deletion denied")
	s := &Server{key: key, onLock: func() error { return failure }}
	if err := s.wipe(); !errors.Is(err, failure) {
		t.Fatalf("cleanup failure lost: %v", err)
	}
	if s.key != nil || !s.expires.IsZero() || !bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("failed cleanup retained in-memory key")
	}
}
