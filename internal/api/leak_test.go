package api_test

import (
	"testing"

	"github.com/osman/sylva/internal/leakcheck"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}
