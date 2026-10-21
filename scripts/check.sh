#!/bin/sh
# Static analysis, nil-pointer checks, vulnerability scan, and tests.
# Race detection runs when a C compiler is available (glibc images).
set -eu

echo "==> go vet"
go vet ./...

echo "==> nilness (nil pointer dereference)"
go tool nilness ./...

echo "==> staticcheck"
go tool staticcheck ./...

echo "==> nilaway (nil pointer flow analysis)"
go tool nilaway ./...

if [ "${SYLVA_SKIP_GOVULNCHECK:-false}" != "true" ]; then
	echo "==> govulncheck"
	go tool govulncheck ./...
else
	echo "==> govulncheck (skipped; already ran at image build)"
fi

if command -v gcc >/dev/null 2>&1; then
	echo "==> go test -race (goroutine / memory races)"
	CGO_ENABLED=1 go test -race -count=1 -cover ./...
else
	echo "==> go test (race detector skipped: no C compiler)"
	go test -count=1 -cover ./...
fi
