#!/bin/sh
# Nil/zero-value analysis, resource lifecycle checks, vulnerability scan, and tests.
# Race detection runs when a C compiler is available (glibc images).
set -u

group=${1:-all}
if [ "$#" -gt 1 ]; then
	echo "Usage: $0 [all|analysis|security|test]" >&2
	exit 2
fi
case "$group" in
	all|analysis|security|test) ;;
	*) echo "Usage: $0 [all|analysis|security|test]" >&2; exit 2 ;;
esac

status=0
run_check() {
	label=$1
	shift
	printf '\n==> %s\n' "$label"
	if "$@"; then
		:
	else
		printf 'FAILED: %s\n' "$label" >&2
		status=1
	fi
}

check_format() {
	files=$(gofmt -l cmd internal) || return 1
	if [ -n "$files" ]; then
		printf 'Run gofmt -w on:\n%s\n' "$files" >&2
		return 1
	fi
}

if [ "$group" = all ] || [ "$group" = analysis ]; then
	run_check "gofmt" check_format
	run_check "go vet (including lost context cancellation)" go vet ./...
	run_check "nilness (nil pointer dereference)" go tool nilness ./...
	run_check "staticcheck (invalid values and API misuse)" go tool staticcheck ./...
	run_check "nilaway (nil pointer flow analysis)" go tool nilaway ./...
	run_check "bodyclose (HTTP response lifecycle)" go tool bodyclose ./...
	run_check "sqlclosecheck (SQL rows and statement lifecycle)" go tool sqlclosecheck ./...
fi

if [ "$group" = all ] || [ "$group" = security ]; then
	if [ "${SYLVA_SKIP_GOVULNCHECK:-false}" != "true" ]; then
		run_check "govulncheck" go tool govulncheck ./...
	else
		echo "==> govulncheck (skipped; already ran at image build)"
	fi
fi

if [ "$group" = all ] || [ "$group" = test ]; then
	if command -v gcc >/dev/null 2>&1; then
		run_check "go test -race (races and goroutine leaks)" env CGO_ENABLED=1 go test -race -count=1 -timeout=5m -cover ./...
	else
		run_check "go test (goroutine leaks; race detector unavailable)" go test -count=1 -timeout=5m -cover ./...
	fi
fi

exit "$status"
