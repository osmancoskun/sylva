# CI and local verification

The [Check workflow](../.github/workflows/check.yml) runs on pushes, pull
requests, and manual dispatch. Jobs run independently, so one failed analyzer
does not prevent tests or the vulnerability scan from producing results.

| Check name | Purpose | Local equivalent |
| --- | --- | --- |
| Static analysis | Formatting, vet, nilness, Staticcheck, NilAway, HTTP/SQL resource lifecycles | `make analyze` |
| Vulnerability scan | Reachable Go vulnerability checks | `make security` |
| Race tests and coverage | Uncached tests, race detector, goroutine cleanup, coverage reports | `make coverage` |
| Crypto fuzzing | Five seconds of mutation per crypto fuzz target, in addition to ordinary seed tests | `make fuzz FUZZTIME=5s` |
| Build binaries | Build CLI and daemon | `make build` |
| Docker mTLS and recovery | Isolated bridge-network transport and CLI recovery checks | `make docker-e2e` |
| check | Pass only when every job above succeeded | Aggregate CI status |

`check` runs even when a dependency fails or is skipped. It fails for any
failure, cancellation, or skipped dependency, and keeps one stable status
name for branch protection. It has no checkout or repository write access.
The workflow grants `contents: read`, disables persisted checkout credentials,
and pins actions to commit SHAs. Docker E2E uses only disposable synthetic data.

## Running locally

Use the Go toolchain from `go.mod`; analysis tools are also pinned there.
`make check` still runs the complete local analysis/security/test suite and
returns failure if any check fails. `scripts/check.sh` also accepts `all`,
`analysis`, `security`, or `test` to run a group directly. Invalid groups fail.
The local script uses the race detector when a C compiler is available;
`make coverage` requires race-detector support, including a C compiler.

```bash
make check
make coverage
make fuzz FUZZTIME=30s
make docker-e2e
```

Docker E2E requires Linux, Docker Compose v2+, Python 3, and OpenSSL, and needs
no existing certificates or `.env`. See [setup](setup.md#tests) for test
isolation and the older `docker-test`/`docker-smoke` targets. It does not test
a real X11/Wayland desktop or an actual Tailscale account policy.

`govulncheck` reports vulnerabilities reachable from application code. Module
findings that are not reachable can still appear in its output; review them
when updating dependencies. The scan is a separate job, with no skip flag in
CI. The Docker test image skips its runtime scan only because the same scan
already ran during the image build.

## Coverage reports

`make coverage` produces these files under `.coverage/` (`COVERAGE_DIR`
overrides the directory):

| File | Contents |
| --- | --- |
| `coverage.out` | Atomic Go statement coverage profile from race-enabled tests |
| `coverage.txt` | Per-function coverage and a total from `go tool cover -func` |
| `coverage.html` | Source-level HTML view from `go tool cover -html` |

Outputs are gitignored and excluded from Docker build contexts. Each run
removes previous reports first. Report generation cannot turn a failed test
run into a successful command. Reports from failed runs may be partial; inspect
the test result before comparing totals.

On GitHub, open the workflow run's **Race tests and coverage** job for the test
output and function table in its summary. Download the
`coverage-<run_id>-<run_attempt>` artifact from the run's **Artifacts** section
for the profile, text table, and HTML view. It is retained for 14 days, subject
to repository policy. Only those three files are uploaded, including on
failure when reports exist; canceled runs may not produce an artifact. No
certificates, databases, backups, or clipboard files are uploaded. See the
[artifact action](https://github.com/actions/upload-artifact) for its options.

There is no percentage threshold yet. Coverage measures exercised statements;
it does not establish protection from every nil pointer, empty reference,
race, or memory leak. Keep lifecycle regression tests and use the heap-profile
workflow in [setup](setup.md#tests) for retained-memory investigations.

## Required PR checks

Workflow files report statuses; they do not enforce merge restrictions by
themselves. On this private repository, both branch-protection and ruleset API
reads returned HTTP 403 with a request to upgrade the GitHub plan. Required
checks have **not** been enabled by this change. See GitHub's
[protected branch availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

When the repository's plan supports it:

1. Push this workflow and let **Check** run so the `check` status is registered.
2. In the repository's branch protection or branch ruleset settings, target
   the default branch (`main`). Preserve any existing reviews, bypass, and
   deletion/force-push restrictions.
3. Require a pull request and passing status checks before merge. Select the
   `check` context produced by GitHub Actions. Its dependency list includes
   Docker E2E, coverage, security, analysis, fuzzing, and the build.
4. Enable the rule and confirm that a PR with a failed job cannot merge. If
   administrators or other actors can bypass it, review that policy explicitly.

Until that repository-side rule is available and enabled, a failing workflow
remains visible but does not itself prevent a merge. This change does not
alter repository visibility, subscription, or existing remote settings.
