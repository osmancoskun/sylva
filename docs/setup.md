# Setup

Sylva is two binaries. Tunables (timeouts, Argon2id, password length, paths) ship in `internal/config/default.conf` and optional `.sylva/config`. `.env` is only host, port, and secrets (auth key, passphrase). `sylvad` stores ciphertext in SQLite. `sylva` encrypts on the client, talks to the daemon, and copies secrets to the clipboard. The server never sees plaintext or identifiers (only a blind index and type).

This page is a first run on **localhost over HTTP**. TLS 1.3 mTLS is optional and later: [mtls.md](mtls.md). Tailscale is optional: [tailscale.md](tailscale.md).

Linux is the supported desktop: native X11/Wayland clipboard and the kernel keyring. macOS and Windows clipboard/keyring are stubs.

## Build

You need Go 1.26 (toolchain `go1.26.10` in `go.mod`) and `make`. Docker is only for tests.

```bash
cp .env.example .env
make build
```

`.env` is gitignored. Do not commit it. Default listen address is `127.0.0.1:8443` (`scheme=http` in the shipped config).

Both commands take `-env PATH` (default `.env`). `sylvad -addr host:port` overrides the listen address. `sylva -server URL` overrides the daemon URL for one invocation. mTLS and Tailscale are not flags: `sylva enable mtls` / `sylva enable tailscale` writes `.sylva/config` once.

## Start the daemon

```bash
./bin/sylvad
./bin/sylva ping
```

`ping` should report `Status: ok` and `mTLS: false`. Data file: `server_db_path` (default `.sylva/sylvad.db`). The CLI may also keep a ciphertext cache at `client_cache_path`.

Successful server reads update the cache. A missing record response removes that identifier from the cache; a successful list replaces the cached snapshot for the requested type (or all types for an unfiltered list). This also handles records deleted or recreated on another device.

An already unlocked client may read its last cached snapshot after a connection failure. HTTP errors, TLS verification errors, malformed responses, and canceled requests are returned without a cache fallback. Changes made elsewhere remain unknown until a successful server read; the cache is not a live synchronization service. Unlocking still requires the server as described below.

## Initialize the vault

Once, against an empty server:

```bash
./bin/sylva init
```

That writes the Argon2id **salt** as server metadata. Clients derive the master key from your passphrase plus this salt. Re-running `init` is safe if the salt already exists; it does not rotate it.

If you lose the passphrase, ciphertext in SQLite cannot be recovered. Back up `.sylva/sylvad.db` (and certs if you later enable mTLS). The file is still not readable without the passphrase.

## Unlock

Secret commands need a master key. Resolution order:

1. Session agent (unix socket `agent_socket_path`), if `agent_enabled=true`
2. `SYLVA_MASTER_PASSPHRASE` in `.env` (convenient for smoke tests; leave empty on a real machine)
3. Linux kernel keyring, if `keyring_enabled=true` in config and you have run `sylva unlock`
4. A terminal prompt with echo disabled. Redirected stdin is never used for the master passphrase.

Typical interactive flow:

```bash
./bin/sylva unlock
# First use: enter and confirm a new master passphrase.
# Later: enter the existing master passphrase.
```

`unlock` verifies the passphrase before storing anything in the agent or keyring, and starts the agent if needed. `get` also starts a detached agent if none is listening, so the CLI can exit while the agent owns the clipboard until `clipboard_clear_after`. `sylva lock` wipes the agent key and the keyring entry.

The first passphrase unlock of an empty vault establishes its master passphrase by storing an encrypted key verifier in server metadata. The verifier remains after all secrets are deleted; a wrong passphrase cannot reopen an empty vault. `init` alone creates only the salt, so it does not establish a passphrase. An explicitly configured passphrase is used without the interactive confirmation.

Existing vaults without a verifier are upgraded automatically only after every stored record authenticates with the supplied passphrase. A wrong passphrase, damaged record, or server error aborts the unlock. Upgrade both binaries and all clients together; older clients do not enforce this verification. Back up the entire SQLite database, including metadata. A legacy vault with no records has no previous passphrase to verify and establishes one on its first unlock.

Passphrase unlock and session-agent key reuse both require the server's verifier; cached records are never used to bypass verification. If the server cannot be reached, unlocking fails. Noninteractive scripts must explicitly supply `SYLVA_MASTER_PASSPHRASE`.

## Secrets

```bash
./bin/sylva set
./bin/sylva set company.com 'secret'
./bin/sylva set mail.company.com --inherit
./bin/sylva set SYLVA_EXAMPLE 'secret' env
./bin/sylva set 10.0.0.1 'secret' ssh
./bin/sylva get mail.company.com
./bin/sylva list
./bin/sylva update github-token 'new-secret'
./bin/sylva delete github-token --yes
```

`set` with no args walks through type and a hidden double password. Extra args skip prompts: `set <id> [password] [type]`. A dotted name or IP defaults to domain. Duplicate identifiers of the same type are rejected; use `update`.

`get` copies to the clipboard (it does not print the secret). If the type is omitted, Sylva probes every kind and asks when the match is empty or ambiguous.

Updates carry the version that was read before editing. The server atomically accepts only the next version; if another device has already changed that record, the update fails with HTTP 409 and asks you to fetch it again. Sylva does not automatically retry a stale edit or merge it over newer data. A deleted and recreated identifier has a different record ID, so an old edit cannot replace it. Upgrade both the server and clients to use this behavior.

Clipboard backends: `auto` (X11 or Wayland), `os`, `memory`, `file`. `auto`/`os` need the agent. Docker smoke uses `memory`.

## Same machine settings on two hosts

`SYLVA_HOST` is both the daemon bind host (unless `server_addr` / `SYLVA_SERVER_ADDR` is set) and the host the CLI dials. On a remote daemon, the client `.env` should use that hostname (or `sylva -server`). The server certificate SAN must match that name if you turn on mTLS. Host and port can later live in `.sylva/config` instead of `.env`; process environment still overrides.

## Tests

`make check` runs formatting, `go vet` (including missed context cancellation),
nilness, Staticcheck, NilAway, HTTP response-body and SQL rows/statement closing
checks, vulnerability scanning, and uncached tests. A failed analysis does not
skip the remaining checks; any failure makes the command fail.

Tests check for goroutines left running after package cleanup with goleak.
The CLI tests use the same check. The race detector runs when a C compiler is
available, and each test package has a five-minute timeout. Tool versions are
pinned in `go.mod`; no separate global tool installation is needed.

These checks detect classes of nil dereferences, invalid zero values, resource
leaks, and races. They do not prove that every empty identifier is invalid or
that heap usage stays bounded. New long-lived caches, timers, network workers,
and background services need lifecycle tests and, when appropriate, repeated
load tests with heap profiles. Test cleanup must close resources, cancel work,
and wait for workers to stop; do not broadly ignore application goroutines.

```bash
make check
make docker-test
make docker-smoke
```

Nil items, blank identifiers, missing type payloads, incomplete encrypted
envelopes, and repeated clipboard copy/close cycles have regression tests in
`make check`. Fuzz seed cases run with the ordinary tests. CI also mutates
inputs for five seconds per fuzz target; run longer sessions locally:

```bash
make fuzz FUZZTIME=30s
make bench BENCHTIME=5s
make profile-memory BENCHTIME=5s
go tool pprof -top -alloc_space .profiles/vault.heap
go tool pprof -top -inuse_space .profiles/vault.heap
go tool pprof -top -inuse_space .profiles/clipboard.heap
```

The benchmarks exercise 1 KiB/64 KiB vault records and clipboard timer
creation/cancellation, using synthetic secrets only. Profiles and test binaries
go into the gitignored `.profiles/` directory (`PROFILE_DIR` overrides it).
Profiling every allocation is intentionally slower than `make bench`.
Compare runs with the same Go version, hardware, payload, and duration.
`alloc_space` shows cumulative allocation; `inuse_space` shows retained heap.
Neither allocations per operation nor one heap snapshot proves a leak. If
retained heap grows with repeated work, compare profiles at increasing workload
sizes before adding a stable regression bound. Machine-dependent memory limits
are not used as CI pass/fail thresholds.

`docker-smoke` brings up compose (`sylvad` as hostname `sylvad`). `make docker-down` removes the volume.

## Next

- Expose the daemon beyond localhost: [mtls.md](mtls.md) and/or [tailscale.md](tailscale.md). Tailscale listens only on the tailnet; mTLS can wrap that listener.
