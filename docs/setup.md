# Setup

Sylva is two binaries. Tunables (timeouts, Argon2id, password length, paths) ship in `internal/config/default.conf` and optional `.sylva/config`. `.env` is only host, port, and secrets (auth key, passphrase). The default self-hosted backend uses `sylvad` to store ciphertext in SQLite. The optional Git backend connects directly from `sylva` to a dedicated Git branch. `sylva` encrypts on the client and copies secrets to the clipboard. Secret values and identifiers remain encrypted in remote storage. Record IDs, types, blind indexes and parent links, versions, timestamps, and ciphertext sizes remain visible as metadata.

Profiles keep work and personal accounts in the same backend using one master
passphrase and SSH unlock session. Existing records belong to `default`.
See [profile commands](howto.md#work-and-personal-profiles).

For a vault without a daemon, follow [Git setup](howto.md#use-a-git-backed-vault).
The daemon, HTTP TLS and Tailscale setup below applies to self-hosted storage.

This page is a first run on **localhost over HTTP**. TLS 1.3 mTLS is optional and later: [mtls.md](mtls.md). Tailscale is optional: [tailscale.md](tailscale.md).

Linux is the supported desktop: native X11/Wayland clipboard and the kernel keyring. macOS and Windows clipboard/keyring are stubs.

## Build

You need Go 1.26.10 (the minimum version in `go.mod`), `make`, Python 3,
Meson >= 1.3 and Ninja. `make build` delegates compilation to Meson.
For Fedora RPMs and the packaged systemd service, see [packaging](packaging.md).
Docker is used for isolated verification and Fedora packaging in CI.

```bash
cp .env.example .env
make build
```

`.env` is gitignored. Do not commit it. Default listen address is `127.0.0.1:8443` (`scheme=http` in the shipped config).

Both commands take `-env PATH` (default `.env`). `sylvad -addr host:port` overrides the listen address. `sylva -server URL` overrides the daemon URL for one invocation. mTLS and Tailscale are not flags: `sylva enable mtls` / `sylva enable tailscale` writes `.sylva/config` once.

Plain HTTP is accepted only on an actual loopback listener (`127.0.0.1` or
`::1`). Binding `0.0.0.0`, an empty host, a LAN address, or even a host Tailscale
IP requires mTLS. This applies to `-addr` overrides too. For remote access,
enable mTLS before binding a network interface, or use the embedded tsnet
listener described in [tailscale.md](tailscale.md).

Loopback HTTP trusts local callers: it has no separate API authentication, so
local processes can read ciphertext and mutate/delete records without the vault
passphrase. Do not expose it through an unauthenticated reverse proxy, port
forward, or tunnel. Every client certificate accepted by mTLS, or peer allowed
to reach tsnet by tailnet policy, has access to the same whole-vault API.

## Start the daemon

```bash
./bin/sylvad
./bin/sylva ping
```

`ping` should report `Status: ok` and `mTLS: false`. Data file: `server_db_path` (default `.sylva/sylvad.db`). The CLI may also keep a ciphertext cache at `client_cache_path`.

Successful server reads update the cache. A missing record response removes that identifier from the cache; a successful list replaces the cached snapshot for the requested type (or all types for an unfiltered list). This also handles records deleted or recreated on another device.

An already unlocked client may read its last cached snapshot after a connection failure. HTTP errors, TLS verification errors, malformed responses, and canceled requests are returned without a cache fallback. Changes made elsewhere remain unknown until a successful server read; the cache is not a live synchronization service. Unlocking still requires the server as described below.

## Initialize the vault

Run the guided first-time setup in a terminal:

```bash
./bin/sylva init
```

The wizard asks for the storage source (self-hosted or Git), connection settings,
profile and optional SSH-agent unlock. It checks connectivity, asks for a new
master passphrase twice on an empty vault or the existing master passphrase on an
initialized vault, and creates the requested profile only when needed. Settings
are saved together in `.sylva/config` after successful verification. Passwords
and private-key contents are never written there. With the session agent enabled,
setup also opens the session so normal `set` and `get` commands work immediately.
See [the setup walkthrough](howto.md#first-time-setup-wizard).

For scripts or the previous salt-only initialization behavior:

```bash
./bin/sylva init --non-interactive
```

Without a terminal, plain `init` also keeps the salt-only behavior; it never reads
wizard answers from a pipe. That mode writes only the Argon2id salt if missing.
It does not establish a master passphrase, create profiles, save settings or open
an unlock session. Re-running either mode does not rotate an existing passphrase.

If you lose the passphrase, ciphertext in SQLite cannot be recovered. Use
`sylva backup <new-file>` for an encrypted archive and follow the
[backup and recovery how-to](howto.md#backup-and-recovery). For a direct SQLite
copy, stop the daemon first and preserve all metadata; copying a live `.db`
alone can miss writes held in the WAL. Protect transport certificates and
private keys separately from the encrypted vault backup.

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

An optional Ed25519 SSH-agent unlock can be registered separately on each
device with `sylva ssh add <public-key-file>`, authorized by the existing
master passphrase. Use `sylva unlock --ssh` to open the session with that key.
See [SSH unlock](howto.md#unlock-using-an-ssh-agent) for supported keys, local
registration files, rotation and agent-access implications.

The first passphrase unlock of an empty vault establishes its master passphrase by storing an encrypted key verifier in server metadata. The verifier remains after all secrets are deleted; a wrong passphrase cannot reopen an empty vault. `init` alone creates only the salt, so it does not establish a passphrase. An explicitly configured passphrase is used without the interactive confirmation.

Existing vaults without a verifier are upgraded automatically only after every stored record authenticates with the supplied passphrase. A wrong passphrase, damaged record, or server error aborts the unlock. Upgrade both binaries and all clients together; older clients do not enforce this verification. Back up the entire SQLite database, including metadata. A legacy vault with no records has no previous passphrase to verify and establishes one on its first unlock.

Passphrase unlock and session-agent key reuse both require the server's verifier; cached records are never used to bypass verification. If the server cannot be reached, unlocking fails. Noninteractive scripts must explicitly supply `SYLVA_MASTER_PASSPHRASE`.

### Agent lifecycle and limits

The agent holds a per-socket file lock (`agent_socket_path` plus `.lock`) for its
whole lifetime. Concurrent starts leave the existing session untouched. A dead
agent's stale socket is recovered on restart; regular files and symlinks at the
socket path are not replaced. Socket and lock files have mode `0600`. The lock
file remains after shutdown so future starts synchronize on the same inode;
do not delete it while an agent is running. Keep the socket/lock on a local
filesystem with working advisory file locks.

Override these defaults in `.sylva/config` or process environment:

| Setting | Default | Purpose |
| --- | --- | --- |
| `agent_request_timeout` | `5s` | Deadline for reading and replying to one request |
| `agent_max_request_bytes` | `1048576` | Encoded JSON frame limit, including its terminating newline |
| `agent_max_connections` | `64` | Maximum simultaneous accepted requests |

The CLI applies the same frame limit to requests and replies. Each connection
uses one newline-terminated JSON request and response; existing `json.Encoder`
clients already send this terminator. Partial requests time out; oversized or
malformed frames are rejected before changing the session. Connections above
the limit are closed immediately. These settings must be positive and are
independent of `agent_idle_timeout`, which still controls automatic key expiry.

On shutdown the agent closes active connections, waits for request and idle
workers, wipes the key/clipboard, and joins pending clipboard clear callbacks
before releasing its lock. Clipboard managers reject copies after closing.

### Cleanup failures and retrying lock

`sylva lock` attempts both keyring deletion and the agent's in-memory key wipe,
even if one fails. Only successful cleanup prints `Session locked`. A missing
agent or keyring entry is harmless; permission, connection, and deletion
failures are returned as errors. The agent always zeroes its session key on a
manual or idle lock, even when clipboard/keyring cleanup fails.

The local agent protocol reports `unlocked` and `cleanup_error` separately.
An expired key can be gone while a keyring entry or clipboard still needs
cleanup. Automatic clipboard failures emit an error event, never a successful
`clipboard cleared` event. Until a successful `sylva lock` retry, the CLI refuses
normal key reuse, unlock, and clipboard commands rather than silently falling
back to the stored/configured passphrase. An automatic clipboard failure by
itself does not immediately erase an active session key; manual/idle locking
still does, and key access remains blocked while cleanup is pending.

Resolve the reported backend/permission issue and run `sylva lock` again. A
successful retry clears the pending error. Agent shutdown also returns cleanup
errors. Upgrade/restart existing agent processes with the CLI so both sides
understand the cleanup status. This is process-local status, not a persistent
audit trail across agent crashes; if an agent exits with a cleanup error, fix
the underlying issue and retry cleanup explicitly.

## Secrets

```bash
./bin/sylva set
./bin/sylva set company.com 'secret'
./bin/sylva set mail.company.com --inherit
./bin/sylva set SYLVA_EXAMPLE 'secret' env
./bin/sylva set 10.0.0.1 'secret' ssh
./bin/sylva get mail.company.com
./bin/sylva list
./bin/sylva set github-token password
./bin/sylva update github-token password
./bin/sylva delete github-token --yes
```

`set` with no args walks through type and a hidden double password. Extra args skip prompts: `set <id> [password] [type]`. A dotted name or IP defaults to domain. Duplicate identifiers of the same type are rejected; use `update`.

`get` copies to the clipboard (it does not print the secret). If the type is omitted, Sylva probes every kind and asks when the match is empty or ambiguous.

Automatic type lookup skips missing entries and skips the domain candidate
when the identifier cannot be normalized as a domain. A failed domain lookup
returns an error instead of selecting an earlier password/token match or
prompting as if the domain were missing. This includes HTTP failures (even a
404 from the domain-list endpoint), malformed responses, corrupted encrypted
logins, and inheritance cycles. Invalid stored domains are errors too; they
are distinguished from invalid lookup input. Cancellation/timeouts remain
visible, subject to the existing cache fallback rules described above.
Specify a type explicitly (`sylva get <id> password`, for example) when you
want to query only that type.

Updates carry the fetched record's version. The server atomically accepts only the next version; if another device changes the record between that fetch and the write, the update fails with HTTP 409 and asks you to fetch it again. Sylva does not automatically retry a stale edit or merge it over newer data. A deleted and recreated identifier has a different record ID, so an old edit cannot replace it. Upgrade both the server and clients to use this behavior.

`delete` asks for confirmation unless `--yes` is supplied. Time spent choosing
a secret type or answering the confirmation does not consume the deletion
request's timeout; that timeout starts after approval. Declining or reaching
end-of-input without approval leaves the record untouched.

Clipboard backends: `auto` (X11 or Wayland), `os`, `memory`, `file`. `auto`/`os` need the agent. Docker smoke uses `memory`.

`auto` and `os` fail when the desktop clipboard is unavailable; they never
silently store a secret in process memory. Wayland requires the
`wlr-data-control` protocol; if unavailable, an accessible X11 display can be
used instead. Connection/protocol errors are retained in the error message.
For a detached agent startup failure, check `agent_log_path` for the clipboard
error. Restart existing agents after upgrading so they use this behavior.
`memory` and `file` remain explicit test/headless backends; they do not update
the desktop clipboard.

## Large vaults and transfer limits

The limits apply to encoded JSON/file bytes, including base64 and metadata,
not just the plaintext secret length:

| Setting | Default | Applies to |
| --- | --- | --- |
| `max_body_bytes` | 1 MiB | Individual records and metadata requests/responses |
| `max_vault_bytes` | 64 MiB | Record lists and snapshot download/replacement |
| `max_backup_bytes` | 128 MiB | Encrypted backup files, both writing and restoring |

These settings are independent. A snapshot cannot bypass the individual record
limit. Backup files need extra room because their authenticated outer envelope
base64-encodes the snapshot again. An oversized response is rejected before
JSON decoding instead of being silently truncated. Server-side size rejections
return HTTP 413. Oversized writes are rejected before changing the database;
failed backups do not publish a destination file.

For larger vaults, put overrides in `.sylva/config` on the relevant clients and
server, then restart the daemon. For example:

```ini
max_vault_bytes=134217728
max_backup_bytes=268435456
```

`max_backup_bytes` is a client setting. Process environment overrides are also
supported (`SYLVA_MAX_VAULT_BYTES`, `SYLVA_MAX_BACKUP_BYTES`); these tunables are
not loaded from `.env`. For Compose, edit the mounted `docker/mtls.conf` or
provide a deployment-specific config mount. Keep TLS enabled.

All limits must be positive; zero does not mean unlimited. Client and server
limits can differ, so raise both sides where needed. Existing `sylva-backup-v1`
archives remain compatible. Large transfers can also need larger
`client_timeout`, `server_read_timeout`, and `server_write_timeout`; the CLI's
request deadline remains in effect. Listing and snapshot/backup operations
still materialize whole datasets in memory. These limits provide configurable
transfer bounds, not streaming or pagination; allow memory headroom for JSON,
decoded records, and cryptographic buffers before raising them.

## Same machine settings on two hosts

`SYLVA_HOST` is both the daemon bind host (unless `server_addr` / `SYLVA_SERVER_ADDR` is set) and the host the CLI dials. On a remote daemon, the client `.env` should use that hostname (or `sylva -server`). The server certificate SAN must match that name if you turn on mTLS. Host and port can later live in `.sylva/config` instead of `.env`; process environment still overrides.

## Tests

The [CI guide](ci.md) lists independent jobs, coverage artifacts, local commands,
and required-check configuration. The [how-to](howto.md) covers daily use,
passphrase rotation, backup/recovery, and common failures.

`make docker-e2e` runs the same Docker integration test as the separate
`Docker mTLS and recovery` CI job. It requires Docker with Compose v2+, OpenSSL,
and Python 3 on Linux. No existing `.env`, certificates, or running daemon are
needed. Each run generates a short-lived test CA and certificate pairs, builds
the images, and starts two vaults on a separate bridge network with unique
volumes. The source server publishes only a random loopback port.

The test checks valid mTLS access, rejection of missing/untrusted client
certificates before HTTP, CLI create/read/update/delete and domain inheritance,
and exact decrypted values for password, domain, env, and SSH entries. It also
changes the master passphrase through hidden terminal prompts and confirms
the old passphrase stops working. Backup/restore checks include encrypted
archives with mode `0600`, refusal to overwrite an existing backup or vault,
wrong-passphrase/tampered-archive rejection, and recovery into a fresh vault.
Recovery must preserve all values without changing the source vault.

Temporary containers, images, volumes, network, certificates, and archive files
are removed on success or failure (also on a handled interrupt). A forced kill
or Docker daemon outage can prevent cleanup; leftover resources have the
unique `sylva-e2e-...` Compose project prefix. The headless value checks use an
explicit temporary file clipboard, never the desktop clipboard. CI does not
upload generated keys, archives, or clipboard files.

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
make coverage
make docker-test
make docker-e2e
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

`docker-smoke` brings up compose (`sylvad` as hostname `sylvad`) over mTLS.
First create the certificates in [mtls.md](mtls.md#docker), including the
`sylvad` DNS SAN. Noninteractive secret commands also need an explicitly set
test master passphrase. Run smoke tests against disposable test data; the
commands write to the Compose vault volume. `make docker-down` removes that
volume.

## Next

- Expose the daemon beyond localhost: [mtls.md](mtls.md) and/or [tailscale.md](tailscale.md). Tailscale listens only on the tailnet; mTLS can wrap that listener.
