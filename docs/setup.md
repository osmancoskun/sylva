# Setup

Sylva is two binaries that share one `.env`. `sylvad` stores ciphertext in SQLite. `sylva` encrypts on the client, talks to the daemon, and copies secrets to the clipboard. The server never sees plaintext or identifiers (only a blind index and type).

This page is a first run on **localhost over HTTP**. TLS 1.3 mTLS is optional and later: [mtls.md](mtls.md). Tailscale is not implemented yet.

Linux is the supported desktop: native X11/Wayland clipboard and the kernel keyring. macOS and Windows clipboard/keyring are stubs.

## Build

You need Go 1.26 (toolchain `go1.26.10` in `go.mod`) and `make`. Docker is only for tests.

```bash
cp .env.example .env
make build
```

`.env` is gitignored. Do not commit it. Default listen address is `127.0.0.1:8443` with `SYLVA_SCHEME=http`.

Both commands take `-env PATH` (default `.env`). `sylvad -addr host:port` overrides the listen address. `sylva -server URL` overrides the daemon URL for one invocation.

## Start the daemon

```bash
./bin/sylvad
./bin/sylva ping
```

`ping` should report `Status: ok` and `mTLS: false`. Data file: `SYLVA_SERVER_DB_PATH` (default `.sylva/sylvad.db`). The CLI may also keep a ciphertext cache at `SYLVA_CLIENT_CACHE_PATH`.

## Initialize the vault

Once, against an empty server:

```bash
./bin/sylva init
```

That writes the Argon2id **salt** as server metadata. Clients derive the master key from your passphrase plus this salt. Re-running `init` is safe if the salt already exists; it does not rotate it.

If you lose the passphrase, ciphertext in SQLite cannot be recovered. Back up `.sylva/sylvad.db` (and certs if you later enable mTLS). The file is still not readable without the passphrase.

## Unlock

Secret commands need a master key. Resolution order:

1. Session agent (unix socket `SYLVA_AGENT_SOCKET_PATH`), if `SYLVA_AGENT_ENABLED=true`
2. `SYLVA_MASTER_PASSPHRASE` in `.env` (convenient for smoke tests; leave empty on a real machine)
3. Linux kernel keyring, if `SYLVA_KEYRING_ENABLED=true` and you have run `sylva unlock`
4. Otherwise the command fails closed

Typical interactive flow:

```bash
# optional: keep the agent in another terminal
./bin/sylva agent

# passphrase from the environment for this shell only, then:
SYLVA_MASTER_PASSPHRASE='your-passphrase' ./bin/sylva unlock
```

`get` starts a detached agent if none is listening, so the CLI can exit while the agent owns the clipboard until `SYLVA_CLIPBOARD_CLEAR_AFTER`. `sylva lock` wipes the agent key and the keyring entry.

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

Clipboard backends: `auto` (X11 or Wayland), `os`, `memory`, `file`. `auto`/`os` need the agent. Docker smoke uses `memory`.

## Same `.env` on two hosts

`SYLVA_HOST` is both the daemon bind host (unless `SYLVA_SERVER_ADDR` is set) and the host the CLI dials. On a remote daemon, the client `.env` should use that hostname (or `sylva -server`). The server certificate SAN must match that name if you turn on mTLS.

## Tests

```bash
make docker-test
make docker-smoke
```

`docker-smoke` brings up compose (`sylvad` as hostname `sylvad`). `make docker-down` removes the volume.

## Next

- Expose the daemon beyond localhost: [mtls.md](mtls.md). Same port as HTTP; restart into mTLS; update **both** `.env` files.
- Tailscale: flags exist (`SYLVA_TAILSCALE_ENABLED`, `sylvad -tailscale`) but `sylvad` exits with `tailscale is not implemented`.
