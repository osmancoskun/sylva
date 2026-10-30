# Command and recovery how-to

Build and configure the binaries with [setup.md](setup.md). Examples assume
you run from the same project directory and have a reachable daemon. Paths
such as `.sylva/config`, the agent socket, and the cache are relative to that
directory unless overridden. Use [mTLS](mtls.md) or [Tailscale](tailscale.md)
before connecting remotely.

## Prepare mTLS certificates

For a new setup, generate the bundle and enable mTLS:

```bash
./bin/sylva cert init
./bin/sylva enable mtls
```

Restart `sylvad` after enabling. If clients dial a remote DNS name or IP,
include it when creating the bundle: `sylva cert init --host vault.example.com`.
The defaults already cover localhost and Docker's `sylvad`. Existing
certificate directories are preserved; this is initialization, not renewal.
Keep `ca.key` offline and follow the [mTLS guide](mtls.md) for distribution.

For Tailscale + mTLS, first enable Tailscale, start `sylvad`, and finish its
login. In a second terminal run `sylva cert init --add-tailscale`, then
`sylva enable mtls` and restart the daemon. The command discovers the actual
embedded node name from the running local daemon. See the
[combined setup](tailscale.md#with-mtls) for details.

If certificates already exist, keep them and use `sylva cert add-tailscale`
after the Tailscale-enabled daemon has joined. Make the original `ca.key`
available locally to sign, then take it offline again. Only `server.pem` is
reissued; current addresses, dates, CA, and client credentials are preserved.
Restart the daemon after an update. See the
[update procedure](mtls.md#add-tailscale-to-existing-certificates) for Docker
recreation and validation requirements.

## Daily use

```bash
./bin/sylva ping
./bin/sylva unlock
./bin/sylva set github-token password
./bin/sylva get github-token password
./bin/sylva update github-token password
./bin/sylva list
./bin/sylva delete github-token password
./bin/sylva lock
```

`unlock` verifies the master passphrase before keeping a key in the session
agent. An empty vault asks you to enter and confirm a new master passphrase.
Deleting every secret does not reset that passphrase. Keep
`SYLVA_MASTER_PASSPHRASE` empty for interactive use; a configured value takes
precedence over a terminal prompt. Master passphrases require an interactive
terminal and are read without echo; piping them into stdin is rejected.

The `set` and `update` examples prompt for the secret twice. Supplying a
literal value as a command argument skips those prompts but exposes it to
shell history and process arguments. `list` prints identifiers and types;
`get` copies the decrypted value and never prints it. For unattended deletion,
use `delete <id> <type> --yes`. Otherwise deletion waits for approval, with
a fresh network deadline after you answer.

## Domains, environment variables, and SSH

```bash
./bin/sylva set company.com
./bin/sylva set mail.company.com --inherit
./bin/sylva get mail.company.com domain
./bin/sylva get login.mail.company.com domain --cascade

./bin/sylva set project-one env --variable API_TOKEN
./bin/sylva get project-one env --variable API_TOKEN

./bin/sylva set 10.0.0.1 ssh
./bin/sylva get 10.0.0.1 ssh
```

An inherited domain entry resolves its parent's password. `--cascade` also
allows lookup to walk to a stored ancestor when the exact domain is absent.
An env entry stores a project and named variables; use `--variable` when a
project has multiple values. The SSH command above stores a passphrase for
the host, not a generated SSH key pair.

Without an explicit type, lookups probe all kinds. A broken domain record,
HTTP failure, or inheritance cycle is reported even if another kind matched
earlier. Specify a type when you intend to query just that kind. If an update
fails with HTTP 409, fetch the current record and review the change before
retrying; Sylva does not overwrite a newer version automatically.

## Clipboard and session cleanup

Desktop copying needs the agent and a working X11 display or Wayland
`wlr-data-control` compositor. `auto` and `os` return errors when unavailable;
they do not fall back to memory. The default automatic clear is `20s`, and it
does not clear content that has since changed. Desktop clipboard managers
and applications may keep their own history outside Sylva's selection.

For headless test automation, explicitly choose `memory` or `file`; neither
updates the desktop clipboard. A file backend writes plaintext to the chosen
path, so use disposable synthetic data. `make docker-e2e` handles this with a
temporary directory. It is the preferred automated Docker check.

`sylva lock` clears the session key, attempts keyring deletion and clipboard
cleanup, and reports failures. A failed cleanup blocks normal session reuse;
fix the display/keyring/permission problem and run `sylva lock` again. Manual
or idle locking still zeroes the agent key even if another cleanup step fails.

The agent log defaults to `.sylva/agent.log`. Clipboard initialization errors
from detached startup appear there. After upgrading, lock and stop the old
agent before starting a new one: use Ctrl-C for a foreground `sylva agent`,
or send SIGTERM to the verified detached agent PID. `sylva lock` locks the
session but does not stop the process. Do not remove its socket or `.lock`
file while it is running; dead-agent sockets are recovered automatically.

## Change the master passphrase

```bash
./bin/sylva passwd
./bin/sylva unlock
```

`passwd` verifies the current key, asks for the new passphrase twice on a
terminal, and atomically re-encrypts the vault. A concurrent change aborts
the replacement rather than leaving a partially rotated vault. Successful
rotation locks the local session; unlock each device with the new passphrase.
Update any explicitly configured `SYLVA_MASTER_PASSPHRASE` too.

If the command says the passphrase changed but cleanup failed, the rotation
already happened. Resolve cleanup and retry `sylva lock`; use the new
passphrase for the next unlock. Take a fresh backup after rotation. Existing
backups still require the passphrase used when they were created.

## Backup and recovery

Create a new archive path in an existing directory:

```bash
mkdir -p .sylva/backups
./bin/sylva backup .sylva/backups/vault-2026-10-30.backup
```

Choose a new filename for every backup. Sylva writes an authenticated,
encrypted archive with mode `0600` and refuses to overwrite an existing file.
It includes vault records, salt, KDF parameters, and the key verifier. It does
not include TLS certificates/private keys, Tailscale state, or local config.
Copy the archive to a separate backup location and protect transport keys
separately. Keep the backup's master passphrase: there is no passphrase reset
or server-side recovery for a lost key.

Restore only into an uninitialized target. Deleting all records from an
existing vault leaves its verifier and does not make it a valid target. Start
a new daemon using a fresh database or a fresh Compose volume. Do not unlock
or add secrets on that target before restoring.

For the default loopback HTTP setup, start a separate target in another
terminal with a new database path and port:

```bash
mkdir -p .sylva/recovery
SYLVA_SERVER_DB_PATH=.sylva/recovery/sylvad.db \
  ./bin/sylvad -addr 127.0.0.1:9443
```

Then restore and verify from the client terminal:

```bash
./bin/sylva -server http://127.0.0.1:9443 restore .sylva/backups/vault-2026-10-30.backup
./bin/sylva -server http://127.0.0.1:9443 unlock
./bin/sylva -server http://127.0.0.1:9443 list
./bin/sylva -server http://127.0.0.1:9443 get company.com domain
```

Supply the archive's passphrase, even if the source vault has since rotated.
An explicitly configured `SYLVA_MASTER_PASSPHRASE` is also used for restore;
clear it to get a terminal prompt, or set it to the archive's passphrase.
For mTLS/tsnet deployments, configure the new target separately using the
transport guides and use its authenticated URL instead of these HTTP examples.
Keep the original database and backup until you have verified the restored
identifiers and representative values of every secret type. Restore locks
the local session and does not modify the source daemon.

For direct SQLite backups, stop the daemon before copying its database and
preserve all metadata. A running SQLite database can have committed writes
in `-wal`; copying only its `.db` file is not a consistent backup strategy.

## Common failures

| Symptom | Action |
| --- | --- |
| `incorrect master passphrase or damaged vault verification data` | Check the configured passphrase and target URL. For restore, use the backup's passphrase. Preserve the original data if corruption is suspected. |
| Clipboard unavailable or agent did not become ready | Check `DISPLAY`/`WAYLAND_DISPLAY`, compositor support, and `agent_log_path`; do not expect headless memory copying to reach the desktop. |
| Cleanup incomplete | Fix the reported backend/keyring error, then retry `sylva lock`. |
| HTTP 409 | Fetch current data and review concurrent changes before retrying. |
| HTTP 413 or a local size-limit error | Review the separate record, snapshot, and backup limits in [setup](setup.md#large-vaults-and-transfer-limits); account for JSON/base64 overhead and memory. |
| TLS trust or client-certificate error | Match the server SAN to the dialed host and install the correct CA/client pair using [mTLS setup](mtls.md). |
| Server unreachable during unlock | Restore connectivity. Cached records cannot bypass master-key verification. |
| Restore requires an uninitialized target | Start a fresh target database/volume; an emptied initialized vault is still initialized. |
