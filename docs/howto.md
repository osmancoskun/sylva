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

## First-time setup wizard

Run `sylva init` in a terminal. The wizard guides you through:

1. **Storage source:** the existing self-hosted service or a Git repository.
2. **Connection:** server URL and optional mTLS certificate paths, or Git remote
   and branch. The Git repository should be private and empty or use a dedicated
   Sylva branch; SSH transport needs a configured host key and loaded SSH key.
3. **Profile:** keep `default`, select an existing profile, or enter a new name
   such as `personal` or `work`. A missing profile is created after authentication.
4. **Unlock method:** retain master-passphrase unlock and optionally register an
   existing Ed25519 SSH-agent key using its `.pub` file path (press Enter to use
   the shown path). Invalid files are prompted again. The matching private key
   must be loaded in ssh-agent. Repeating setup reuses an existing registration
   after verifying agent access and that it unlocks the current vault key. A
   different key, stale registration or invalid file is never silently replaced;
   use `sylva ssh remove` before registering another key.
5. **Verification:** review the choices, confirm setup, then supply the master
   passphrase. Empty vaults ask for a new passphrase and confirmation; initialized
   vaults require their existing passphrase. The master passphrase is read with
   terminal echo disabled. If `SYLVA_MASTER_PASSPHRASE` is explicitly configured,
   that value is used instead of prompting.

Setup connects to an existing service/repository; it does not start a daemon,
create a hosted Git repository, accept unknown SSH host keys or generate/load
SSH private keys. For mTLS, supply the CA and client files issued for that server.
A Git setup leaves existing self-hosted TLS settings intact. Reconfiguration
selects a source; it does not copy or migrate secrets between sources.

Cancelling the review or failing connection/password verification leaves the
local configuration unchanged. Successful verification creates any required
vault metadata/profile and saves the selected connection and profile together
with mode `0600`, preserving unrelated settings. Master passphrases and private
key contents are not saved in this file. If a later optional SSH enrollment or
session startup fails, the error reports that setup was saved and how to retry.

A configured environment override takes precedence over saved configuration.
The wizard refuses conflicting choices and names the variable to unset instead
of saving choices that subsequent commands would ignore. Global `--server` and
`--profile` flags seed wizard defaults; `--timeout` applies to its requests.

With the default session agent enabled, setup finishes with the chosen profile
active and the session unlocked. Daily use keeps its usual syntax:

```bash
sylva init
sylva set github.com
sylva get github.com
```

`init --wizard` explicitly requests the wizard and requires a terminal.
`init --non-interactive` preserves the original salt-only initialization and
never opens a wizard, even in a terminal. Plain `init` without a terminal also
uses that mode, preserving existing automation. Redirected input never supplies
wizard answers or a master passphrase. Invalid/extra init arguments are rejected.

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

## Work and personal profiles

Existing commands keep their usual syntax: `sylva set github.com`,
`sylva get github.com`, and the `sylva github.com` shorthand still work. Profile
management is optional. Until you explicitly select another profile, commands
continue using `default`. After `sylva switch work`, that selection stays active
until you explicitly switch again; daily commands require no profile flag or type
argument unless you need to disambiguate multiple secret types.

Profiles separate accounts within the same vault backend. They share one master
passphrase, SSH unlock registration and session agent. Creating or switching a
profile does not change the server, SQLite database, Git repository or branch.
Existing records remain in the built-in `default` profile without re-encryption.

```bash
./bin/sylva unlock
./bin/sylva profile create personal
./bin/sylva profile create work
./bin/sylva profile list
./bin/sylva profile current

./bin/sylva switch personal
./bin/sylva set github.com --username personal@example.com

./bin/sylva switch work
./bin/sylva set github.com --username employee@example.com
./bin/sylva get github.com
./bin/sylva list

./bin/sylva switch personal
./bin/sylva get github.com
./bin/sylva switch default
```

`set` prompts for the password. The username field may contain an email address;
username support currently belongs to domain/login records. `get` continues to
copy the password. The same identifier and type may exist independently in each
profile, including separate domain inheritance trees, environment bundles and SSH
records. Ordinary secret lists never include the encrypted profile descriptors.

`switch <name>` (also `profile use <name>`) verifies that the profile exists before
saving `profile=<name>` in the local `.sylva/config`. Selection is local to this
working directory/device; switching on A does not switch B. Profile names use
1–64 lowercase letters, digits, hyphens or underscores. `SYLVA_PROFILE` overrides
the saved selection; `--profile` before the command overrides it for one command.
Unset a conflicting `SYLVA_PROFILE` before using `switch`. Unknown profiles fail
instead of being created implicitly or falling back to another profile.

An unlocked session can switch profiles without re-entering the master passphrase.
Switching clears the agent-owned clipboard while retaining the root session key.
Use `sylva profile current` to inspect the selection; ordinary command output
keeps its existing format. `sylva lock` closes access
to every profile in that session. A registered SSH key unlocks the same root vault
and can be used with any of its profiles; register separately on each device.

Profile descriptors (names and random IDs) are encrypted root records. Each named
profile derives its own encryption and blind-index keys from the root key and
random profile ID; authenticated record data binds ciphertext to that profile.
The default profile preserves the legacy key/index format. Opaque profile IDs
and record grouping are visible to storage, but profile names, usernames and
passwords remain encrypted. Profiles organize one person's accounts: backend
credentials and the root master key still grant access to the entire vault.

`passwd`, `backup` and `restore` always cover **all profiles**, even when a named
profile or `--profile` is selected. Rotation re-encrypts the profile catalog and
all records atomically, invalidating old root sessions and SSH registrations.
Backups preserve the complete catalog and profile bindings; restoring an older
backup without profiles creates only `default`. The local active selection is
not part of a backup. After changing backends or restoring a vault without the
saved profile, use `sylva switch default` to recover the local selection.

Upgrade `sylvad` and all clients before creating profiles. SQLite adds an indexed
`profile_id` column automatically without changing existing envelopes. Git keeps
default records in `records/` and named-profile records in
`profiles/<opaque-id>/records/` within the same branch. Profile creation does not
move existing default records. Older clients cannot safely manage profiled vaults.

## Unlock using an SSH agent

The master passphrase remains the vault's recovery and normal unlock method.
You can also register an ordinary Ed25519 key already loaded in your local
SSH agent. On each device, connect to the intended server, establish the vault's
master passphrase with `sylva unlock` if needed, then run:

```bash
ssh-add ~/.ssh/id_ed25519
./bin/sylva ssh add ~/.ssh/id_ed25519.pub
# Enter the existing vault master passphrase to authorize this device's key.
./bin/sylva ssh status
./bin/sylva unlock --ssh
./bin/sylva get github-token password
./bin/sylva lock
```

`ssh add` reads only the public key file and requires the master passphrase
even if a Sylva session is already open. The corresponding private key must
be available through `SSH_AUTH_SOCK`. Agent policies still apply: approval
may be required, and registration performs two signing requests to check
repeatability. RSA, ECDSA, SSH certificates and `sk-*` FIDO keys are not
supported by this unlock format. No SSH key is generated or loaded by Sylva.

`unlock --ssh` opens the Sylva session agent, so `agent_enabled=true` is
required (the default). Subsequent commands reuse that session normally.
`sylva unlock` without the flag continues using the existing master-passphrase
and OS-keyring flow. A missing/locked SSH agent, rejected approval, damaged
registration or failed server verification is an error; SSH unlock does not
silently fall back to another method. Use plain `sylva unlock` to choose the
master passphrase instead. `lock` wipes the active session; reopening through
SSH requires another explicit `unlock --ssh`.

The local registration is a 0600 file in `.sylva/ssh/` (override
`ssh_unlock_dir` in `.sylva/config` or `SYLVA_SSH_UNLOCK_DIR` in the process
environment). It contains the public key, random salt and an encrypted copy
of the vault key, bound to the server URL and API prefix. SSH signatures and
unwrapped vault keys are never written to this file. The key is verified
against the live server before the session is opened, so SSH unlock requires
connectivity. Remote mTLS/Tailscale access settings still apply.

For A and B, register each device separately with the same master passphrase;
their SSH keys may differ. Neither A's session nor its private SSH key needs
to be copied to B. Registrations are local conveniences and are not included
in server backups. The master-passphrase backup/restore format is unchanged.
After `sylva passwd`, use the new master passphrase and register SSH again:

```bash
./bin/sylva ssh remove
./bin/sylva ssh add ~/.ssh/id_ed25519.pub
```

`ssh remove` deletes only this device's local registration. It does not close
an open session, unload the SSH key or revoke copies of the registration.
Use `sylva lock` to close a session; change the master passphrase to invalidate
existing SSH registrations against the current vault.

Treat a registered SSH agent as access to the vault: anyone who can request
its signature and obtain the local registration can recover the vault key.
This includes a host to which you forward that agent. A captured signature
for this registration can unlock its encrypted key later, even after the
agent is locked. Keep registrations private, avoid forwarding the registered
key to untrusted hosts, and use an agent confirmation policy where appropriate.
The signing payload uses the OpenSSH SSHSIG format with a Sylva-specific
namespace; HKDF-SHA256 derives the AES-256-GCM wrapping key from the verified,
deterministic Ed25519 signature. This is a convenience unlock mechanism, not
a second authentication factor.

## Use a Git-backed vault

Self-hosted storage is still the default (`backend=self-hosted`). Git is an
optional client backend; it does not require `sylvad` or a Sylva TLS listener.
Create a separate **private, empty repository** on GitHub, GitLab, or another
Git server. Do not initialize the selected branch with a README or source code.
Alternatively, select a new dedicated branch in an existing private repository.
Sylva refuses a branch containing unrelated files.

Configure `.sylva/config` on each device:

```ini
backend=git
git_remote=git@github.com:YOUR_USER/sylva-vault.git
git_branch=main
git_timeout=30s
git_cache_dir=.sylva/git
```

These are local configuration settings, not `.env` settings. Process environment
overrides such as `SYLVA_BACKEND`, `SYLVA_GIT_REMOTE`, `SYLVA_GIT_BRANCH` and
`SYLVA_GIT_TIMEOUT` are also supported. `-server` applies only to self-hosted
storage; it cannot override the Git destination.

Install Git and OpenSSH on CLI hosts. The Docker CLI image includes both.
Load the intended SSH key into your existing SSH agent and establish the Git
host's verified key in `known_hosts` using your normal SSH setup. Sylva uses
SSH batch mode and strict host-key checking: it does not accept unknown host
keys or prompt for an SSH private-key passphrase during a Git operation.
Standard `~/.ssh/config` host aliases, identity files and jump hosts apply.

```bash
ssh-add ~/.ssh/id_ed25519
./bin/sylva ping
./bin/sylva unlock
# First device creates the master passphrase; other devices enter that same one.
./bin/sylva set github-token password
./bin/sylva get github-token password
./bin/sylva lock
```

Git over SSH provides encrypted transport without Sylva mTLS certificates.
HTTPS Git remotes are also supported, with TLS verification enabled and
credentials supplied through a configured Git credential helper. Use the
canonical repository URL; HTTP redirects are disabled. Do not embed
passwords or tokens in `git_remote`. Plain HTTP, `git://`, and executable remote
helpers are rejected. Absolute local bare repository paths and local `file://`
URLs are supported for private local storage and tests.

Git authentication grants repository access. Master-passphrase or registered
SSH unlock grants decryption access; these remain separate. The optional
`sylva ssh add` / `sylva unlock --ssh` flow also works with Git. Register on each
device after selecting its Git backend; registrations are bound to the remote
and branch. Changing only an HTTP server URL does not select a different Git
vault. Use separate working directories or override agent/cache paths when
working with multiple vaults.

The selected branch contains `vault.json` for the format marker, salt, KDF
parameters, key verifier, revision/generation, an ID-to-blind-index map and
opaque record-to-profile mappings.
Each default-profile encrypted record is a separate `records/<blind-index>.json`
file; named profiles use `profiles/<opaque-id>/records/<blind-index>.json`. File names
never contain plaintext identifiers. Record types, versions, timestamps, sizes
and blind indexes remain visible as in self-hosted storage; secret values and
identifiers stay encrypted. Commit messages contain no secret identifiers.

Each CLI command fetches the live branch once, then verifies the key and reads
records from that same commit. Named-profile commands also read the encrypted profile descriptor.
Single-record reads decode the requested record; listing and domain-tree resolution may read multiple records. Writes
reuse unchanged Git blobs and publish one commit only if the fetched branch tip
is still current. A concurrent branch update or stale record edit fails: fetch
the latest state and review before retrying. No merge, rebase, automatic conflict
retry, or overwrite of another writer is performed. Passphrase rotation and
restore still publish all records and metadata together in one commit.

A private bare Git repository is retained under `git_cache_dir` (default
`.sylva/git`), separately for each remote and branch. Git can reuse downloaded
objects on later commands; the initial fetch still transfers the current vault.
Cross-process locks protect the local repository. Files are never checked out,
and client-side hooks are disabled. The directory must have mode `0700`.
The cache contains ciphertext and can be removed while no commands are running;
the next command downloads it again. It is independent of the SQLite cache and
is used even if `client_cache_enabled=false`.

Remote access is still required for every command's initial fetch. A failed
fetch never silently falls back to cached data, and there is no offline write
queue. Record writes require a push as well as that fetch, so network latency
still contributes to operation time.

Existing `sylva-vault.json` (`sylva-git-v1`) vaults remain readable. The first
successful write converts the branch to the new layout in the same atomic
commit as that change, preserving existing ciphertext and the master passphrase.
Upgrade all Git clients before writing: older clients cannot read the new layout.
The old file remains accessible in Git history.

`passwd`, `backup` and `restore` use the same client encryption as self-hosted
storage. A master-passphrase change publishes all newly encrypted records and
metadata together; old sessions cannot write to the current vault generation.
**Git history still contains earlier ciphertext.** Deleting a record or changing
the master passphrase does not erase historical commits, clones, or backups.
Old master keys can still decrypt those historical versions. Git access can
also allow deletion or rollback of the repository; encryption alone does not
prove that the provider supplied the newest historical state.

To move an existing vault, make a new encrypted backup while configured for
its current backend, then lock the session. Select a fresh Git remote/branch
and run `sylva restore <backup-file>` using the backup's master passphrase.
Do **not** unlock/initialize a master passphrase on the target before restoring:
restore requires an uninitialized vault. The source remains untouched. Reverse
migration uses a backup and a fresh self-hosted database in the same way.
Selecting a backend never automatically migrates or dual-writes a vault.

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
