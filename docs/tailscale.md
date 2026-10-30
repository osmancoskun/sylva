# Tailscale (tsnet)

`sylvad` can join your tailnet as its own node. It does **not** use the host `tailscaled`. The CLI is a normal HTTP/HTTPS client: run Tailscale on the machine that runs `sylva`, and dial the MagicDNS name.

This is how you expose the daemon past localhost without opening a LAN port. mTLS is still optional on top: [mtls.md](mtls.md). First run stays HTTP on loopback: [setup.md](setup.md).

## What changes

When Tailscale is on, `sylvad` listens on the tailnet (port `SYLVA_PORT`) **and** on `127.0.0.1` so the CLI on the same machine works. It does not bind the LAN.

Only the embedded tsnet listener gets this remote-HTTP exception. Binding a
regular TCP listener to a host Tailscale IP still requires mTLS. Tailscale
encrypts and authenticates the network connection, while your tailnet access
policy must restrict the Sylva node/port to the intended users or devices.
Any allowed peer can use the whole-vault API, including deleting ciphertext;
the vault passphrase is not API authorization. Configure
[Tailscale access control](https://tailscale.com/docs/features/access-control)
before relying on a tailnet-only deployment. Enable mTLS on top when you also
need client-certificate authentication.

Use loopback for a client on the daemon host and the MagicDNS FQDN from other
tailnet devices. Short-name resolution depends on resolver configuration;
dialing the embedded node's tailnet IP from its own host can also encounter
hairpin routing problems:

```bash
# same machine as sylvad
./bin/sylva -server http://127.0.0.1:8443 ping

# another device on the tailnet
./bin/sylva -server http://sylva.tailXXXX.ts.net:8443 ping
```

`sylva ping` should report `Tailscale: true`. Remote CLI `.env`:

```bash
SYLVA_HOST=sylva.tailXXXX.ts.net
SYLVA_PORT=8443
```

## Enable once

Do not pass `-tailscale` or `SYLVA_TAILSCALE_ENABLED` on every start.

```bash
./bin/sylva enable tailscale
# restart sylvad
./bin/sylvad
```

That writes `tailscale=true` to `.sylva/config`. If `.sylva/tsnet/tailscaled.state` already exists from a previous join, Tailscale turns on even without that file. `sylva disable tailscale` writes `false` and wins over leftover state.

Node name and state dir default in `default.conf`. Override in `.sylva/config` if needed:

```
tailscale_node=sylva
tailscale_state_dir=.sylva/tsnet
```

For an interactive first join, leave the auth key empty and follow the login
URL printed by `sylvad`. For unattended setup of a persistent node, use a
one-off auth key from the Tailscale admin console. Put it in `.env` as
`SYLVA_TAILSCALE_AUTHKEY` or in `.sylva/tsnet.authkey` (mode `600`). If the key
is tagged, set matching `tailscale_tags` in `.sylva/config` (comma-separated,
`tag:sylvad`). Existing state is used for later starts. See
[Tailscale auth keys](https://tailscale.com/docs/features/access-control/auth-keys).

`NeedsLogin; running StartLoginInteractive` is normal for a few seconds even with an auth key. Wait for `joined tailnet` (control plane can take 30s+). Do not Ctrl-C at the first line — that cancels `tsnet.Up`. If the key is empty, tsnet prints a login URL about every five seconds.

After the first join, state in `tailscale_state_dir` is enough; keep that directory private (`0700`).

`./bin/sylvad` is enough after enable (or after the first join state exists).

## With mTLS

For a new certificate setup, first enable Tailscale and start the daemon:

```bash
./bin/sylva enable tailscale
./bin/sylvad
```

Complete login if prompted and wait for `joined tailnet`. `enable tailscale`
only writes configuration; it does not itself join the network. Keep this
daemon running while, in a second terminal on the same machine and working
directory, you generate the certificates:

```bash
./bin/sylva cert init --add-tailscale
./bin/sylva enable mtls
```

Then stop and restart `sylvad` so both features are active. `sylva ping` should
report `mTLS: true`, `Tailscale: true`, and the node's full `Tailnet DNS` name.
Remote clients use `https://<that-full-name>:8443` with the CA and their
client certificate/key, and need access through the tailnet policy.

`--add-tailscale` queries the running local `sylvad` on loopback using the
configured port and API prefix. Use the same `-env` file/config as the daemon
if you changed those settings. It reads the embedded node's current complete
MagicDNS name, including any assigned node suffix, and adds it to the default
localhost/Docker certificate identities. It does not inspect host `tailscaled`,
start another tsnet node, read cached identity files, or change feature flags.
An unavailable daemon, incomplete join, missing DNS identity, or older daemon
that lacks the identity field causes an error before certificates are written.
You can combine it with additional `--host` values.

This remains a new-bundle command: an existing `.sylva/certs` directory is
never replaced by `cert init`. For an existing deployment, make the original
CA signing key available locally and run:

```bash
./bin/sylva cert add-tailscale
```

This reissues only the server certificate and preserves the existing CA,
server key, client pair, addresses, and expiry. Restart `sylvad` afterwards
(recreate a bind-mounted Docker server container). Return `ca.key` to offline
storage. See [existing certificate updates](mtls.md#add-tailscale-to-existing-certificates)
for requirements. If the node name or tailnet changes later, rerun this command
to add the new name; previously included names are retained.

Restart into mTLS as usual. The server certificate SAN must include each name
or IP the client actually dials: the MagicDNS FQDN for remote clients and
`IP:127.0.0.1` if local clients use loopback. Use `https://` URLs when mTLS is
enabled. `SYLVA_HOST` is one such dialed name; a one-off `-server` URL must also
match a SAN.

## Limits

tsnet is not Funnel. Peers still need to be on the tailnet. Do not treat Tailscale identity as a substitute for the vault passphrase or, if you enabled it, client certificates.
