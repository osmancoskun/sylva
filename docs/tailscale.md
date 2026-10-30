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

On this host, `http://100.x.x.x:8443` and the short name `sylva` often fail: MagicDNS may not resolve the short label, and packets to the tsnet IP go out `tailscale0` while the node is in-process userspace (hairpin timeout). Use loopback locally, and the FQDN from other tailnet devices:

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

Create a reusable auth key in the Tailscale admin console. Put it in `.env` as `SYLVA_TAILSCALE_AUTHKEY` or in `.sylva/tsnet.authkey` (mode `600`). If the key is **tagged**, set `tailscale_tags` in `.sylva/config` (comma-separated, `tag:sylvad`). Without matching tags, tsnet stays in `NeedsLogin`.

`NeedsLogin; running StartLoginInteractive` is normal for a few seconds even with an auth key. Wait for `joined tailnet` (control plane can take 30s+). Do not Ctrl-C at the first line — that cancels `tsnet.Up`. If the key is empty, tsnet prints a login URL about every five seconds.

After the first join, state in `tailscale_state_dir` is enough; keep that directory private (`0700`).

`./bin/sylvad` is enough after enable (or after the first join state exists).

## With mTLS

Restart into mTLS as usual. The server certificate SAN must match `SYLVA_HOST` as the **client** dials it (the MagicDNS name), not `127.0.0.1`.

## Limits

tsnet is not Funnel. Peers still need to be on the tailnet. Do not treat Tailscale identity as a substitute for the vault passphrase or, if you enabled it, client certificates.
