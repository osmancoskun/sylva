# mTLS setup

Start on localhost HTTP first: [setup.md](setup.md). mTLS authenticates the **transport**. It does not replace the vault passphrase. The server still only stores ciphertext. With mTLS on, `sylvad` rejects connections that lack a client certificate signed by your CA. TLS is 1.3 only.

Use a private CA. Do not put these certificates on a public CA.

## Files

| File | Who loads it |
| --- | --- |
| CA cert | `sylvad` and `sylva` |
| Server cert + key | `sylvad` |
| Client cert + key | `sylva` |

Keep the CA private key offline after you issue certs. Mode `600` on keys.

The server certificate **SAN must match** the host in the client URL (`SYLVA_HOST` / `host` in config). `127.0.0.1` needs an IP SAN. `localhost` or a Docker name like `sylvad` needs a DNS SAN.

## Issue a local CA and a pair of certs

Requires OpenSSL. Adjust SANs if the client will not connect to `127.0.0.1` / `localhost`.

```bash
mkdir -p .sylva/certs
cd .sylva/certs

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
  -days 3650 -nodes \
  -subj "/CN=Sylva local CA" \
  -keyout ca.key -out ca.pem

cat > server.ext <<'EOF'
subjectAltName=DNS:localhost,DNS:sylvad,IP:127.0.0.1
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EOF

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -subj "/CN=sylvad" \
  -keyout server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile server.ext -out server.pem

cat > client.ext <<'EOF'
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -subj "/CN=sylva" \
  -keyout client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile client.ext -out client.pem

chmod 600 ca.key server.key client.key
rm -f server.csr client.csr server.ext client.ext
```

A second machine gets **its own** client cert from the same CA. Copy `ca.pem` plus that client pair; never reuse `server.key` on the CLI host unless it is the same machine.

## Enable once

Certificates default to `.sylva/certs/` as in the commands above. After they exist:

```bash
./bin/sylva enable mtls
# restart sylvad
./bin/sylvad
./bin/sylva ping
```

That writes `mtls=true` to `.sylva/config`. The client scheme becomes `https` automatically. Leftover cert files do **not** turn mTLS on by themselves (a previous test CA would surprise you). `sylva disable mtls` turns it off without deleting the files.

Optional path overrides in `.sylva/config` if you keep certs elsewhere:

```
ca_cert_path=.sylva/certs/ca.pem
server_cert_path=.sylva/certs/server.pem
server_key_path=.sylva/certs/server.key
client_cert_path=.sylva/certs/client.pem
client_key_path=.sylva/certs/client.key
```

Both binaries read the same files. Extra paths on one side are ignored.

Use the same `SYLVA_PORT` as plaintext (default `8443`). mTLS is a mode on that listener, not a second port. Stop the HTTP `sylvad` before starting the mTLS one; two processes cannot bind the same address. Do not multiplex plain HTTP and mTLS on one socket: the first bytes are either an HTTP request or a TLS handshake, and serving both would let anyone skip the client certificate.

## Check

```bash
./bin/sylvad
./bin/sylva ping
```

`ping` should report `mTLS: true`. A client without the cert, or a cert from another CA, must fail the handshake.

## Enabling mTLS later

`sylvad` does not speak HTTP and mTLS on the same listener, and it does not upgrade an existing HTTP session. You start without TLS, later `sylva enable mtls` and **restart** `sylvad`. From that moment every new TCP connection must finish TLS 1.3 with a client certificate **before** any vault request. The previous HTTP client is not “detected later”; it is a new connection that already fails.

| What the old client still does | What you see | What it means |
| --- | --- | --- |
| Client still on HTTP (`scheme=http`) | `sylvad is in HTTPS/mTLS mode but this client sent HTTP` | First bytes were `GET`, not a TLS ClientHello. The server never asked for a certificate. |
| `https` without your CA | `this client does not trust sylvad's certificate` | TLS started, but the private CA is not in the system trust store. |
| CA present, no client cert | `sylvad requires a client certificate (mTLS)` | Handshake reached TLS; the server sent `certificate_required` and closed. No JSON body. |
| Client cert from another CA | untrusted CA, or `sylvad rejected this client certificate` | CA files must match on both sides. |

`sylva` prints that reason on stderr (and points at this page). Run `sylva enable mtls` on the client machine too, then `sylva ping`. Vault data in SQLite does not change; only the transport does.

## Docker

Compose keeps its bridge network and requires mTLS for every connection,
including container-to-container traffic. Before starting it, issue the five
files above under `.sylva/certs/`: `ca.pem`, `server.pem`, `server.key`,
`client.pem`, and `client.key`. The server SAN must contain `DNS:sylvad` (as in
the example above) because that is the hostname used by the CLI container.
Missing bind-mounted certificate files prevent container startup.

The server receives only the CA certificate and its own server pair; the CLI
receives only the CA certificate and its own client pair. The CA private key
is never mounted. These files and `docker/mtls.conf` are mounted read-only;
bind mounts use a shared SELinux label for hosts that enforce SELinux.
Compose uses this dedicated config even if the host `.sylva/config` has mTLS
disabled. The server service does not import the CLI's master passphrase from
`.env` into its environment.

```bash
cp .env.example .env  # only when .env does not already exist
DOCKER_BUILDKIT=0 COMPOSE_BAKE=false docker compose up -d --build sylvad
docker compose run --rm sylva ping
```

The build variables match the Makefile's classic-builder setup for this
project's host-network module downloads.

The certificate directory and CLI environment file can be overridden with
`SYLVA_CERT_DIR` and `SYLVA_ENV_FILE`; their defaults remain `.sylva/certs` and
`.env`. `make docker-e2e` uses temporary replacements for an isolated automated
test, including certificate rejection, passphrase rotation, and backup/recovery.

The published host port defaults to `127.0.0.1`. To intentionally publish to a
LAN interface, set `SYLVA_PUBLISH_HOST` in `.env` to that interface's IP;
`0.0.0.0` publishes on all IPv4 interfaces. mTLS remains required in either
case. A host-native CLI must enable mTLS separately and use a URL whose hostname
or IP is included in the server SAN.

## Limits

mTLS is not Tailscale. It does not punch NAT or assign a mesh IP. It only proves the TCP peer holds a cert you issued. The vault key is still derived from the master passphrase. Mesh listen: [tailscale.md](tailscale.md).
