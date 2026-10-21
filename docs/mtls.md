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

The server certificate **SAN must match** `SYLVA_HOST` (the host in the client URL). `127.0.0.1` needs an IP SAN. `localhost` or a Docker name like `sylvad` needs a DNS SAN.

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
subjectAltName=DNS:localhost,IP:127.0.0.1
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

## `.env`

```bash
SYLVA_SCHEME=https
SYLVA_HOST=127.0.0.1
SYLVA_PORT=8443
SYLVA_MTLS_ENABLED=true
SYLVA_CA_CERT_PATH=.sylva/certs/ca.pem
SYLVA_SERVER_CERT_PATH=.sylva/certs/server.pem
SYLVA_SERVER_KEY_PATH=.sylva/certs/server.key
SYLVA_CLIENT_CERT_PATH=.sylva/certs/client.pem
SYLVA_CLIENT_KEY_PATH=.sylva/certs/client.key
```

Both binaries read the same file. Extra paths on one side are ignored.

Use the same `SYLVA_PORT` as plaintext (default `8443`). mTLS is a mode on that listener, not a second port. Stop the HTTP `sylvad` before starting the mTLS one; two processes cannot bind the same address. Do not multiplex plain HTTP and mTLS on one socket: the first bytes are either an HTTP request or a TLS handshake, and serving both would let anyone skip the client certificate.

`./bin/sylvad -mtls` only sets the enable flag. Certificate paths must still be in the environment; empty paths fail closed.

## Check

```bash
./bin/sylvad
./bin/sylva ping
```

`ping` should report `mTLS: true`. A client without the cert, or a cert from another CA, must fail the handshake.

## Enabling mTLS later

`sylvad` does not speak HTTP and mTLS on the same listener, and it does not upgrade an existing HTTP session. You start without TLS, later set `SYLVA_MTLS_ENABLED=true`, put cert paths in `.env`, set `SYLVA_SCHEME=https`, **restart** `sylvad`. From that moment every new TCP connection must finish TLS 1.3 with a client certificate **before** any vault request. The previous HTTP client is not “detected later”; it is a new connection that already fails.

| What the old client still does | What you see | What it means |
| --- | --- | --- |
| `SYLVA_SCHEME=http` (plaintext) | `sylvad is in HTTPS/mTLS mode but this client sent HTTP` | First bytes were `GET`, not a TLS ClientHello. The server never asked for a certificate. |
| `https` without your CA | `this client does not trust sylvad's certificate` | TLS started, but the private CA is not in the system trust store. |
| CA present, no client cert | `sylvad requires a client certificate (mTLS)` | Handshake reached TLS; the server sent `certificate_required` and closed. No JSON body. |
| Client cert from another CA | untrusted CA, or `sylvad rejected this client certificate` | CA files must match on both sides. |

`sylva` prints that reason on stderr (and points at this page). Fix the **client** `.env` the same way as the server, then `sylva ping`. Vault data in SQLite does not change; only the transport does.

## Docker

Compose talks to the daemon as hostname `sylvad`. Add `DNS:sylvad` to the server SAN (and rebuild the cert) or the client name check fails even with a valid client certificate.

## Limits

mTLS is not Tailscale. It does not punch NAT or assign a mesh IP. It only proves the TCP peer holds a cert you issued. The vault key is still derived from the master passphrase.
