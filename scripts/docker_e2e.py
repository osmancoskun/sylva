#!/usr/bin/env python3
"""Disposable Docker integration test; requires Python 3, OpenSSL and Compose v2+."""

import copy
import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parent.parent
OLD_PASS = "synthetic-e2e-old-passphrase"
NEW_PASS = "synthetic-e2e-new-passphrase"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, env, check=True, timeout=120):
    result = subprocess.run(args, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({args[0]}):\n{result.stdout}")
    return result


def certificates(directory, env):
    def openssl(*args):
        run(["openssl", *map(str, args)], env)

    ca, ca_key = directory / "ca.pem", directory / "ca.key"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "2", "-subj", "/CN=Sylva disposable test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", ca_key, "-out", ca)
    for name, usage in [("server", "serverAuth"), ("client", "clientAuth")]:
        ext = directory / f"{name}.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature\n"
                       f"extendedKeyUsage={usage}\n" +
                       ("subjectAltName=DNS:sylvad,DNS:recovery,IP:127.0.0.1\n"
                        if name == "server" else ""))
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-subj", f"/CN={name}", "-keyout", directory / f"{name}.key",
                "-out", directory / f"{name}.csr")
        openssl("x509", "-req", "-in", directory / f"{name}.csr", "-CA", ca,
                "-CAkey", ca_key, "-CAcreateserial", "-days", "2", "-extfile", ext,
                "-out", directory / f"{name}.pem")
    # This client is not signed by the trusted CA.
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "2", "-subj", "/CN=untrusted-test-client",
            "-addext", "extendedKeyUsage=clientAuth", "-keyout", directory / "rogue.key",
            "-out", directory / "rogue.pem")
    for path in directory.iterdir():
        path.chmod(0o600)


def rotate_passphrase(command, env):
    """Exercise the real hidden terminal prompts, never a passphrase flag."""
    master, slave = pty.openpty()
    proc = None
    transcript = bytearray()
    prompts = [b"New master passphrase: ", b"Confirm new master passphrase: "]

    def failure_detail():
        output = transcript.decode(errors="replace")
        for secret in (OLD_PASS, NEW_PASS):
            output = output.replace(secret, "[REDACTED]")
        return (f"exit={proc.poll() if proc else None}, prompts={step}/{len(prompts)}\n"
                f"{output[-4096:]}")

    step = 0
    try:
        proc = subprocess.Popen(command, env=env, stdin=slave, stdout=slave, stderr=slave,
                                start_new_session=True)
        os.close(slave)
        slave = None
        deadline = time.monotonic() + 90
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError("Passphrase terminal prompts timed out: " + failure_detail())
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    data = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                transcript.extend(data)
                if step < len(prompts) and prompts[step] in transcript:
                    # ReadPassword has disabled echo before the prompt is serviced.
                    # Wait for the remote terminal to finish entering that mode.
                    time.sleep(0.1)
                    os.write(master, (NEW_PASS + "\n").encode())
                    step += 1
            elif proc.poll() is not None:
                break
        require(proc.wait(timeout=10) == 0 and step == 2 and
                b"Master passphrase changed" in transcript,
                "Interactive passphrase rotation failed: " + failure_detail())
        require(NEW_PASS.encode() not in transcript, "Passphrase was echoed by the terminal")
    finally:
        if slave is not None:
            os.close(slave)
        os.close(master)
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


def exercise(compose, env, directory):
    def dc(*args, check=True):
        return run([*compose, *args], env, check=check)

    def cli(*args, target="sylvad", password=OLD_PASS, check=True, extra=()):
        return dc("run", "--rm", "--no-deps", "-T", "-e", f"SYLVA_HOST={target}",
                  "-e", f"SYLVA_MASTER_PASSPHRASE={password}", *extra, "sylva", *args,
                  check=check)

    def expect_failure(*args, reason, **kwargs):
        result = cli(*args, check=False, **kwargs)
        require(result.returncode != 0 and reason in result.stdout,
                f"Expected failure containing {reason!r}: {result.stdout}")

    def get_value(identifier, kind, expected, **kwargs):
        clip = directory / "artifacts" / "clipboard"
        clip.unlink(missing_ok=True)
        cli("get", identifier, kind, extra=("-e", "SYLVA_CLIPBOARD_BACKEND=file",
            "-e", "SYLVA_CLIPBOARD_FILE=/artifacts/clipboard"), **kwargs)
        require(clip.read_text() == expected, f"Decrypted value mismatch: {identifier}")
        clip.unlink()

    dc("up", "-d", "--no-build", "sylvad", "recovery")
    for target in ["sylvad", "recovery"]:
        for _ in range(30):
            ping = cli("ping", target=target, check=False)
            if ping.returncode == 0:
                require("mTLS: true" in " ".join(ping.stdout.split()), "mTLS was not enabled")
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"{target} did not become ready: {ping.stdout}")
    print("PASS: bridge-network mTLS connectivity", flush=True)

    cli("init")
    cli("set", "smoke-token", "synthetic-token", "password")
    cli("update", "smoke-token", "synthetic-updated", "password")
    cli("set", "company.example", "synthetic-domain", "domain")
    cli("set", "mail.company.example", "--inherit")
    cli("set", "SMOKE_ENV", "synthetic-env", "env")
    cli("set", "smoke-ssh", "synthetic-ssh", "ssh")
    entries = [("smoke-token", "password", "synthetic-updated"),
               ("mail.company.example", "domain", "synthetic-domain"),
               ("SMOKE_ENV", "env", "synthetic-env"),
               ("smoke-ssh", "ssh", "synthetic-ssh")]
    for identifier, kind, value in entries:
        get_value(identifier, kind, value)
    print("PASS: CLI CRUD and decrypted values for all secret types", flush=True)

    port = dc("port", "sylvad", "8443").stdout.strip()
    url = f"https://{port}/api/v1"
    certs = directory / "certs"

    def opener(identity=None):
        ctx = ssl.create_default_context(cafile=str(certs / "ca.pem"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        if identity:
            ctx.load_cert_chain(certs / f"{identity}.pem", certs / f"{identity}.key")
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                          urllib.request.HTTPSHandler(context=ctx))

    trusted = opener("client")
    with trusted.open(url + "/records", timeout=5) as response:
        before = json.load(response)["records"]
    record_id = before[0]["id"]
    for identity in [None, "rogue"]:
        for method, path in [("GET", "/records"), ("DELETE", "/records/" + record_id)]:
            try:
                with opener(identity).open(urllib.request.Request(url + path, method=method),
                                           timeout=5) as response:
                    response.read()
            except urllib.error.HTTPError as exc:
                raise RuntimeError("Unauthenticated client reached HTTP instead of failing TLS") from exc
            except urllib.error.URLError as exc:
                require(isinstance(exc.reason, (ssl.SSLError, ConnectionError)),
                        f"Expected a TLS rejection, got: {exc.reason}")
            except (ssl.SSLError, ConnectionError):
                pass
            else:
                raise RuntimeError(f"Unauthenticated {method} was accepted ({identity})")
    with trusted.open(url + "/records", timeout=5) as response:
        require(json.load(response)["records"] == before,
                "Unauthenticated requests changed the vault")
    print("PASS: missing/untrusted client certificates rejected before HTTP", flush=True)

    cli("backup", "/artifacts/vault.backup")
    backup = directory / "artifacts" / "vault.backup"
    original = backup.read_bytes()
    require(backup.stat().st_mode & 0o777 == 0o600, "Backup permissions are not 0600")
    require(all(value.encode() not in original for _, _, value in entries),
            "Backup contains a plaintext secret")
    expect_failure("backup", "/artifacts/vault.backup", reason="without overwriting")
    require(backup.read_bytes() == original, "Existing backup was overwritten")
    expect_failure("restore", "/artifacts/vault.backup", reason="uninitialized target vault")

    rotate_passphrase([*compose, "run", "--rm", "--no-deps", "--no-tty=false",
                       "sylva", "passwd"], env)
    expect_failure("get", "smoke-token", "password", reason="incorrect master passphrase")
    for identifier, kind, value in entries:
        get_value(identifier, kind, value, password=NEW_PASS)
    print("PASS: terminal passphrase rotation; old key rejected and values preserved", flush=True)

    with trusted.open(url + "/records", timeout=5) as response:
        rotated = json.load(response)["records"]
    expect_failure("restore", "/artifacts/vault.backup", target="recovery",
                   password="incorrect-test-passphrase", reason="incorrect master passphrase")
    corrupt = json.loads(original)
    # Retain valid JSON but invalidate the authenticated archive.
    corrupt["salt"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    (directory / "artifacts" / "corrupt.backup").write_text(json.dumps(corrupt))
    expect_failure("restore", "/artifacts/corrupt.backup", target="recovery",
                   reason="incorrect master passphrase")
    cli("restore", "/artifacts/vault.backup", target="recovery")
    for identifier, kind, value in entries:
        get_value(identifier, kind, value, target="recovery")
    require("company.example" in cli("list", target="recovery").stdout,
            "Restored vault listing is incomplete")
    expect_failure("get", "smoke-token", "password", target="recovery",
                   password=NEW_PASS, reason="incorrect master passphrase")
    with trusted.open(url + "/records", timeout=5) as response:
        require(json.load(response)["records"] == rotated, "Recovery changed the source vault")
    cli("delete", "smoke-token", "password", "--yes", target="recovery")
    require("smoke-token" not in cli("list", target="recovery").stdout,
            "Authorized deletion did not remove the restored secret")
    print("PASS: encrypted backup, invalid archives rejected, restore into a fresh vault", flush=True)


def main():
    def interrupted(signum, frame):
        raise InterruptedError("Docker end-to-end test interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    # Preserve Docker connection settings, but never inherit vault settings or a
    # developer's .env/config/certificates. Compose receives a synthetic env file.
    env = {key: value for key, value in os.environ.items() if not key.startswith("SYLVA_")}
    env.setdefault("DOCKER_BUILDKIT", "0")
    env.setdefault("COMPOSE_BAKE", "false")
    with tempfile.TemporaryDirectory(prefix="sylva-e2e-") as scratch:
        directory = Path(scratch)
        for name in ["certs", "artifacts"]:
            (directory / name).mkdir(mode=0o700)
        certificates(directory / "certs", env)
        env_file = directory / "test.env"
        env_file.write_text(f"SYLVA_MASTER_PASSPHRASE={OLD_PASS}\nSYLVA_PORT=8443\n")
        env_file.chmod(0o600)
        env.update(SYLVA_CERT_DIR=str(directory / "certs"), SYLVA_ENV_FILE=str(env_file))
        project = "sylva-e2e-" + uuid.uuid4().hex[:12]
        base = ["docker", "compose", "--env-file", str(env_file), "--project-name", project]
        config = json.loads(run([*base, "-f", str(ROOT / "docker-compose.yml"),
                                 "config", "--format", "json"], env).stdout)
        config["services"].pop("test", None)
        server = config["services"]["sylvad"]
        server["ports"] = [{"target": 8443, "published": "0", "host_ip": "127.0.0.1"}]
        recovery = copy.deepcopy(server)
        recovery.pop("ports")
        recovery.pop("build")
        server["image"] = recovery["image"] = project + "-sylvad"
        recovery["volumes"][0]["source"] = "recovery-data"
        config["volumes"]["recovery-data"] = {}
        config["services"]["recovery"] = recovery
        client = config["services"]["sylva"]
        security = json.loads(run(["docker", "info", "--format", "{{json .SecurityOptions}}"],
                                  env).stdout)
        # Rootless Docker maps container root to the invoking host user. For
        # rootful Docker, write 0600 artifacts using the host UID instead.
        if not any("rootless" in option for option in security):
            client["user"] = f"{os.getuid()}:{os.getgid()}"
        client["environment"].update(SYLVA_AGENT_ENABLED="false", SYLVA_KEYRING_ENABLED="false",
                                      SYLVA_CLIENT_CACHE_ENABLED="false")
        client["volumes"].append({"type": "bind", "source": str(directory / "artifacts"),
                                  "target": "/artifacts", "bind": {"selinux": "z"}})
        manifest = directory / "compose.json"
        manifest.write_text(json.dumps(config))
        manifest.chmod(0o600)
        compose = [*base, "-f", str(manifest)]
        try:
            print("Building disposable Docker mTLS/recovery test", flush=True)
            subprocess.run([*compose, "build", "sylvad", "sylva"], env=env,
                           check=True, timeout=1200)
            exercise(compose, env, directory)
        except BaseException:
            # Only server logs: do not print generated configuration, keys or backups.
            logs = run([*compose, "logs", "--no-color", "--tail", "60", "sylvad", "recovery"],
                       env, check=False)
            print(logs.stdout, flush=True)
            raise
        finally:
            cleanup = run([*compose, "down", "--volumes", "--rmi", "all", "--remove-orphans"],
                          env, check=False)
            require(cleanup.returncode == 0, "Disposable Compose cleanup failed:\n" + cleanup.stdout)
            print("Removed disposable containers, volumes, images and bridge network", flush=True)


if __name__ == "__main__":
    main()
