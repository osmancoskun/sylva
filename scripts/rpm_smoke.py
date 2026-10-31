#!/usr/bin/env python3
"""Install and exercise RPMs inside a disposable Fedora container only."""

import argparse
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if not Path('/.dockerenv').exists() and not Path('/run/.containerenv').exists():
        parser.error('RPM smoke installation must run in a disposable container')
    packages = sorted(str(path) for path in args.artifacts.glob('*.rpm') if not path.name.endswith('.src.rpm'))
    if len(packages) != 2:
        parser.error('expected exactly the CLI and daemon binary RPMs')
    run('dnf', '-y', '--setopt=install_weak_deps=False', 'install', *packages)
    assert run('/usr/bin/sylva', '-env', '/dev/null', 'version').strip() == 'sylva client v' + args.version
    assert run('/usr/bin/sylvad', '-version').strip() == 'sylvad v' + args.version
    account = pwd.getpwnam('sylva')
    assert account.pw_uid != 0
    config = Path('/etc/sylva/sylvad.conf')
    assert stat.S_IMODE(config.stat().st_mode) == 0o640
    assert config.stat().st_gid == account.pw_gid
    assert stat.S_IMODE(Path('/etc/sysconfig/sylvad').stat().st_mode) == 0o600
    state = Path('/var/lib/sylva')
    assert state.stat().st_uid == account.pw_uid
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    run('systemd-analyze', 'verify', '/usr/lib/systemd/system/sylvad.service')
    original = config.read_text() + '\n# Local setting retained across upgrades.\nlog_level=debug\n'
    config.write_text(original)
    run('rpm', '-U', '--replacepkgs', *packages)
    assert config.read_text() == original
    env = dict(os.environ, SYLVA_LOCAL_CONFIG=str(config))
    server = subprocess.Popen(['runuser', '-u', 'sylva', '--', '/usr/bin/sylvad', '-env', '/dev/null'],
                              env=env, cwd=state, umask=0o077, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                status = run('/usr/bin/sylva', '-env', '/dev/null', 'ping', cwd='/tmp')
                assert 'Status:    ok' in status or 'Status:   ok' in status
                assert args.version in status
                break
            except (subprocess.CalledProcessError, AssertionError):
                if server.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('packaged daemon did not become ready') from None
                time.sleep(0.05)
        assert (state / 'sylvad.db').is_file()
        assert (state / 'sylvad.db').stat().st_uid == account.pw_uid
        assert stat.S_IMODE((state / 'sylvad.db').stat().st_mode) == 0o600
    finally:
        if server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
        server.wait(timeout=10)
    print('PASS: RPM install, versions, service user, permissions, unit validation, config preservation and daemon startup')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(str(error) + '\n' + (error.stdout or '') + (error.stderr or '')) from error
