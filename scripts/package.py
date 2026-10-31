#!/usr/bin/env python3
"""Build versioned, vendored source archives and Fedora RPMs from this checkout."""

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?')
SOURCE_ROOT_FILES = {'go.mod', 'go.sum', 'VERSION', 'LICENSE', 'README.md', 'Makefile',
                     'meson.build', 'meson_options.txt', '.env.example'}
SOURCE_SUFFIXES = {'cmd': {'.go'}, 'internal': {'.go', '.conf'}, 'docs': {'.md'},
                   'scripts': {'.py', '.sh'}, 'packaging': {'.in', '.conf', '.env', '.sysusers'}}


def run(command, cwd=ROOT, **kwargs):
    return subprocess.run(command, cwd=cwd, check=True, **kwargs)


def git(source, *args):
    return run(['git', *args], cwd=source, capture_output=True, text=True).stdout.rstrip('\n')


def normalize_version(value):
    version = value.removeprefix('v')
    if not VERSION_RE.fullmatch(version):
        raise ValueError('version must be X.Y.Z or X.Y.Z-prerelease (optionally prefixed with v)')
    return version


def rpm_version(value):
    base, separator, prerelease = normalize_version(value).partition('-')
    return base + ('~' + prerelease.replace('-', '.') if separator else '')


def module_rpm_version(value):
    # Go pseudo-versions contain two hyphens; RPM interprets a hyphen as the
    # version/release separator and rejects a second one in dependency EVRs.
    return value.removeprefix('v').replace('-', '.').replace('+', '.')


def resolve_version(source, override=None):
    if override:
        return normalize_version(override)
    result = subprocess.run(['git', 'describe', '--exact-match', '--tags', '--match', 'v[0-9]*', 'HEAD'],
                            cwd=source, capture_output=True, text=True, check=False)
    if result.returncode == 0:
        return normalize_version(result.stdout.strip())
    return normalize_version((source / 'VERSION').read_text().strip())


def rpm_text(value):
    # Commit messages and author names are data, never RPM macros or scriptlets.
    return ' '.join(value.split()).replace('%', '%%')


def commits(source, revision):
    raw = git(source, 'log', '-z', '--format=%H%x00%at%x00%an%x00%ae%x00%s', revision)
    if not raw:
        return []
    fields = raw.removesuffix('\0').split('\0')
    if len(fields) % 5:
        raise ValueError('unexpected Git log record format')
    return [fields[i:i + 5] for i in range(0, len(fields), 5)]


def changelog(source, version):
    if not (source / '.git').exists():
        return (source / 'CHANGELOG.rpm.txt').read_text()
    if git(source, 'rev-parse', '--is-shallow-repository') == 'true':
        raise ValueError('RPM changelog requires full Git history; run git fetch --unshallow --tags')
    tags = {}
    for tag in git(source, 'tag', '--sort=version:refname', '--merged', 'HEAD', '--list', 'v[0-9]*').splitlines():
        try:
            tagged_version = normalize_version(tag)
        except ValueError:
            continue
        commit = git(source, 'rev-list', '-n', '1', tag)
        # Releasing the same source under another tag must remain possible.
        # Attribute a shared commit's changes to its earliest version only.
        tags.setdefault(commit, (tag, tagged_version))
    history = git(source, 'rev-list', '--first-parent', 'HEAD').splitlines()
    boundaries = [tags[commit] for commit in history[1:] if commit in tags]
    current, current_version = 'HEAD', version
    entries = []
    for previous, previous_version in [*boundaries, (None, None)]:
        rows = commits(source, previous + '..' + current if previous else current)
        if rows:
            head = commits(source, current)[0]
            date = datetime.fromtimestamp(int(head[1]), timezone.utc)
            stamp = ('Mon Tue Wed Thu Fri Sat Sun'.split()[date.weekday()] + ' ' +
                     'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[date.month - 1] +
                     f' {date.day:02d} {date.year}')
            entries.append(f'* {stamp} {rpm_text(head[2])} <{rpm_text(head[3])}> - {rpm_version(current_version)}-1')
            entries.extend('- ' + rpm_text(row[4]) + ' (' + row[0][:12] + ')' for row in rows)
            entries.append('')
        current, current_version = previous, previous_version
    return '\n'.join(entries).rstrip() + '\n'


def copy_sources(source, target):
    # Explicit source types prevent working vaults, .git, .env, keys, databases,
    # binaries and build directories from entering release or source RPM assets.
    for name in sorted(SOURCE_ROOT_FILES):
        src = source / name
        if src.is_symlink():
            raise ValueError('source file must not be a symlink: ' + name)
        shutil.copyfile(src, target / name)
    for directory, suffixes in SOURCE_SUFFIXES.items():
        for src in sorted((source / directory).rglob('*')):
            if src.is_file() and src.suffix in suffixes and '__pycache__' not in src.parts:
                if src.is_symlink():
                    raise ValueError('source file must not be a symlink: ' + str(src))
                dest = target / src.relative_to(source)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dest)
                dest.chmod(src.stat().st_mode & 0o777)


def bundled_notices(stage, go, env):
    parts = ['Bundled Go dependencies. Original notices follow their source paths.\n',
             (stage / 'vendor/modules.txt').read_text()]
    goroot = run([go, 'env', 'GOROOT'], cwd=stage, env=env, capture_output=True, text=True).stdout.strip()
    # Fedora moves the Go distribution license out of GOROOT into its license
    # directory. Keep the original text in both upstream and distro toolchains.
    go_license = next((path for path in (Path(goroot) / 'LICENSE', Path('/usr/share/licenses/golang/LICENSE')) if path.is_file()), None)
    if go_license is None:
        raise ValueError('cannot find the Go standard library license in GOROOT or the distro license directory')
    parts.extend(['\n===== Go standard library LICENSE =====\n', go_license.read_text()])
    for path in sorted((stage / 'vendor').rglob('*')):
        if path.is_file() and path.name.lower().startswith(('license', 'copying', 'notice', 'copyright')):
            parts.extend(['\n===== ' + str(path.relative_to(stage)) + ' =====\n', path.read_text(errors='replace')])
    (stage / 'THIRD_PARTY_LICENSES').write_text('\n'.join(parts))
    modules = run([go, 'list', '-mod=vendor', '-deps', '-f',
                   '{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}',
                   './cmd/sylva', './cmd/sylvad'], cwd=stage, env=env, capture_output=True, text=True).stdout
    provides = []
    for line in sorted(set(modules.splitlines())):
        fields = line.split()
        if len(fields) == 2:
            provides.append('Provides:       bundled(golang(' + fields[0] + ')) = ' + module_rpm_version(fields[1]))
    return '\n'.join(provides)


def source_archive(stage, archive, epoch):
    with archive.open('wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=epoch) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as tar:
                for path in [stage, *sorted(stage.rglob('*'))]:
                    info = tar.gettarinfo(str(path), arcname=str(path.relative_to(stage.parent)))
                    info.uid = info.gid = 0
                    info.uname = info.gname = 'root'
                    info.mtime = epoch
                    if info.isfile():
                        with path.open('rb') as stream:
                            tar.addfile(info, stream)
                    else:
                        tar.addfile(info)


def normalize_source_timestamps(source):
    # Git dates can be ahead of the builder's clock. Keep the source archive
    # reproducible, but prevent Meson/Ninja from rejecting its unpacked files.
    now = time.time()
    for path in [source, *source.rglob('*')]:
        info = path.lstat()
        if info.st_mtime > now:
            os.utime(path, (min(info.st_atime, now), now), follow_symlinks=False)


def prepare(source, output, version, go):
    output.mkdir(parents=True, exist_ok=True)
    text = changelog(source, version)
    if (source / '.git').exists():
        epoch = int(git(source, 'show', '-s', '--format=%ct', 'HEAD'))
    else:
        epoch = int((source / 'SOURCE_DATE_EPOCH').read_text())
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', CGO_ENABLED='0')
    with tempfile.TemporaryDirectory(prefix='sylva-source-') as directory:
        stage = Path(directory) / ('sylva-' + version)
        stage.mkdir()
        copy_sources(source, stage)
        (stage / 'VERSION').write_text(version + '\n')
        (stage / 'CHANGELOG.rpm.txt').write_text(text)
        (stage / 'SOURCE_DATE_EPOCH').write_text(str(epoch) + '\n')
        run([go, 'mod', 'vendor'], cwd=stage, env=env)
        provides = bundled_notices(stage, go, env)
        spec = (stage / 'packaging/rpm/sylva.spec.in').read_text()
        for token, value in {'UPSTREAM_VERSION': version, 'RPM_VERSION': rpm_version(version),
                             'BUNDLED_PROVIDES': provides, 'CHANGELOG': text}.items():
            spec = spec.replace('@' + token + '@', value)
        (output / 'sylva.spec').write_text(spec)
        (output / 'CHANGELOG.rpm.txt').write_text(text)
        shutil.copyfile(stage / 'packaging/systemd/sylva.sysusers', output / 'sylva.sysusers')
        source_archive(stage, output / ('sylva-' + version + '.tar.gz'), epoch)
    return output


def build_rpm(output, rpmbuild, flags):
    topdir = output / 'rpmbuild'
    for directory in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
        (topdir / directory).mkdir(parents=True, exist_ok=True)
    for path in [*output.glob('sylva-*.tar.gz'), output / 'sylva.sysusers']:
        shutil.copyfile(path, topdir / 'SOURCES' / path.name)
    shutil.copyfile(output / 'sylva.spec', topdir / 'SPECS/sylva.spec')
    run([rpmbuild, '-ba', '--define', '_topdir ' + str(topdir), *shlex.split(flags),
         str(topdir / 'SPECS/sylva.spec')])
    for directory in ('RPMS', 'SRPMS'):
        for path in (topdir / directory).rglob('*.rpm'):
            shutil.copyfile(path, output / path.name)


def checksums(output):
    paths = sorted(path for path in output.iterdir() if path.is_file() and path.name != 'SHA256SUMS')
    (output / 'SHA256SUMS').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n' for path in paths))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('version', 'changelog', 'sources', 'rpm', 'timestamps'))
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--version')
    parser.add_argument('--dist-dir', type=Path, default=ROOT / 'dist')
    parser.add_argument('--go', default='go')
    parser.add_argument('--rpmbuild', default='rpmbuild')
    parser.add_argument('--rpmbuild-flags', default='')
    args = parser.parse_args()
    source = args.source.resolve()
    try:
        if args.command == 'timestamps':
            normalize_source_timestamps(source)
            return
        version = resolve_version(source, args.version)
        if args.command == 'version':
            print(version)
        elif args.command == 'changelog':
            print(changelog(source, version), end='')
        else:
            output = prepare(source, args.dist_dir.resolve() / version, version, args.go)
            if args.command == 'rpm':
                build_rpm(output, args.rpmbuild, args.rpmbuild_flags)
            checksums(output)
            print('Package artifacts: ' + str(output))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
