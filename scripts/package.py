#!/usr/bin/env python3
"""Resolve and validate build and RPM versions."""

import argparse
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?')


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('version',))
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--version')
    args = parser.parse_args()
    try:
        print(resolve_version(args.source.resolve(), args.version))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
