#!/usr/bin/env python3
"""Meson adapter for Go's dependency-aware builder."""

import argparse
import os
from pathlib import Path
import subprocess

from package import normalize_version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--package', choices=('./cmd/sylva', './cmd/sylvad'), required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--module-mode', choices=('readonly', 'vendor'), default='readonly')
    args = parser.parse_args()
    version = normalize_version(args.version)
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', CGO_ENABLED='0')
    if args.module_mode == 'vendor':
        env.update(GOPROXY='off', GOSUMDB='off')
    command = [args.go, 'build', '-trimpath', '-buildvcs=false',
               '-mod=' + args.module_mode, '-buildmode=pie',
               '-ldflags=-X github.com/osman/sylva/internal/config.BuildVersion=' + version,
               '-o', str(args.output.resolve()), args.package]
    subprocess.run(command, cwd=args.source, env=env, check=True)


if __name__ == '__main__':
    main()
