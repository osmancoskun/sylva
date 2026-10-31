#!/usr/bin/env python3
"""Regression checks for release versioning, Git changelogs and source safety."""

import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import package


class PackagingTests(unittest.TestCase):
    def test_future_source_timestamps_are_clamped_without_changing_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            future = root / 'meson.build'
            past = root / 'VERSION'
            epoch = root / 'SOURCE_DATE_EPOCH'
            future.write_text("project('clock-skew-fixture')\n")
            past.write_text('0.1.1\n')
            epoch.write_text('1800007200\n')
            os.utime(future, (1800007200, 1800007200))
            os.utime(past, (1700000000, 1700000000))
            os.utime(epoch, (1800007200, 1800007200))
            with mock.patch('package.time.time', return_value=1800000000):
                package.normalize_source_timestamps(root)
            self.assertEqual(future.stat().st_mtime, 1800000000)
            self.assertEqual(past.stat().st_mtime, 1700000000)
            self.assertEqual(epoch.stat().st_mtime, 1800000000)
            self.assertEqual(epoch.read_text(), '1800007200\n')
            self.assertEqual(future.read_text(), "project('clock-skew-fixture')\n")

    def test_release_versions(self):
        self.assertEqual(package.normalize_version('v1.2.3'), '1.2.3')
        self.assertEqual(package.rpm_version('v1.2.3-rc.1'), '1.2.3~rc.1')
        self.assertEqual(package.rpm_version('v1.2.3-rc-1'), '1.2.3~rc.1')
        for invalid in ('../1.0', '1.2', '01.2.3', '1.2.3\n%prep', '1.2.3+metadata', '1.2.3;id'):
            with self.subTest(version=invalid), self.assertRaises(ValueError):
                package.normalize_version(invalid)

    def test_go_pseudo_versions_are_valid_rpm_dependency_versions(self):
        self.assertEqual(package.module_rpm_version('v0.0.0-20260214004413-d219187c3433'),
                         '0.0.0.20260214004413.d219187c3433')
        self.assertEqual(package.module_rpm_version('v2.0.0+incompatible'), '2.0.0.incompatible')

    def test_git_changelog_preserves_release_ranges_and_escapes_macros(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_AUTHOR_DATE='2026-01-03T12:00:00Z', GIT_COMMITTER_DATE='2026-01-03T12:00:00Z')

            def git(*args):
                return subprocess.run(['git', '-c', 'user.name=Test Maintainer', '-c',
                                       'user.email=test@example.test', *args], cwd=source,
                                      env=env, check=True, capture_output=True, text=True).stdout

            git('init', '-b', 'main')
            (source / 'VERSION').write_text('0.1.0-dev\n')
            git('add', 'VERSION')
            git('commit', '-m', 'feat: first release')
            git('tag', 'v1.0.0')
            git('commit', '--allow-empty', '-m', 'fix: escape %{lua:os.execute("false")} and 100% values')
            git('tag', '-a', 'v1.1.0', '-m', 'Second release')
            self.assertEqual(package.resolve_version(source), '1.1.0')
            git('tag', 'v1.1.1')  # Another release of the same source is valid.
            git('commit', '--allow-empty', '-m', 'feat: latest change')
            text = package.changelog(source, '1.2.0-rc.1')
            self.assertIn('* Sat Jan 03 2026 Test Maintainer <test@example.test> - 1.2.0~rc.1-1', text)
            self.assertIn(' - 1.1.0-1', text)
            self.assertIn(' - 1.0.0-1', text)
            self.assertIn('%%{lua:os.execute("false")} and 100%% values', text)
            self.assertEqual(text.count('- feat: latest change'), 1)
            self.assertEqual(text.count('- feat: first release'), 1)
            self.assertLess(text.index('latest change'), text.index('100%%'))
            self.assertLess(text.index('100%%'), text.index('first release'))

    def test_source_allowlist_excludes_local_secrets_and_build_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'src', Path(directory) / 'stage'
            source.mkdir()
            target.mkdir()
            for name in package.SOURCE_ROOT_FILES:
                (source / name).write_text('source fixture\n')
            for name in ('internal/config/config.go', 'packaging/systemd/sylvad.service.in',
                         'scripts/package.py', '.env', '.sylva/config', 'bin/sylva',
                         'internal/config/private.key', 'docs/private.pem', 'dist/old.rpm',
                         'scripts/__pycache__/package.pyc'):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            package.copy_sources(source, target)
            self.assertTrue((target / 'internal/config/config.go').is_file())
            self.assertTrue((target / 'packaging/systemd/sylvad.service.in').is_file())
            for name in ('.env', '.sylva', 'bin', 'dist', 'internal/config/private.key', 'docs/private.pem', 'scripts/__pycache__'):
                self.assertFalse((target / name).exists(), name)
            (source / 'internal/config/link.go').symlink_to(source / '.env')
            with self.assertRaises(ValueError):
                package.copy_sources(source, target)

    def test_source_archive_is_reproducible_and_keeps_versioned_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'sylva-1.2.3'
            stage.mkdir()
            path = stage / 'VERSION'
            path.write_text('1.2.3\n')
            first, second = root / 'first.tar.gz', root / 'second.tar.gz'
            package.source_archive(stage, first, 1760000000)
            os.utime(path, (1770000000, 1770000000))
            package.source_archive(stage, second, 1760000000)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                self.assertEqual(archive.extractfile('sylva-1.2.3/VERSION').read(), b'1.2.3\n')
                self.assertEqual(archive.getmember('sylva-1.2.3/VERSION').uid, 0)


if __name__ == '__main__':
    unittest.main()
