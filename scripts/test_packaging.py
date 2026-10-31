#!/usr/bin/env python3
"""Regression checks for build and RPM version normalization."""

import unittest

import package


class PackagingTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
