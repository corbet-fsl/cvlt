"""Reject declared and transitive pins before any repository code is built."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECK = Path(__file__).with_name('check-lock.py')
URL = 'https://github.com/corbet-foss/ckmg'
SHA = 'a' * 40


def validate(selector='branch = "main"', source=None, duplicate=False):
    source = source or f'git+{URL}?branch=main#{SHA}'
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'Cargo.toml').write_text(
            '[package]\nname="fixture"\nversion="0.0.0"\n[dependencies]\n'
            + 'ckmg = { git = "' + URL + '", ' + selector + ' }\n')
        package = f'[[package]]\nname="ckmg"\nversion="0.0.0"\nsource="{source}"\n'
        (root / 'Cargo.lock').write_text('version=4\n' + package + (package if duplicate else ''))
        return subprocess.run([sys.executable, str(CHECK)], cwd=root,
                              capture_output=True, check=False).returncode


class LockTests(unittest.TestCase):
    def test_one_main_revision(self):
        self.assertEqual(validate(), 0)

    def test_direct_pin_or_other_branch(self):
        for selector in ['rev="' + SHA + '"', 'tag="v1"', 'branch="preview"',
                         'branch="main", rev="' + SHA + '"']:
            with self.subTest(selector=selector):
                self.assertNotEqual(validate(selector=selector), 0)

    def test_transitive_revision_tag_and_other_branch(self):
        for selector in ['rev=' + SHA, 'tag=v1', 'branch=preview', 'branch=main&rev=' + SHA]:
            with self.subTest(selector=selector):
                self.assertNotEqual(validate(source=f'git+{URL}?{selector}#{SHA}'), 0)

    def test_duplicate_first_party_package(self):
        self.assertNotEqual(validate(duplicate=True), 0)


if __name__ == '__main__':
    unittest.main()
