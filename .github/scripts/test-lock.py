"""Reject wrong sources and declared/transitive pins using inert file fixtures."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECK = Path(__file__).with_name('check-lock.py')
URL = 'https://git.corbet.ch/corbet-foss/ckmg.git'
SHA = 'a' * 40


def validate(selector='branch = "v01"', source=None, duplicate=False,
             name='ckmg', url=URL, extra=''):
    source = source or f'git+{url}?branch=v01#{SHA}'
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'Cargo.toml').write_text(
            '[package]\nname="fixture"\nversion="0.0.0"\n[dependencies]\n'
            + name + ' = { git = "' + url + '", ' + selector + ' }\n')
        package = f'[[package]]\nname="{name}"\nversion="0.0.0"\nsource="{source}"\n'
        (root / 'Cargo.lock').write_text('version=4\n' + package + (package if duplicate else '') + extra)
        return subprocess.run([sys.executable, str(CHECK)], cwd=root,
                              capture_output=True, check=False).returncode


class LockTests(unittest.TestCase):
    def test_exact_original_revision(self):
        self.assertEqual(validate(), 0)

    def test_exact_shared_revision(self):
        url = 'https://git.corbet.ch/corbet-foss/csgn'
        self.assertEqual(validate(name='csgn', url=url, selector='branch="main"',
                                  source=f'git+{url}?branch=main#{SHA}'), 0)

    def test_direct_pin_or_other_branch(self):
        for selector in ['rev="' + SHA + '"', 'tag="v1"', 'branch="preview"',
                         'branch="main"', 'branch="v01", rev="' + SHA + '"',
                         'branch="v01", tag="v1"', 'branch="v01", path="."']:
            with self.subTest(selector=selector):
                self.assertNotEqual(validate(selector=selector), 0)

    def test_transitive_revision_tag_and_other_branch(self):
        for selector in ['rev=' + SHA, 'tag=v1', 'branch=preview', 'branch=main',
                         'branch=v01&rev=' + SHA, 'branch=v01&tag=v1',
                         'branch=v01&branch=v01', 'branch=v01&other=value']:
            with self.subTest(selector=selector):
                self.assertNotEqual(validate(source=f'git+{URL}?{selector}#{SHA}'), 0)

    def test_duplicate_first_party_package(self):
        self.assertNotEqual(validate(duplicate=True), 0)
        for source in ['', 'source="registry+https://github.com/rust-lang/crates.io-index"\n']:
            extra = f'[[package]]\nname="ckmg"\nversion="1.0.0"\n{source}'
            self.assertNotEqual(validate(extra=extra), 0)

    def test_wrong_owner_url_or_package(self):
        for url in [URL.removesuffix('.git'), URL.replace('https:', 'http:'),
                    URL.replace('git.corbet.ch', 'github.com'),
                    URL.replace('git.corbet.ch', 'foreign.example'),
                    'https://foreign.example/other/ckmg']:
            self.assertNotEqual(validate(url=url), 0)
        self.assertNotEqual(validate(name='csgn'), 0)
        self.assertNotEqual(validate(name='unknown', url='https://git.corbet.ch/corbet-foss/unknown'), 0)

    def test_short_resolved_revision(self):
        self.assertNotEqual(validate(source=f'git+{URL}?branch=v01#short'), 0)

    def test_shared_cannot_select_original_branch_or_suffix(self):
        for url in ['https://git.corbet.ch/corbet-foss/csgn',
                    'https://git.corbet.ch/corbet-foss/csgn.git']:
            self.assertNotEqual(validate(name='csgn', url=url), 0)

    def test_original_sibling_and_exact_shared_engine_source(self):
        url = 'https://git.corbet.ch/corbet-foss/cprz.git'
        self.assertEqual(validate(name='cprz-pad', url=url), 0)
        url = 'https://git.corbet.ch/corbet-libre/cwlt'
        extra = f'[[package]]\nname="cwlt-engine"\nversion="0.0.0"\nsource="git+{url}?branch=main#{SHA}"\n'
        self.assertEqual(validate(name='cwlt', url=url, selector='branch="main"',
                                  source=f'git+{url}?branch=main#{SHA}', extra=extra), 0)
        self.assertNotEqual(validate(name='cwlt', url=url, selector='branch="main"',
                                     source=f'git+{url}?branch=main#{SHA}',
                                     extra=extra.replace(SHA, 'b' * 40)), 0)
        self.assertNotEqual(validate(name='cwlt-engine'), 0)


if __name__ == '__main__':
    unittest.main()
