"""Require the approved canonical owner graph before repository code is built."""
from pathlib import Path
import re
import tomllib
from urllib.parse import parse_qs, urlsplit

CANONICAL = re.compile(r'^https://git\.corbet\.ch/(corbet-(?:libre|fsl))/([a-z][a-z0-9-]*)(\.git)?$')
SHA = re.compile(r'^[0-9a-f]{40}$')
# The v01 original-owner exceptions ended with the 2026-11 org move: every
# first-party pin is branch = main at its new owner. The `.git` suffix is
# historical spelling and carries no meaning; both forms are canonical.
ORIGINAL = {
    'corbet-libre': frozenset(),
    'corbet-fsl': frozenset(),
}
SHARED = {
    'corbet-libre': frozenset({'cbcn', 'cblv', 'cchr', 'cdht', 'cfbk', 'cgrd',
                               'ckmg', 'ckyh', 'cpky', 'cpns', 'cprz', 'cpsd',
                               'crbk', 'crlt', 'csgn', 'cshm', 'cvch', 'cvln',
                               'cwlt', 'cwst', 'czkp'}),
    'corbet-fsl': frozenset({'cmsh'}),
}
SIBLINGS = {'cprz-blob': 'cprz', 'cprz-pad': 'cprz', 'cwlt-engine': 'cwlt'}
PACKAGES = frozenset().union(*ORIGINAL.values(), *SHARED.values(), SIBLINGS)


def first_party(source):
    return any(owner in source for owner in ('corbet-libre/', 'corbet-fsl/', 'cmtymeet/'))


def owner_branch(repo, package):
    matched = CANONICAL.fullmatch(repo)
    if not matched:
        raise ValueError('First-party source must use its canonical HTTPS owner URL')
    group, slug, suffix = matched.groups()
    if not isinstance(package, str) or SIBLINGS.get(package, package) != slug:
        raise ValueError(f'Package {package} differs from its repository owner')
    if slug not in ORIGINAL[group] and slug not in SHARED[group]:
        raise ValueError(f'Unknown first-party owner: {group}/{slug}')
    return 'main'


def check_manifest(value, alias=None):
    if isinstance(value, dict):
        package = value.get('package', alias)
        if first_party(value.get('git', '')) or (
            isinstance(package, str) and package in PACKAGES
            and {'git', 'path'}.intersection(value)
        ):
            branch = owner_branch(value.get('git', ''), package)
            if value.get('branch') != branch or {'rev', 'tag', 'path'}.intersection(value):
                raise ValueError(f'First-party dependency must declare its approved branch {branch}')
        for key, item in value.items():
            check_manifest(item, key)
    elif isinstance(value, list):
        for item in value:
            check_manifest(item)


def check_lock(packages):
    names = {p['name'] for p in packages
             if p['name'] in PACKAGES or first_party(p.get('source', ''))}
    owner_sources = {}
    for name in names:
        entries = [p for p in packages if p['name'] == name]
        if len(entries) != 1:
            raise ValueError(f'Duplicate first-party crate: {name}')
        raw = entries[0].get('source', '')
        if not raw.startswith('git+'):
            raise ValueError(f'Invalid first-party source for {name}')
        source = urlsplit(raw.removeprefix('git+'))
        repo = source._replace(query='', fragment='').geturl()
        branch = owner_branch(repo, name)
        query = parse_qs(source.query, keep_blank_values=True)
        if not SHA.fullmatch(source.fragment):
            raise ValueError(f'Missing resolved revision for {name}')
        if query != {'branch': [branch]} or source.query != 'branch=' + branch:
            raise ValueError(f'Invalid first-party source selector for {name}')
        previous = owner_sources.setdefault(repo, raw)
        if previous != raw:
            raise ValueError(f'Mixed first-party owner revisions: {repo}')


if __name__ == '__main__':
    for path in Path('.').rglob('Cargo.toml'):
        if {'target', '.git', 'node_modules'}.intersection(path.parts):
            continue
        check_manifest(tomllib.loads(path.read_text()))
    check_lock(tomllib.loads(Path('Cargo.lock').read_text())['package'])
    print('First-party declarations follow approved canonical owners with one locked identity')
