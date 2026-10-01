"""Gate LLVM line and branch evidence with exact, documented unreachable lines."""
import json, sys
from pathlib import Path

exclusions = json.loads(Path('.github/coverage-exclusions.json').read_text())
allowed = {}
for entry in exclusions:
    path, line = entry['file'], entry['line']
    assert entry['reason'] and entry['evidence'], 'exclusion requires a rationale and evidence'
    source = Path(path).read_text().splitlines()
    assert source[line - 1].strip() == entry['source'], 'exclusion source moved; review it again'
    if (sys.argv[2] if len(sys.argv) > 2 else "native") in entry.get("targets", ["native", "wasm"]):
        allowed[(path, line)] = entry
seen = set()
lines = branches = hit_lines = hit_branches = 0
misses = []
file = None
for record in Path(sys.argv[1]).read_text().splitlines():
    if record.startswith('SF:'):
        name = record[3:]
        file = 'src/' + name.split('/src/', 1)[1] if '/src/' in name else name
    elif record.startswith('DA:'):
        line, count = map(int, record[3:].split(',')[:2])
        key = (file, line)
        if key in allowed:
            seen.add(key)
            assert count == 0, 'formerly unreachable line was exercised; remove its exclusion'
            print('Unreachable:', file, line, allowed[key]['reason'])
            continue
        lines += 1
        hit_lines += count > 0
        if count == 0:
            misses.append(f'{file}:{line}')
    elif record.startswith('BRDA:'):
        parts = record[5:].split(',')
        branches += 1
        hit_branches += parts[3] != '-' and int(parts[3]) > 0
        if parts[3] == '-' or int(parts[3]) == 0:
            misses.append(f'{file}:{parts[0]} branch {parts[1]}:{parts[2]}')
assert seen == allowed.keys(), 'an exclusion is absent from LLVM evidence'
print(f'Reachable lines: {hit_lines}/{lines}; branches: {hit_branches}/{branches}')
assert lines > 0 and branches > 0 and not misses, '\n'.join(misses)
