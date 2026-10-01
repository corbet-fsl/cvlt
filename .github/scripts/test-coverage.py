"""Exercise the actual source gate against LLVM-format acceptance/refusal cases."""
import copy
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('gate', Path(__file__).parent / 'check-coverage.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
ROOT = Path('/tmp/policy-coverage-fixture')
RAW = {'type': 'llvm.coverage.json.export', 'data': [{'files': [{'filename': str(ROOT / 'src/lib.rs'), 'branches': [[1, 1, 1, 2, 2, 1, 0, 0, 4]], 'summary': {'lines': {'count': 2, 'covered': 2}, 'branches': {'count': 2, 'covered': 2}}}]}]}
LCOV = f'SF:{ROOT}/src/lib.rs\nDA:1,3\nDA:2,1\nLF:2\nLH:2\nBRDA:1,0,0,2\nBRDA:1,0,1,1\nBRF:2\nBRH:2\nend_of_record\n'


class GateTests(unittest.TestCase):
    def test_complete_source_coverage(self):
        gate.check(LCOV, RAW, ROOT)

    def test_merged_generic_source_is_not_instantiation_coverage(self):
        raw = copy.deepcopy(RAW)
        file = raw['data'][0]['files'][0]
        file['branches'].append(file['branches'][0][:])
        file['summary']['lines'] = {'count': 3, 'covered': 2}
        file['summary']['branches'] = {'count': 4, 'covered': 3}
        report = LCOV.replace('LF:2', 'LF:3').replace('BRF:2', 'BRF:4').replace('BRH:2', 'BRH:3')
        gate.check(report, raw, ROOT)

    def test_no_instrumentable_branches(self):
        value = '\n'.join(row for row in LCOV.splitlines() if not row.startswith('BR'))
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'][0]['summary']['branches'] = {'count': 0, 'covered': 0}
        raw['data'][0]['files'][0]['branches'] = []
        gate.check(value, raw, ROOT)

    def test_refuses_missing_malformed_or_uncovered_records(self):
        bad = [
            '', LCOV.replace('DA:2,1', 'DA:2,0'),
            LCOV.replace('BRDA:1,0,1,1', 'BRDA:1,0,1,0'),
            LCOV.replace('BRDA:1,0,1,1\n', ''), LCOV.replace('DA:2,1', 'DA:2,0').replace('LH:2', 'LH:1'),
            LCOV.replace('BRDA:1,0,1,1', 'BRDA:1,0,1,0').replace('BRH:2', 'BRH:1'),
            LCOV.replace('BRDA:1,0,1,1', 'BRDA:1,0,1,-').replace('BRH:2', 'BRH:1'),
            LCOV.replace('DA:1,3', 'DA:1,-1'),
            LCOV.replace('BRDA:1,0,0,2', 'BRDA:1,0,0,-2'),
            LCOV.replace('DA:1,3', 'DA:1,3\nDA:1,3'),
            LCOV.replace('BRDA:1,0,0,2', 'BRDA:1,0,0,2\nBRDA:1,0,0,2'),
            LCOV.replace('LF:2', 'LF:3'), LCOV.replace('BRH:2', 'BRH:1'),
            LCOV.replace('LF:2', 'LF:2\nLF:2'),
            LCOV.replace('end_of_record\n', ''), LCOV + LCOV,
            LCOV.replace('/src/lib.rs', '/tests/lib.rs'),
            LCOV.replace('/src/lib.rs', '/../outside.rs'),
            LCOV.replace('DA:1,3', 'DA:0,3'), LCOV + 'DA:4,1\n',
            LCOV.replace('LF:2\n', ''), LCOV.replace('BRF:2\n', ''),
        ]
        for index, report in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(ValueError):
                gate.check(report, RAW, ROOT)

    def test_companion_inventory_cannot_be_missing_or_truncated(self):
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'].append({'filename': str(ROOT / 'src/missing.rs'), 'branches': [], 'summary': copy.deepcopy(RAW['data'][0]['files'][0]['summary'])})
        for report in ({}, {'type': 'other', 'data': []}, raw):
            with self.subTest(report=report), self.assertRaises(ValueError):
                gate.check(LCOV, report, ROOT)


    def test_only_documented_uncovered_line_can_be_excluded(self):
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'][0]['summary']['lines']['covered'] = 1
        value = LCOV.replace('DA:2,1', 'DA:2,0').replace('LH:2', 'LH:1')
        gate.check(value, raw, ROOT, {('src/lib.rs', 2): 'upstream bound'})
        for report, companion, exclusions in [
            (LCOV, RAW, {('src/lib.rs', 2): 'now reached'}),
            (LCOV, RAW, {('src/lib.rs', 3): 'missing'}),
            (LCOV, RAW, {('src/lib.rs', 1): 'branch location'}),
        ]:
            with self.subTest(exclusions=exclusions), self.assertRaises(ValueError):
                gate.check(report, companion, ROOT, exclusions)

    def test_duplicate_companion_inventory_is_rejected(self):
        raw = copy.deepcopy(RAW)
        raw['data'][0]['files'].append(copy.deepcopy(raw['data'][0]['files'][0]))
        with self.assertRaises(ValueError):
            gate.check(LCOV, raw, ROOT)


if __name__ == '__main__':
    unittest.main()
