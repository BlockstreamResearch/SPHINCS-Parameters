#!/usr/bin/env python3
"""Runs the tests of tests/test_*.py, all or the areas named; pytest runs them too.

  python3 tests/run.py [model] [generated] [site] [sage]

Without node or sage, their tests are skipped. Without the generated files
(make generate), their tests are skipped too, or fail with GENERATED_REQUIRED=1
as in CI.
"""
import importlib
import sys

AREAS = ['model', 'generated', 'site', 'sage']


def main(areas):
    total = failed = 0
    for area in areas:
        tests = importlib.import_module('test_' + area)
        for name, fn in sorted(vars(tests).items()):
            if not (name.startswith('test_') and callable(fn)):
                continue
            total += 1
            try:
                fn()
                print(f'PASS  {name}')
            except AssertionError as e:
                failed += 1
                print(f'FAIL  {name}: {e}')
    print(f'\n{total - failed}/{total} passed')
    return 1 if failed else 0


if __name__ == '__main__':
    unknown = [a for a in sys.argv[1:] if a not in AREAS]
    if unknown:
        sys.exit('unknown area: %s (areas: %s)' % (', '.join(unknown), ', '.join(AREAS)))
    sys.exit(main(sys.argv[1:] or AREAS))
