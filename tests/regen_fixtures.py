#!/usr/bin/env python3
"""Compare tests/fixtures.json with the values the code produces now.

Model values come from tests/model.py. Row and pool counts come from the
generated files (utils/*.csv and site/data.json) and are skipped without them.

    python3 tests/regen_fixtures.py           # list the values that differ
    python3 tests/regen_fixtures.py --write   # write them into tests/fixtures.json
"""
import copy
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, 'fixtures.json')
sys.path.insert(0, HERE)

import model as M  # noqa: E402

METRICS = ('size', 'kg', 'sg', 'sv', 'sv_worst')
BASELINE = (63, 7, 14, 12, 16)
MISSING = '(missing)'


def ints(text):
    return [int(x) for x in text.split(',')]


def update(entry, values, keys):
    for k in keys:
        entry[k] = values[k]


def replace(entry, values):
    """Make entry equal to values while keeping its key order."""
    for k in [k for k in entry if k not in values]:
        del entry[k]
    entry.update(values)


def model_values(fx):
    M.set_convention('cached')  # regardless of HASH_CONVENTION
    fx['wots_len'] = {w: M.wots_len(int(w)) for w in fx['wots_len']}
    fx['wots_len_wc'] = {w: M.wots_len(int(w), wc=True) for w in fx['wots_len_wc']}
    fx['swn'] = {w: M.SWN[int(w)] for w in fx['swn']}
    update(fx['baseline'], M.spx_metrics(*BASELINE), METRICS)
    for key, entry in fx['stateless'].items():
        update(entry, M.spx_metrics(*ints(key)), METRICS)
    for key, entry in fx['stateful']['uxmss'].items():
        ots, w = key.split(',')
        replace(entry, M.uxmss_metrics(ots, int(w)))
    for key, entry in fx['stateful']['xmssmt'].items():
        ots, params = key.split(',', 1)
        replace(entry, M.xmssmt_metrics(ots, *ints(params)))
    for key, entry in fx['variants'].items():
        scheme, params = key.split('|')
        update(entry, M.scheme_metrics(scheme, *ints(params)), METRICS)

    M.set_convention('uncached')
    try:
        for key, entry in fx['uncached_spot'].items():
            kind, _, params = key.partition('|')
            if kind == 'baseline':
                values = M.spx_metrics(*BASELINE)
            elif kind == 'variant':
                scheme, params = params.split('|')
                values = M.scheme_metrics(scheme, *ints(params))
            else:
                ots, w = params.split(',')
                values = M.uxmss_metrics(ots, int(w))
            update(entry, values, list(entry))
    finally:
        M.set_convention('cached')


def pipeline_counts(fx):
    """Read the row and pool counts from the generated files. False if they are missing."""
    csvs = {name: os.path.join(ROOT, 'utils', name) for name in fx['csv_rows']}
    data_json = os.path.join(ROOT, 'site', 'data.json')
    if not all(os.path.exists(p) for p in [*csvs.values(), data_json]):
        return False
    for name, path in csvs.items():
        with open(path, newline='') as fh:
            fx['csv_rows'][name] = sum(1 for _ in csv.DictReader(fh))
    with open(data_json) as fh:
        data = json.load(fh)
    spx = data['pools']['SPX']
    w = spx['fields'].index('w')
    fx['site_pool_count'] = len(spx['rows'])
    for scheme in fx['variant_pool_counts']:
        if scheme in data['pools']:  # tests/synth_generated.py does not export W+C_P+FP
            fx['variant_pool_counts'][scheme] = data['pools'][scheme]['count']
    fx['optional_pool_counts'] = {str(x): sum(1 for r in spx['rows'] if r[w] == x)
                                  for x in data['meta']['w_optional']}
    return True


def differences(old, new, path=''):
    if isinstance(old, dict) and isinstance(new, dict):
        for k in list(old) + [k for k in new if k not in old]:
            yield from differences(old.get(k, MISSING), new.get(k, MISSING),
                                   f'{path}/{k}' if path else k)
    elif old != new:
        yield path, old, new


def main():
    with open(FIXTURES) as fh:
        old = json.load(fh)
    new = copy.deepcopy(old)
    model_values(new)
    counted = pipeline_counts(new)

    diff = list(differences(old, new))
    for path, a, b in diff:
        print(f'{path}: {a} -> {b}')
    if not counted:
        print('Row and pool counts not checked: run `make check-local` or `make generate` first.')
    if not diff:
        print('tests/fixtures.json matches the code.')
    elif '--write' in sys.argv[1:]:
        with open(FIXTURES, 'w') as fh:
            fh.write(json.dumps(new, indent=1) + '\n')
        print(f'{len(diff)} values updated in tests/fixtures.json.')
    else:
        print(f'{len(diff)} values differ. If the change is intended: make fixtures WRITE=1')


if __name__ == '__main__':
    main()
