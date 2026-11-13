"""Paths, fixtures and helpers the test modules share."""
import csv
import json
import os
import re
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

FIX = json.load(open(os.path.join(HERE, 'fixtures.json')))

GENERATED_REQUIRED = bool(os.environ.get('GENERATED_REQUIRED'))
CSVS = ('analysis/all_size_capped_candidates.csv', 'analysis/all_unbound_candidates.csv')
DATA_JSON = 'site/data.json'


def missing(*relpaths):
    """True if a generated file is absent; under GENERATED_REQUIRED=1 that
    fails instead."""
    absent = [p for p in relpaths if not os.path.exists(os.path.join(ROOT, p))]
    if not absent:
        return False
    assert not GENERATED_REQUIRED, f'generated artifacts missing: {absent}'
    print(f"  [skip] generated artifacts not present (run `make generate`): {', '.join(absent)}")
    return True


def tuple_of(key):
    return tuple(int(x) for x in key.split(','))


def csv_rows(name):
    with open(os.path.join(ROOT, 'analysis', name)) as fh:
        return list(csv.DictReader(fh))


def page_js(page):
    """The scripts a page loads, in order, as one script to run under node."""
    html = open(os.path.join(ROOT, 'site', page), encoding='utf-8').read()
    srcs = re.findall(r'<script src="([^"]+)"></script>', html)
    return '\n'.join(open(os.path.join(ROOT, 'site', s), encoding='utf-8').read() for s in srcs)


def run_node(js):
    if not shutil.which('node'):
        print('  [skip] node not available')
        return None
    p = subprocess.run(['node', '-e', js], capture_output=True, text=True,
                       cwd=ROOT, timeout=300)
    assert p.returncode == 0, p.stderr[:2000]
    return json.loads(p.stdout.strip().splitlines()[-1])


def site_data():
    return json.load(open(os.path.join(ROOT, 'site', 'data.json')))
