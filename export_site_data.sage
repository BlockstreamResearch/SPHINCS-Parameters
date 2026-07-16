#!/usr/bin/env sage
"""
Export the canonical dataset consumed by both interactive pages: site/data.json.

Single source of truth:
  - SPX pool        : read from utils/all_size_capped_candidates.csv
                      (regenerate first if needed:
                       sage slhdsa-2to40.sage --max-size 7856 &&
                       mv candidates.csv utils/all_size_capped_candidates.csv)
  - variant pools   : W+C, W+C_F+C, W+C_P+FP swept over the same canonical
                      grid with (w, swn) in {(16, 240), (256, 2040)}, using
                      costs.sage / security.sage directly
  - stateful grid, UXMSS variants, SLH baseline
                    : computed by loading stateful.sage

The pages load data.json at startup and fall back to in-browser computation
(SPX only) if the file is unavailable; they also self-check the loaded
numbers against their local formulas and log any divergence to the console.

Usage:
  sage export_site_data.sage                     # all schemes (a few minutes)
  sage export_site_data.sage --schemes SPX,W+C   # subset (pages adapt)
Verify:
  python3 tests/test_regression.py
"""
import os
import sys
import csv as _csvmod
import json
import subprocess
import datetime

_dir = os.path.dirname(os.path.abspath(__file__))
os.environ['STATEFUL_SAGE_NO_MAIN'] = '1'
os.environ['COSTS_SAGE_NO_MAIN'] = '1'

_saved_argv = sys.argv
sys.argv = ['export_site_data.sage']
load(os.path.join(_dir, "stateful.sage"))   # also loads costs.sage + security.sage
sys.argv = _saved_argv

ALL_SCHEMES = ['SPX', 'W+C', 'W+C_F+C', 'W+C_P+FP']
schemes = ALL_SCHEMES
_args = _saved_argv[1:]
i = 0
while i < len(_args):
    if _args[i] == '--schemes' and i + 1 < len(_args):
        schemes = [s for s in _args[i + 1].split(',') if s]
        i += 2
    elif _args[i] == '--help':
        print(__doc__)
        sys.exit(0)
    else:
        print("Unknown argument: {}".format(_args[i]), file=sys.stderr)
        sys.exit(2)
for s in schemes:
    assert s in ALL_SCHEMES, "unknown scheme: %s" % s

# Canonical stateless grid (report Sec. 2; must match slhdsa-2to40.sage
# defaults and the explorer's fallback sweep).
GRID = {'h': [40, 50], 'd': [2, 25], 'k': [6, 24], 'a': [8, 20],
        'w': [16, 32, 256], 'q_s_log2': 40, 'max_size': 7856}
WC_PAIRS = [(16, 240), (256, 2040)]   # (w, swn) for WOTS+C schemes
POOL_FIELDS = ['h', 'd', 'k', 'a', 'w', 'swn', 'mmax',
               'size', 'kg', 'sg', 'sv', 'sv_worst']


def _hd_pairs():
    return [(h, d)
            for h in range(GRID['h'][0], GRID['h'][1] + 1)
            for d in range(GRID['d'][0], GRID['d'][1] + 1)
            if h % d == 0]


# ---------------------------------------------------------------------------
# SPX pool: straight from the canonical sweep CSV
# ---------------------------------------------------------------------------
csv_path = os.path.join(_dir, 'utils', 'all_size_capped_candidates.csv')
spx_rows, baseline = [], None
with open(csv_path) as f:
    for r in _csvmod.DictReader(f):
        rec = [int(r['h']), int(r['d']), int(r['k']), int(r['a']), int(r['w']),
               0, 0,
               int(r['size']), int(float(r['keygen_C'])), int(float(r['sign_C'])),
               int(float(r['verify_C'])), int(float(r['verify_worst_C']))]
        if r['label'] == 'STANDARD':
            baseline = {'params': {'h': 63, 'd': 7, 'k': 14, 'a': 12, 'w': 16},
                        'size': rec[7], 'kg': rec[8], 'sg': rec[9],
                        'sv': rec[10], 'sv_worst': rec[11]}
        else:
            spx_rows.append(rec)
assert baseline is not None, "STANDARD row missing from %s" % csv_path

# ---------------------------------------------------------------------------
# Variant pools: computed with costs.sage functions (security cached)
# ---------------------------------------------------------------------------
_sec_cache = {}


def _security_ok(model, h, k, a):
    key = (model, int(h), int(k), int(a))
    if key not in _sec_cache:
        _sec_cache[key] = float(compute_security(
            2**GRID['q_s_log2'], h, k, a, model, hashbytes=16)) >= 128.0
    return _sec_cache[key]


def sweep_scheme(scheme):
    model = "PORS+FP" if scheme == "W+C_P+FP" else "FORS"
    rows, considered = [], 0
    pairs = _hd_pairs()
    for w, swn in WC_PAIRS:
        for pi, (h, d) in enumerate(pairs):
            print("  {}: (w={}, swn={}) {}/{}".format(scheme, w, swn, pi + 1, len(pairs)),
                  file=sys.stderr, end='\r')
            for k in range(GRID['k'][0], GRID['k'][1] + 1):
                for a in range(GRID['a'][0], GRID['a'][1] + 1):
                    considered += 1
                    if not _security_ok(model, h, k, a):
                        continue
                    try:
                        sign = compute_signing_time(h, d, a, k, w, swn, scheme)
                        mmax = sign['mmax']
                        verify = compute_verification_time(h, d, a, k, w, swn, scheme, mmax)
                        size = compute_size(h, d, a, k, w, scheme, mmax)
                    except Exception:
                        continue
                    if size >= GRID['max_size']:
                        continue
                    kg = compute_keygen_time(h, d, w, scheme)
                    rows.append([int(h), int(d), int(k), int(a), int(w),
                                 int(swn), int(mmax), int(size), int(kg),
                                 int(sign['compressions']),
                                 int(verify['compressions']),
                                 int(verify['compressions_worst'])])
    print(file=sys.stderr)
    return rows, considered


pools = {}
if 'SPX' in schemes:
    pairs = _hd_pairs()
    spx_considered = (len(pairs) * len(GRID['w'])
                      * (GRID['k'][1] - GRID['k'][0] + 1)
                      * (GRID['a'][1] - GRID['a'][0] + 1))
    pools['SPX'] = {'fields': POOL_FIELDS, 'considered': spx_considered,
                    'count': len(spx_rows), 'rows': spx_rows}
    print("SPX: {} rows (from CSV)".format(len(spx_rows)), file=sys.stderr)
for scheme in schemes:
    if scheme == 'SPX':
        continue
    rows, considered = sweep_scheme(scheme)
    pools[scheme] = {'fields': POOL_FIELDS, 'considered': considered,
                     'count': len(rows), 'rows': rows}
    print("{}: {} rows of {} considered".format(scheme, len(rows), considered),
          file=sys.stderr)

# ---------------------------------------------------------------------------
# Stateful: XMSS/XMSS-MT grid + UXMSS variants (same functions as the CLI)
# ---------------------------------------------------------------------------
_SWN = {16: 240, 32: 403, 256: 2040}
UXMSS_REF = 5712   # Report Candidate 2 — reference bound for max stateful size

xmssmt_rows = []
for ots_label, ots_type in (('TW', OTS_TW), ('WC', OTS_WC)):
    for w in (16, 32, 256):
        swn = _SWN[w] if ots_type == OTS_WC else 0
        for h in range(10, 41):
            for d in range(1, 11):
                if h % d != 0:
                    continue
                xmssmt_rows.append([
                    ots_label, h, d, w,
                    int(xmssmt_size_h(h, d, w, ots_type)),
                    int(xmssmt_keygen_C_h(h, d, w, ots_type)),
                    int(xmssmt_sign_bds_C_h(h, d, w, swn, ots_type)),
                    int(xmssmt_sign_cold_C_h(h, d, w, swn, ots_type)),
                    int(xmssmt_state_bytes(h, d, w, ots_type)),
                    int(xmssmt_verify_C_h(h, d, w, swn, ots_type, worst_case=False)),
                    int(xmssmt_verify_C_h(h, d, w, swn, ots_type, worst_case=True)),
                ])

uxmss_rows = []
for ots_label, ots_type in (('TW', OTS_TW), ('WC', OTS_WC)):
    for w in (16, 32, 256):
        swn = _SWN[w] if ots_type == OTS_WC else 0
        hsf = find_max_hsf(w, ots_type, UXMSS_REF)
        uxmss_rows.append([
            ots_label, w, int(hsf),
            int(uxmss_size(1, hsf, w, ots_type)),
            int(uxmss_size(hsf, hsf, w, ots_type)),
            int(uxmss_keygen_C(hsf, w, ots_type)),
            int(uxmss_sign_C(1, hsf, w, swn, ots_type)),
            int(uxmss_sign_cold_C(hsf, w, swn, ots_type)),
            int(uxmss_state_bytes(hsf)),
            int(uxmss_verify_C(hsf, hsf, w, swn, ots_type, worst_case=False)),
            int(uxmss_verify_C(hsf, hsf, w, swn, ots_type, worst_case=True)),
        ])


def _commit():
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=_dir, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        sha = os.environ.get('GITHUB_SHA', '')
        return sha[:7] if sha else 'unknown'


data = {
    'meta': {
        'version': 3,
        'generator': 'export_site_data.sage',
        'generated': datetime.date.today().isoformat(),
        'commit': _commit(),
        'grid': GRID,
        'wc_pairs': WC_PAIRS,
        'schemes': [s for s in ALL_SCHEMES if s in pools],
        'uxmss_ref_size': UXMSS_REF,
        'hsf_max': int(HSF_MAX),
        'cost_convention': HASH_CONVENTION,
    },
    'baseline': baseline,
    'pools': pools,
    'stateful': {
        'slh': {'size': baseline['size'], 'kg': baseline['kg'],
                'sg': baseline['sg'], 'sv': baseline['sv'],
                'sv_worst': baseline['sv_worst'], 'qs_log2': 64},
        'xmssmt': {
            'fields': ['ots', 'h', 'd', 'w', 'size', 'kg', 'sg', 'sg_cold',
                       'state', 'sv', 'sv_worst'],
            'rows': xmssmt_rows,
        },
        'uxmss': {
            'fields': ['ots', 'w', 'hsf', 'sz_q1', 'sz_max', 'kg', 'sg',
                       'sg_cold', 'state', 'sv_max', 'sv_max_worst'],
            'rows': uxmss_rows,
        },
    },
}

out_path = os.path.join(_dir, 'site', 'data.json')
with open(out_path, 'w') as f:
    # default=int: the sage preparser turns integer literals into sage
    # Integers, which the json module cannot serialize directly.
    json.dump(data, f, separators=(',', ':'), default=int)
print("Wrote {} — schemes: {} — commit {}".format(
    out_path, ', '.join('%s:%d' % (s, pools[s]['count']) for s in pools),
    data['meta']['commit']))
