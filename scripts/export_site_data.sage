#!/usr/bin/env sage
"""
Writes site/data.json for the explorer and the stateful page: the SPX pool from
analysis/all_size_capped_candidates.csv (make sweeps) with the optional w added,
the W+C, W+C_F+C and W+C_P+FP pools from the sweep of costs.sage, and the
XMSS-MT and UXMSS rows of stateful.sage. The pages check samples of it against
their own model.

  sage scripts/export_site_data.sage                     (all schemes, a few minutes)
  sage scripts/export_site_data.sage --schemes SPX,W+C   (a subset; the pages adapt)
"""
import os
import sys
import csv as _csvmod
import json
import subprocess
import datetime

_DOC = __doc__   # loading stateful.sage replaces __doc__
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # see model/costs.sage
os.environ['STATEFUL_SAGE_NO_MAIN'] = '1'   # its functions, without its CLI
load(os.path.join(ROOT, "model", "stateful.sage"))   # and through it costs.sage and security.sage

ALL_SCHEMES = ['SPX', 'W+C', 'W+C_F+C', 'W+C_P+FP']
schemes = ALL_SCHEMES
_args = sys.argv[1:]
i = 0
while i < len(_args):
    if _args[i] == '--schemes' and i + 1 < len(_args):
        schemes = [s for s in _args[i + 1].split(',') if s]
        i += 2
    elif _args[i] == '--help':
        print(_DOC)
        sys.exit(0)
    else:
        print("Unknown argument: {}".format(_args[i]), file=sys.stderr)
        sys.exit(2)
for s in schemes:
    assert s in ALL_SCHEMES, "unknown scheme: %s" % s

GRID = PARAMETERS['stateless']['grid']
W_OPTIONAL = PARAMETERS['stateless']['w_optional']   # SPX only
WC_PAIRS = [(w, SWN[w]) for w in PARAMETERS['stateless']['wc_w']]
POOL_FIELDS = ['h', 'd', 'k', 'a', 'w', 'swn', 'mmax',
               'size', 'kg', 'sg', 'sv', 'sv_worst']


H_VALUES = range(GRID['h'][0], GRID['h'][1] + 1)
D_VALUES = range(GRID['d'][0], GRID['d'][1] + 1)
K_VALUES = range(GRID['k'][0], GRID['k'][1] + 1)
A_VALUES = range(GRID['a'][0], GRID['a'][1] + 1)


# SPX pool: the rows of the sweep CSV
csv_path = os.path.join(ROOT, 'analysis', 'all_size_capped_candidates.csv')
spx_rows, baseline = [], None
with open(csv_path) as f:
    for r in _csvmod.DictReader(f):
        rec = [int(r['h']), int(r['d']), int(r['k']), int(r['a']), int(r['w']),
               0, 0,
               int(r['size']), int(float(r['keygen_C'])), int(float(r['sign_C'])),
               int(float(r['verify_C'])), int(float(r['verify_worst_C']))]
        if r['label'] == 'STANDARD':
            baseline = {'params': {x: PARAMETERS['baseline'][x] for x in ('h', 'd', 'k', 'a', 'w')},
                        'size': rec[7], 'kg': rec[8], 'sg': rec[9],
                        'sv': rec[10], 'sv_worst': rec[11]}
        else:
            spx_rows.append(rec)
assert baseline is not None, "STANDARD row missing from %s" % csv_path

# The optional w of SPX and the variant pools: the sweep of costs.sage
def pool_rows(scheme, w_swn_pairs):
    """Pool rows (POOL_FIELDS) of the grid below max_size, and the number of
    parameter sets considered."""
    rows, considered, at = [], 0, None
    for (w, swn, h, d, k, a), r in sweep(scheme, w_swn_pairs, H_VALUES, D_VALUES,
                                          K_VALUES, A_VALUES, GRID['q_s_log2']):
        considered += 1
        if (w, h, d) != at:
            at = (w, h, d)
            print("  {}: w={}, h={}, d={}".format(scheme, w, h, d), file=sys.stderr, end='\r')
        if r is None or r['size'] >= GRID['max_size']:
            continue
        rows.append([int(r[f]) for f in ('h', 'd', 'k', 'a', 'w', 'swn', 'mmax', 'size',
                                         'keygen', 'sign', 'verify', 'verify_worst')])
    print(file=sys.stderr)
    return rows, considered


pools = {}
if 'SPX' in schemes:
    # 'considered' counts the core grid only; the page derives the count for
    # whichever w set is active from meta.grid.
    hd_pairs = sum(1 for h in H_VALUES for d in D_VALUES if h % d == 0)
    spx_considered = hd_pairs * len(GRID['w']) * len(K_VALUES) * len(A_VALUES)
    spx_extra, _ = pool_rows('SPX', [(w, 0) for w in W_OPTIONAL])
    all_spx = spx_rows + spx_extra
    pools['SPX'] = {'fields': POOL_FIELDS, 'considered': spx_considered,
                    'count': len(all_spx), 'rows': all_spx}
    print("SPX: {} rows ({} core from CSV + {} optional-w)".format(
        len(all_spx), len(spx_rows), len(spx_extra)), file=sys.stderr)
for scheme in schemes:
    if scheme == 'SPX':
        continue
    rows, considered = pool_rows(scheme, WC_PAIRS)
    pools[scheme] = {'fields': POOL_FIELDS, 'considered': considered,
                     'count': len(rows), 'rows': rows}
    print("{}: {} rows of {} considered".format(scheme, len(rows), considered),
          file=sys.stderr)

# Stateful: XMSS-MT (XMSS is d = 1) and UXMSS, from stateful.sage
STATEFUL = PARAMETERS['stateful']

xmssmt_rows = []
for ots_label, ots_type in (('TW', OTS_TW), ('WC', OTS_WC)):
    for w in STATEFUL['w']:
        swn = SWN[w] if ots_type == OTS_WC else 0
        for h in range(STATEFUL['h'][0], STATEFUL['h'][1] + 1):
            for d in range(STATEFUL['d'][0], STATEFUL['d'][1] + 1):
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
    for w in STATEFUL['w']:
        swn = SWN[w] if ots_type == OTS_WC else 0
        hsf = find_max_hsf(w, ots_type, STATEFUL['uxmss_ref_size'])
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
            cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
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
        'w_optional': W_OPTIONAL,
        'wc_pairs': WC_PAIRS,
        'schemes': [s for s in ALL_SCHEMES if s in pools],
        'uxmss_ref_size': STATEFUL['uxmss_ref_size'],
        'hsf_max': int(HSF_MAX),
        'cost_convention': 'cached',
    },
    'baseline': baseline,
    'pools': pools,
    'stateful': {
        'slh': {'size': baseline['size'], 'kg': baseline['kg'],
                'sg': baseline['sg'], 'sv': baseline['sv'],
                'sv_worst': baseline['sv_worst'],
                'qs_log2': PARAMETERS['baseline']['q_s_log2']},
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

out_path = os.path.join(ROOT, 'site', 'data.json')
with open(out_path, 'w') as f:
    # default=int: the sage preparser turns integer literals into sage
    # Integers, which the json module cannot serialize directly.
    json.dump(data, f, separators=(',', ':'), default=int)
print("Wrote {} — schemes: {} — commit {}".format(
    out_path, ', '.join('%s:%d' % (s, pools[s]['count']) for s in pools),
    data['meta']['commit']))
