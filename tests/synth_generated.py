#!/usr/bin/env python3
"""Writes the generated files, the sweep CSVs and site/data.json, from
tests/model.py instead of Sage, so the tests of those files run without Sage.
The security bits come from the stateless page's JavaScript. The PORS+FP pool
needs Sage and is left out. make check-local runs:

  python3 tests/synth_generated.py
  GENERATED_REQUIRED=1 python3 tests/test_regression.py
"""
import csv
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import model as M  # noqa: E402

P = M.PARAMETERS
GRID = P['stateless']['grid']
W_OPTIONAL = P['stateless']['w_optional']
WC_PAIRS = [(w, M.SWN[w]) for w in P['stateless']['wc_w']]
STATEFUL = P['stateful']
BASELINE = tuple(P['baseline'][x] for x in ('h', 'd', 'k', 'a', 'w'))
POOL_FIELDS = ['h', 'd', 'k', 'a', 'w', 'swn', 'mmax',
               'size', 'kg', 'sg', 'sv', 'sv_worst']
CSV_FIELDS = ['label', 'h', 'd', 'h_prime', 'k', 'a', 'w', 'l',
              'swn', 'mmax', 'security', 'size', 'keygen_C',
              'sign_C', 'verify_C', 'verify_worst_C',
              'c_per_byte', 'c_per_byte_worst']


def hd_pairs():
    return [(h, d)
            for h in range(GRID['h'][0], GRID['h'][1] + 1)
            for d in range(GRID['d'][0], GRID['d'][1] + 1)
            if h % d == 0]


def security_from_page():
    """FORS security bits per (h, k, a), via the stateless page's JS."""
    if not shutil.which('node'):
        sys.exit('node is required (the security analysis runs from the page JS)')
    html = open(os.path.join(ROOT, 'site', 'stateless.html'), encoding='utf-8').read()
    srcs = re.findall(r'<script src="([^"]+)"></script>', html)
    js = '\n'.join(open(os.path.join(ROOT, 'site', s), encoding='utf-8').read() for s in srcs) + """
const out = { grid: {}, std: computeSecurityBits(%d, %d, %d, %d) };
for (let h = %d; h <= %d; h++)
  for (let k = %d; k <= %d; k++)
    for (let a = %d; a <= %d; a++)
      out.grid[[h, k, a].join(',')] = computeSecurityBits(%d, h, k, a);
console.log(JSON.stringify(out));
""" % (P['baseline']['q_s_log2'], P['baseline']['h'], P['baseline']['k'], P['baseline']['a'],
       GRID['h'][0], GRID['h'][1], GRID['k'][0], GRID['k'][1],
       GRID['a'][0], GRID['a'][1], GRID['q_s_log2'])
    p = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stderr[:2000]
    out = json.loads(p.stdout.strip().splitlines()[-1])
    grid = {tuple(int(x) for x in key.split(',')): v for key, v in out['grid'].items()}
    return grid, out['std']


def spx_csv_row(label, h, d, k, a, w, security):
    m = M.spx_metrics(h, d, k, a, w)
    return {
        'label': label, 'h': h, 'd': d, 'h_prime': h // d, 'k': k, 'a': a,
        'w': w, 'l': M.wots_len(w), 'swn': 0, 'mmax': 0,
        'security': float(security), 'size': m['size'],
        'keygen_C': float(m['kg']), 'sign_C': float(m['sg']),
        'verify_C': float(m['sv']), 'verify_worst_C': float(m['sv_worst']),
        'c_per_byte': m['cpb'], 'c_per_byte_worst': m['cpb_worst'],
    }


def main():
    sec, std_sec = security_from_page()
    passing = {t for t, bits in sec.items() if bits >= P['security_bits']}
    pairs = hd_pairs()

    # The sweep CSVs: the grid's w only, as slhdsa-2to40.sage
    std = spx_csv_row('STANDARD', *BASELINE, std_sec)
    for name, max_size in (('all_size_capped_candidates.csv', GRID['max_size']),
                           ('all_unbound_candidates.csv', 10**8)):
        rows = [std]
        for w in GRID['w']:
            for (h, d) in pairs:
                for k in range(GRID['k'][0], GRID['k'][1] + 1):
                    for a in range(GRID['a'][0], GRID['a'][1] + 1):
                        if (h, k, a) not in passing:
                            continue
                        r = spx_csv_row('w=%d' % w, h, d, k, a, w, sec[(h, k, a)])
                        if r['size'] >= max_size:
                            continue
                        rows.append(r)
        rows.sort(key=lambda r: r['size'])
        path = os.path.join(ROOT, 'analysis', name)
        with open(path, 'w', newline='') as f:
            wtr = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            wtr.writeheader()
            wtr.writerows(rows)
        print('%s: %d rows' % (name, len(rows)))

    # data.json: the SPX pool, with the optional w
    def spx_pool_row(h, d, k, a, w):
        m = M.spx_metrics(h, d, k, a, w)
        return [h, d, k, a, w, 0, 0, m['size'], m['kg'], m['sg'], m['sv'], m['sv_worst']]

    spx_rows = []
    for w in GRID['w'] + W_OPTIONAL:
        for (h, d) in pairs:
            for k in range(GRID['k'][0], GRID['k'][1] + 1):
                for a in range(GRID['a'][0], GRID['a'][1] + 1):
                    if (h, k, a) in passing and \
                            M.spx_metrics(h, d, k, a, w)['size'] < GRID['max_size']:
                        spx_rows.append(spx_pool_row(h, d, k, a, w))
    spx_considered = (len(pairs) * len(GRID['w'])
                      * (GRID['k'][1] - GRID['k'][0] + 1)
                      * (GRID['a'][1] - GRID['a'][0] + 1))
    pools = {'SPX': {'fields': POOL_FIELDS, 'considered': spx_considered,
                     'count': len(spx_rows), 'rows': spx_rows}}

    # The FORS-based variant pools
    for scheme in ('W+C', 'W+C_F+C'):
        rows, considered = [], 0
        for w, swn in WC_PAIRS:
            for (h, d) in pairs:
                for k in range(GRID['k'][0], GRID['k'][1] + 1):
                    for a in range(GRID['a'][0], GRID['a'][1] + 1):
                        considered += 1
                        if (h, k, a) not in passing:
                            continue
                        m = M.scheme_metrics(scheme, h, d, k, a, w, swn)
                        if m['size'] >= GRID['max_size']:
                            continue
                        rows.append([h, d, k, a, w, swn, m['mmax'], m['size'],
                                     m['kg'], m['sg'], m['sv'], m['sv_worst']])
        pools[scheme] = {'fields': POOL_FIELDS, 'considered': considered,
                         'count': len(rows), 'rows': rows}
        print('%s: %d rows' % (scheme, len(rows)))

    # Stateful
    b = M.spx_metrics(*BASELINE)
    baseline = {'params': dict(zip(('h', 'd', 'k', 'a', 'w'), BASELINE)),
                'size': b['size'], 'kg': b['kg'], 'sg': b['sg'],
                'sv': b['sv'], 'sv_worst': b['sv_worst']}
    xmssmt_rows, uxmss_rows = [], []
    for ots in ('TW', 'WC'):
        for w in STATEFUL['w']:
            for h in range(STATEFUL['h'][0], STATEFUL['h'][1] + 1):
                for d in range(STATEFUL['d'][0], STATEFUL['d'][1] + 1):
                    if h % d:
                        continue
                    m = M.xmssmt_metrics(ots, h, d, w)
                    xmssmt_rows.append([ots, h, d, w, m['size'], m['kg'],
                                        m['sg'], m['sg_cold'], m['state'],
                                        m['sv'], m['sv_worst']])
            u = M.uxmss_metrics(ots, w)
            uxmss_rows.append([ots, w, u['hsf'], u['sz_q1'], u['sz_max'],
                               u['kg'], u['sg'], u['sg_cold'], u['state'],
                               u['sv_max'], u['sv_max_worst']])

    data = {
        'meta': {
            'version': 3,
            'generator': 'tests/synth_generated.py (tests/model.py, not Sage)',
            'generated': datetime.date.today().isoformat(),
            'commit': 'local-synth',
            'grid': GRID,
            'w_optional': W_OPTIONAL,
            'wc_pairs': [list(p) for p in WC_PAIRS],
            'schemes': list(pools.keys()),
            'uxmss_ref_size': STATEFUL['uxmss_ref_size'],
            'hsf_max': M.HSF_MAX,
            'cost_convention': 'cached',
        },
        'baseline': baseline,
        'pools': pools,
        'stateful': {
            'slh': {'size': baseline['size'], 'kg': baseline['kg'],
                    'sg': baseline['sg'], 'sv': baseline['sv'],
                    'sv_worst': baseline['sv_worst'],
                    'qs_log2': P['baseline']['q_s_log2']},
            'xmssmt': {'fields': ['ots', 'h', 'd', 'w', 'size', 'kg', 'sg',
                                  'sg_cold', 'state', 'sv', 'sv_worst'],
                       'rows': xmssmt_rows},
            'uxmss': {'fields': ['ots', 'w', 'hsf', 'sz_q1', 'sz_max', 'kg',
                                 'sg', 'sg_cold', 'state', 'sv_max',
                                 'sv_max_worst'],
                      'rows': uxmss_rows},
        },
    }
    out_path = os.path.join(ROOT, 'site', 'data.json')
    json.dump(data, open(out_path, 'w'), separators=(',', ':'))
    print('site/data.json: SPX %d rows, stateful %d + %d rows' %
          (len(spx_rows), len(xmssmt_rows), len(uxmss_rows)))


if __name__ == '__main__':
    main()
