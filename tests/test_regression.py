#!/usr/bin/env python3
"""Regression tests for the SPHINCS-Parameters tool chain.

Diffs three independent implementations against frozen golden fixtures:
  1. tests/model.py       — stdlib-only reference model (audit port)
  2. utils/*.csv          — the published sweep data (sage output)
  3. site/*.html          — the interactive pages' JS (executed under node)
  4. costs.sage           — exercised directly when `sage` is on PATH

Run:  python3 tests/test_regression.py        (also works under pytest)

Requires node for the site tests and sage for the sage test; both are
skipped with a notice when unavailable.

Generated artifacts (the sweep CSVs and site/data.json) are produced by
`make generate` and are not tracked in git. Tests that validate them skip
with a notice when the files are absent - set GENERATED_REQUIRED=1 (as the
CI pipeline does after its generate stage) to turn those skips into
failures.

These tests would have caught both critical audit findings:
  C1 (w=32 chain-count floor bug)  -> test_wots_chain_counts, test_csv_*
  C2 (randomness-size divergence)  -> test_stateful_model, test_site_stateful
"""
import csv
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

FIX = json.load(open(os.path.join(HERE, 'fixtures.json')))

GENERATED_REQUIRED = bool(os.environ.get('GENERATED_REQUIRED'))


def _missing(*relpaths):
    """True if any generated artifact is absent.

    Under GENERATED_REQUIRED=1 (CI pipeline mode) absence is a failure
    instead of a skip.
    """
    absent = [p for p in relpaths if not os.path.exists(os.path.join(ROOT, p))]
    if not absent:
        return False
    assert not GENERATED_REQUIRED, f'generated artifacts missing: {absent}'
    print(f"  [skip] generated artifacts not present (run `make generate`): {', '.join(absent)}")
    return True


CSVS = ('utils/all_size_capped_candidates.csv', 'utils/all_unbound_candidates.csv')
DATA_JSON = 'site/data.json'


def _tuple_of(key):
    return tuple(int(x) for x in key.split(','))


# ---------------------------------------------------------------------------
# 1. Reference model vs frozen fixtures
# ---------------------------------------------------------------------------

def test_wots_chain_counts():
    """FIPS 205 chain counts — catches the C1 class of bug (w=32 -> 28, not 27)."""
    for w, l in FIX['wots_len'].items():
        assert M.wots_len(int(w)) == l, (w, M.wots_len(int(w)), l)
    for w, l in FIX['wots_len_wc'].items():
        assert M.wots_len(int(w), wc=True) == l
    for w, s in FIX['swn'].items():
        assert M.SWN[int(w)] == s


def test_baseline_metrics():
    b = FIX['baseline']
    m = M.spx_metrics(63, 7, 14, 12, 16)
    for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
        assert m[k] == b[k], (k, m[k], b[k])
    assert abs(m['cpb'] - 0.2743126272912423) < 1e-12
    assert abs(m['cpb_worst'] - 0.4952902240325865) < 1e-12


def test_stateless_fixtures():
    for key, f in FIX['stateless'].items():
        m = M.spx_metrics(*_tuple_of(key))
        for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
            assert m[k] == f[k], (key, k, m[k], f[k])


def test_stateful_model():
    """UXMSS + XMSS-MT fixtures — catches the C2 class of bug (R_SIZE drift)."""
    for key, f in FIX['stateful']['uxmss'].items():
        ots, w = key.split(',')
        m = M.uxmss_metrics(ots, int(w))
        assert m == f, (key, m, f)
    for key, f in FIX['stateful']['xmssmt'].items():
        parts = key.split(',')
        m = M.xmssmt_metrics(parts[0], int(parts[1]), int(parts[2]), int(parts[3]))
        assert m == f, (key, m, f)


# ---------------------------------------------------------------------------
# 2. Published CSVs vs reference model
# ---------------------------------------------------------------------------

def _csv_rows(name):
    with open(os.path.join(ROOT, 'utils', name)) as fh:
        return list(csv.DictReader(fh))


def test_csv_row_counts():
    if _missing(*CSVS):
        return
    for name, expected in FIX['csv_rows'].items():
        assert len(_csv_rows(name)) == expected, name


def test_csv_full_consistency():
    """Every row of both sweep CSVs must match the reference model exactly."""
    if _missing(*CSVS):
        return
    for name in FIX['csv_rows']:
        for r in _csv_rows(name):
            t = tuple(int(r[x]) for x in 'hdkaw')
            m = M.spx_metrics(*t)
            got = (int(r['size']), int(float(r['keygen_C'])),
                   int(float(r['sign_C'])), int(float(r['verify_C'])),
                   int(float(r['verify_worst_C'])), int(r['l']))
            want = (m['size'], m['kg'], m['sg'], m['sv'], m['sv_worst'],
                    M.wots_len(t[4]))
            assert got == want, (name, t, got, want)
            assert abs(float(r['c_per_byte']) - m['cpb']) < 1e-9
            assert abs(float(r['c_per_byte_worst']) - m['cpb_worst']) < 1e-9


def test_csv_standard_row():
    if _missing(CSVS[0]):
        return
    std = [r for r in _csv_rows('all_size_capped_candidates.csv')
           if r['label'] == 'STANDARD']
    assert len(std) == 1
    assert int(std[0]['size']) == FIX['baseline']['size']


# ---------------------------------------------------------------------------
# 3. Site pages (node)
# ---------------------------------------------------------------------------

def _extract_js(page, end_marker):
    html = open(os.path.join(ROOT, 'site', page)).read()
    m = re.search(r"'use strict';(.*?)" + re.escape(end_marker), html, re.S)
    assert m, f'extraction markers not found in {page} — update the test'
    return m.group(1)


def _run_node(js):
    if not shutil.which('node'):
        print('  [skip] node not available')
        return None
    p = subprocess.run(['node', '-e', js], capture_output=True, text=True,
                       cwd=ROOT, timeout=300)
    assert p.returncode == 0, p.stderr[:2000]
    return json.loads(p.stdout.strip().splitlines()[-1])


def test_site_index():
    js = _extract_js('stateless.html', '// ---------- State ----------')
    tuples = [list(_tuple_of(k)) for k in FIX['stateless']]
    js += f"""
const _tuples = {json.dumps(tuples)};
const out = {{ pool: sweep().filter(passesInitial).length, metrics: {{}} }};
for (const t of _tuples) {{
  const m = metrics({{h:t[0], d:t[1], k:t[2], a:t[3], w:t[4]}});
  out.metrics[t.join(',')] = [m.size, m.kg, m.sg, m.sv, m.sv_worst];
}}
console.log(JSON.stringify(out));
"""
    out = _run_node(js)
    if out is None:
        return
    assert out['pool'] == FIX['site_pool_count'], out['pool']
    for key, f in FIX['stateless'].items():
        got = out['metrics'][key]
        want = [f['size'], f['kg'], f['sg'], f['sv'], f['sv_worst']]
        assert got == want, (key, got, want)


def test_site_main():
    """index.html (SHRINCS main): pinned cards must match the reference model."""
    js = _extract_js('index.html', '// ---------- Render ----------')
    js += """
const out = {};
out.pinned = (m => [m.size, m.kg, m.sg, m.sv, m.svWorst])(slhMetrics(PINNED));
out.slh = (m => [m.size, m.kg, m.sg, m.sv, m.svWorst])(slhMetrics(SLH));
const swn = WOTS_C_SWN[256];
out.xmss = {};
for (const h of [10, 20, 25, 40]) {
  out.xmss[h] = [xmssMtSize(h,1,256,'WC'), xmssMtKeygenC(h,1,256,'WC'),
    xmssMtSignBdsC(h,1,256,swn,'WC'), xmssMtSignColdC(h,1,256,swn,'WC'),
    xmssMtStateBytes(h,1,256,'WC'), xmssMtVerifyC(h,1,256,swn,'WC')];
}
const hsf = findMaxHsf(256, 'WC', UXMSS_TARGET_SIZE);
out.uxmss = [hsf, uxmssSize(1,hsf,256,'WC'), uxmssSize(hsf,hsf,256,'WC'),
  uxmssKeygenC(hsf,256,'WC'), uxmssSignC(256,swn,'WC'),
  uxmssVerifyC(hsf,hsf,256,swn,'WC')];
console.log(JSON.stringify(out));
"""
    out = _run_node(js)
    if out is None:
        return
    pm = M.spx_metrics(45, 5, 10, 13, 16)
    assert out['pinned'] == [pm['size'], pm['kg'], pm['sg'], pm['sv'], pm['sv_worst']], out['pinned']
    assert out['pinned'][0] == 5776   # the page's advertised 5,776 B
    bm = M.spx_metrics(63, 7, 14, 12, 16)
    assert out['slh'] == [bm['size'], bm['kg'], bm['sg'], bm['sv'], bm['sv_worst']], out['slh']
    for h, got in out['xmss'].items():
        m = M.xmssmt_metrics('WC', int(h), 1, 256)
        want = [m['size'], m['kg'], m['sg'], m['sg_cold'], m['state'], m['sv']]
        assert got == want, (h, got, want)
    u = M.uxmss_metrics('WC', 256)
    want = [u['hsf'], u['sz_q1'], u['sz_max'], u['kg'], u['sg'], u['sv_max']]
    assert out['uxmss'] == want, (out['uxmss'], want)


def test_site_stateful():
    js = _extract_js('stateful.html', '// Shared slider/number-input renderer')
    js += """
const out = { slh: null, uxmss: {}, xmssmt: {} };
const s = buildSLH().metrics;
out.slh = [s.size, s.keygen, s.siggen, s.sigver, s.sigverWorst];
for (const ots of ['TW','WC']) for (const w of [16,32,64,128,256]) {
  const c = buildUxmss(ots, w), m = c.metrics;
  out.uxmss[`${ots},${w}`] = [c.hsf, m.sizeQ1, m.size, m.keygen, m.siggen, m.sigver, m.sigverWorst];
}
""" + "".join(
        f"""{{ const m = buildXmssMt('{k.split(',')[0]}', {k.split(',')[1]}, {k.split(',')[2]}, {k.split(',')[3]}).metrics;
out.xmssmt['{k}'] = [m.size, m.keygen, m.siggen, m.sigver, m.sigverWorst]; }}
""" for k in FIX['stateful']['xmssmt']) + """
console.log(JSON.stringify(out));
"""
    out = _run_node(js)
    if out is None:
        return
    b = FIX['baseline']
    assert out['slh'] == [b['size'], b['kg'], b['sg'], b['sv'], b['sv_worst']], out['slh']
    for key, f in FIX['stateful']['uxmss'].items():
        want = [f['hsf'], f['sz_q1'], f['sz_max'], f['kg'], f['sg'],
                f['sv_max'], f['sv_max_worst']]
        assert out['uxmss'][key] == want, (key, out['uxmss'][key], want)
    for key, f in FIX['stateful']['xmssmt'].items():
        want = [f['size'], f['kg'], f['sg'], f['sv'], f['sv_worst']]
        assert out['xmssmt'][key] == want, (key, out['xmssmt'][key], want)


# ---------------------------------------------------------------------------
# 4. Canonical site dataset (site/data.json)
# ---------------------------------------------------------------------------

def _site_data():
    return json.load(open(os.path.join(ROOT, 'site', 'data.json')))


def test_data_json_meta():
    if _missing(DATA_JSON):
        return
    d = _site_data()
    for key in ('version', 'generator', 'generated', 'commit', 'grid', 'schemes'):
        assert key in d['meta'], key
    assert d['meta']['version'] == 3
    assert d['meta']['cost_convention'].startswith('cached')
    assert d['meta']['grid']['h'] == [40, 50]
    assert d['meta']['grid']['k'] == [6, 24]
    assert 'SPX' in d['meta']['schemes']
    for s in d['meta']['schemes']:
        p = d['pools'][s]
        assert p['count'] == len(p['rows']), s
    assert d['pools']['SPX']['considered'] == 43225


def test_data_json_stateless():
    if _missing(DATA_JSON, CSVS[0]):
        return
    d = _site_data()
    b = FIX['baseline']
    for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
        assert d['baseline'][k] == b[k], k
    p = d['pools']['SPX']
    idx = {f: i for i, f in enumerate(p['fields'])}
    rows = p['rows']
    assert len(rows) == FIX['site_pool_count']
    csv_tuples = {tuple(int(r[x]) for x in 'hdkaw')
                  for r in _csv_rows('all_size_capped_candidates.csv')
                  if r['label'] != 'STANDARD'}
    json_tuples = set()
    for r in rows:
        t = (r[idx['h']], r[idx['d']], r[idx['k']], r[idx['a']], r[idx['w']])
        json_tuples.add(t)
        m = M.spx_metrics(*t)
        got = tuple(r[idx[k]] for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'))
        want = (m['size'], m['kg'], m['sg'], m['sv'], m['sv_worst'])
        assert got == want, (t, got, want)
        assert r[idx['swn']] == 0 and r[idx['mmax']] == 0
    assert json_tuples == csv_tuples


def test_sage_preparser_hazards():
    """No backslash line-continuations in .sage files"""
    import glob
    offenders = []
    for path in glob.glob(os.path.join(ROOT, '*.sage')):
        for lineno, line in enumerate(open(path), 1):
            if line.rstrip('\n').endswith('\\'):
                offenders.append(f'{os.path.basename(path)}:{lineno}')
    assert not offenders, f'backslash continuations in sage files: {offenders}'


def test_uncached_convention():
    """The original Th2=2 convention stays available (HASH_CONVENTION=uncached)
    and still reproduces values frozen from real prior sage runs."""
    spot = FIX['uncached_spot']
    M.set_convention('uncached')
    try:
        b = M.spx_metrics(63, 7, 14, 12, 16)
        for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
            assert b[k] == spot['baseline'][k], (k, b[k])
        v = M.scheme_metrics('W+C', 44, 4, 8, 16, 16, 240)
        ref = spot['variant|W+C|44,4,8,16,16,240']
        for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
            assert v[k] == ref[k], (k, v[k])
        u = M.uxmss_metrics('TW', 16)
        for k, val in spot['uxmss|TW,16'].items():
            assert u[k] == val, (k, u[k], val)
    finally:
        M.set_convention('cached')


def test_variant_fixtures():
    """Frozen values from a real `sage costs.sage` run vs the reference model."""
    for key, f in FIX['variants'].items():
        scheme, rest = key.split('|')
        h, d, k, a, w, swn = (int(x) for x in rest.split(','))
        m = M.scheme_metrics(scheme, h, d, k, a, w, swn)
        for fld in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
            assert m[fld] == f[fld], (key, fld, m[fld], f[fld])


def test_data_json_variant_pools():
    if _missing(DATA_JSON):
        return
    d = _site_data()
    grid = d['meta']['grid']
    for scheme in ('W+C', 'W+C_F+C', 'W+C_P+FP'):
        if scheme not in d['pools']:
            print(f'  [skip] {scheme} pool not exported')
            continue
        p = d['pools'][scheme]
        assert p['count'] == FIX['variant_pool_counts'][scheme], (scheme, p['count'])
        idx = {f: i for i, f in enumerate(p['fields'])}
        for r in p['rows']:
            h, dd, k, a, w, swn = (r[idx[x]] for x in ('h', 'd', 'k', 'a', 'w', 'swn'))
            assert grid['h'][0] <= h <= grid['h'][1] and h % dd == 0
            assert grid['k'][0] <= k <= grid['k'][1]
            assert grid['a'][0] <= a <= grid['a'][1]
            assert (w, swn) in ((16, 240), (256, 2040)), (w, swn)
            m = M.scheme_metrics(scheme, h, dd, k, a, w, swn)
            got = tuple(r[idx[x]] for x in ('mmax', 'size', 'kg', 'sg', 'sv', 'sv_worst'))
            want = (m['mmax'], m['size'], m['kg'], m['sg'], m['sv'], m['sv_worst'])
            assert got == want, (scheme, (h, dd, k, a, w, swn), got, want)
            assert m['size'] < grid['max_size']


def test_data_json_stateful():
    if _missing(DATA_JSON):
        return
    d = _site_data()['stateful']
    b = FIX['baseline']
    assert (d['slh']['size'], d['slh']['kg'], d['slh']['sg'], d['slh']['sv'],
            d['slh']['sv_worst'], d['slh']['qs_log2']) == \
           (b['size'], b['kg'], b['sg'], b['sv'], b['sv_worst'], 64)
    xi = {f: i for i, f in enumerate(d['xmssmt']['fields'])}
    XKEYS = ('size', 'kg', 'sg', 'sg_cold', 'state', 'sv', 'sv_worst')
    for r in d['xmssmt']['rows']:
        m = M.xmssmt_metrics(r[xi['ots']], r[xi['h']], r[xi['d']], r[xi['w']])
        got = tuple(r[xi[k]] for k in XKEYS)
        want = tuple(m[k] for k in XKEYS)
        assert got == want, (r[:4], got, want)
        assert m['sg_cold'] >= m['sg']
    ui = {f: i for i, f in enumerate(d['uxmss']['fields'])}
    assert len(d['uxmss']['rows']) == 10
    UKEYS = ('hsf', 'sz_q1', 'sz_max', 'kg', 'sg', 'sg_cold', 'state',
             'sv_max', 'sv_max_worst')
    for r in d['uxmss']['rows']:
        m = M.uxmss_metrics(r[ui['ots']], r[ui['w']])
        got = tuple(r[ui[k]] for k in UKEYS)
        want = tuple(m[k] for k in UKEYS)
        assert got == want, (r[:2], got, want)
        assert m['hsf'] <= M.HSF_MAX


def test_site_data_integration():
    """Run both pages' data-loading paths under node against site/data.json."""
    if _missing(DATA_JSON):
        return
    data_path = os.path.join(ROOT, 'site', 'data.json')
    # stateless.html: poolFromData must reproduce the pool; STD_M must equal baseline
    js = _extract_js('stateless.html', '// ---------- State ----------')
    js += f"""
const data = JSON.parse(require('fs').readFileSync({json.dumps(data_path)}, 'utf8'));
const pool = poolFromData(data, 'SPX');
let ok = pool.length === data.pools.SPX.count;
const KEYS = ['size','kg','sg','sv','sv_worst'];
ok = ok && !KEYS.some(k => STD_M[k] !== data.baseline[k]);
const step = Math.max(1, Math.floor(pool.length / 50));
for (let i = 0; i < pool.length; i += step) {{
  const m = metrics(pool[i]);
  if (KEYS.some(k => m[k] !== pool[i][k])) ok = false;
}}
// variant pools must map cleanly too (field mapping + count only; metrics are sage-side)
for (const s of data.meta.schemes) {{
  const vp = poolFromData(data, s);
  if (vp.length !== data.pools[s].count) ok = false;
  if (vp.length && !(vp[0].size > 0 && vp[0].sv_worst >= vp[0].sv)) ok = false;
}}
console.log(JSON.stringify({{ok, n: pool.length}}));
"""
    out = _run_node(js)
    if out is not None:
        assert out['ok'] and out['n'] == FIX['site_pool_count'], out
    # stateful.html: the page's own self-check must pass on the shipped data
    js2 = _extract_js('stateful.html', '// Shared slider/number-input renderer')
    js2 += f"""
SITE_DATA = JSON.parse(require('fs').readFileSync({json.dumps(data_path)}, 'utf8'));
const okCheck = selfCheckStateful(SITE_DATA);
const slh = buildSLH().metrics;
const okSlh = slh.size === SITE_DATA.stateful.slh.size && slh.qsLog2 === 64;
console.log(JSON.stringify({{ok: okCheck && okSlh}}));
"""
    out2 = _run_node(js2)
    if out2 is not None:
        assert out2['ok'], out2


# ---------------------------------------------------------------------------
# 5. Sage (optional)
# ---------------------------------------------------------------------------

def test_sage_costs():
    if not shutil.which('sage'):
        print('  [skip] sage not available')
        return
    args = ['sage', 'costs.sage', '--params', 'SPX', '64', '14', '12', '63', '7', '16', '0']
    # Default convention (cached)
    p = subprocess.run(args, capture_output=True, text=True, cwd=ROOT, timeout=600)
    assert p.returncode == 0, p.stderr[:2000]
    b = FIX['baseline']
    assert f"Size:       {b['size']} bytes" in p.stdout, p.stdout
    assert 'Security:   128.0 bits' in p.stdout, p.stdout
    assert 'C/byte:     0.27  (worst: 0.50)' in p.stdout, p.stdout
    # Original convention via the env flag
    env = dict(os.environ, HASH_CONVENTION='uncached')
    p2 = subprocess.run(args, capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    assert p2.returncode == 0, p2.stderr[:2000]
    assert 'C/byte:     0.30  (worst: 0.52)' in p2.stdout, p2.stdout


# ---------------------------------------------------------------------------
# Plain runner (no pytest required)
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith('test_') and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f'PASS  {name}')
        except AssertionError as e:
            failed += 1
            print(f'FAIL  {name}: {e}')
    print(f'\n{len(tests) - failed}/{len(tests)} passed')
    sys.exit(1 if failed else 0)
