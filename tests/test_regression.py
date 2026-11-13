#!/usr/bin/env python3
"""Checks tests/model.py, the generated files (the sweep CSVs and site/data.json),
the site's JavaScript (under node) and costs.sage (under sage) against
tests/fixtures.json and against each other.

  python3 tests/test_regression.py      (or pytest)

Without node or sage, their tests are skipped. Without the generated files
(make generate), their tests are skipped too, or fail with GENERATED_REQUIRED=1
as in CI.
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
    """True if a generated file is absent; under GENERATED_REQUIRED=1 that
    fails instead."""
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


# The reference model against the fixtures

def test_wots_chain_counts():
    """FIPS 205 chain counts, l1 rounded up: 28 chains for w = 32, not 27."""
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
    assert abs(m['cpb'] - 2193 / 7856) < 1e-12
    assert abs(m['cpb_worst'] - 3893 / 7856) < 1e-12


def test_stateless_fixtures():
    for key, f in FIX['stateless'].items():
        m = M.spx_metrics(*_tuple_of(key))
        for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
            assert m[k] == f[k], (key, k, m[k], f[k])


def test_stateful_model():
    """UXMSS and XMSS-MT against the fixtures."""
    for key, f in FIX['stateful']['uxmss'].items():
        ots, w = key.split(',')
        m = M.uxmss_metrics(ots, int(w))
        assert m == f, (key, m, f)
    for key, f in FIX['stateful']['xmssmt'].items():
        parts = key.split(',')
        m = M.xmssmt_metrics(parts[0], int(parts[1]), int(parts[2]), int(parts[3]))
        assert m == f, (key, m, f)


# The sweep CSVs against the reference model

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


# The site pages, under node

def _page_js(page):
    """The scripts a page loads, in order, as one script to run under node."""
    html = open(os.path.join(ROOT, 'site', page), encoding='utf-8').read()
    srcs = re.findall(r'<script src="([^"]+)"></script>', html)
    return '\n'.join(open(os.path.join(ROOT, 'site', s), encoding='utf-8').read() for s in srcs)


def _run_node(js):
    if not shutil.which('node'):
        print('  [skip] node not available')
        return None
    p = subprocess.run(['node', '-e', js], capture_output=True, text=True,
                       cwd=ROOT, timeout=300)
    assert p.returncode == 0, p.stderr[:2000]
    return json.loads(p.stdout.strip().splitlines()[-1])


def test_site_explorer():
    js = _page_js('stateless.html')
    tuples = [list(_tuple_of(k)) for k in FIX['stateless']]
    js += f"""
const _tuples = {json.dumps(tuples)};
const out = {{ metrics: {{}} }};
for (const t of _tuples) {{
  const m = metrics({{h:t[0], d:t[1], k:t[2], a:t[3], w:t[4]}});
  out.metrics[t.join(',')] = [m.size, m.kg, m.sg, m.sv, m.sv_worst];
}}
console.log(JSON.stringify(out));
"""
    out = _run_node(js)
    if out is None:
        return
    for key, f in FIX['stateless'].items():
        got = out['metrics'][key]
        want = [f['size'], f['kg'], f['sg'], f['sv'], f['sv_worst']]
        assert got == want, (key, got, want)


def test_site_security_small_trees():
    """The custom-candidate panel accepts any (h, k, a), so the forgery sum
    must stay cheap when the hypertree has few leaves (lambda = q_s / 2^h
    huge)."""
    js = _page_js('stateless.html')
    js += """
const t0 = Date.now();
const out = {
  // lambda = 2^26 and 2^33: every FORS instance is reused millions of times
  h14: forsForgeryExponent(Q_S_LOG2, 14, 14, 12),
  h7: forsForgeryExponent(Q_S_LOG2, 7, 14, 12),
  // same lambda with 2^40 leaves per tree: (2^26 / 2^40)^14 = 2^-196
  h14_a40: forsForgeryExponent(Q_S_LOG2, 14, 14, 40),
  // lambda = 2^12 and 2^5: every term is summed (stride 1)
  h28: forsForgeryExponent(Q_S_LOG2, 28, 14, 12),
  h35: forsForgeryExponent(Q_S_LOG2, 35, 14, 12),
};
out.ms = Date.now() - t0;
console.log(JSON.stringify(out));
"""
    out = _run_node(js)
    if out is None:
        return
    assert 0 <= out['h14'] < 1e-3 and 0 <= out['h7'] < 1e-3, out
    assert abs(out['h14_a40'] - 196) < 1e-3, out
    assert abs(out['h28'] - 9.2530) < 1e-3 and abs(out['h35'] - 94.7784) < 1e-3, out
    assert out['ms'] < 5000, out     # about 0.1 s


def test_site_parameters():
    """The JavaScript model's copies of parameters.json, kept so the pages also
    work without data.json."""
    js = _page_js('stateless.html') + """
console.log(JSON.stringify({ w: ALLOWED_W, w_optional: OPTIONAL_W, swn: WOTS_C_SWN,
  uxmss_ref_size: UXMSS_TARGET_SIZE, hsf_max: HSF_MAX, slh: SLH, q_s_log2: Q_S_LOG2 }));
"""
    out = _run_node(js)
    if out is None:
        return
    P = M.PARAMETERS
    assert out['w'] == P['stateless']['grid']['w'], out['w']
    assert out['w_optional'] == P['stateless']['w_optional'], out['w_optional']
    assert out['swn'] == P['swn'], out['swn']
    assert out['uxmss_ref_size'] == P['stateful']['uxmss_ref_size']
    assert out['hsf_max'] == P['stateful']['hsf_max']
    assert out['slh'] == {x: P['baseline'][x] for x in ('h', 'd', 'k', 'a', 'w')}, out['slh']
    assert out['q_s_log2'] == P['stateless']['grid']['q_s_log2']


def test_site_main():
    """index.html (SHRINCS main): pinned cards must match the reference model."""
    js = _page_js('index.html')
    js += """
const out = {};
out.pinned = (m => [m.size, m.kg, m.sg, m.sv, m.svWorst])(slhMetrics(PINNED));
out.shrincs_size = shrincsStatelessSize(PINNED);
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
  uxmssKeygenC(hsf,256,'WC'), uxmssSignC(1,hsf,256,swn,'WC'),
  uxmssVerifyC(hsf,hsf,256,swn,'WC')];
// the pinned UXMSS card (first..last signature) and its cold signer
const pw = XMSS_W, pswn = WOTS_C_SWN[pw], phsf = findMaxHsf(pw, 'WC', UXMSS_TARGET_SIZE);
out.pinned_uxmss = {
  w: pw, hsf: phsf,
  size: [uxmssSize(1,phsf,pw,'WC'), uxmssSize(phsf,phsf,pw,'WC')],
  sign: [uxmssSignC(1,phsf,pw,pswn,'WC'), uxmssSignC(phsf+1,phsf,pw,pswn,'WC')],
  cold: uxmssSignColdC(phsf,pw,pswn,'WC'),
  verify: [uxmssVerifyC(1,phsf,pw,pswn,'WC'), uxmssVerifyC(phsf,phsf,pw,pswn,'WC')],
};
console.log(JSON.stringify(out));
"""
    out = _run_node(js)
    if out is None:
        return
    pm = M.spx_metrics(45, 5, 10, 13, 16)
    assert out['pinned'] == [pm['size'], pm['kg'], pm['sg'], pm['sv'], pm['sv_worst']], out['pinned']
    assert out['pinned'][0] == 5776   # the SLH-DSA signature
    # the page advertises the SHRINCS signature: indicator byte + SLH-DSA signature
    assert out['shrincs_size'] == pm['size'] + M.IND_SIZE == 5777, out['shrincs_size']
    bm = M.spx_metrics(63, 7, 14, 12, 16)
    assert out['slh'] == [bm['size'], bm['kg'], bm['sg'], bm['sv'], bm['sv_worst']], out['slh']
    for h, got in out['xmss'].items():
        m = M.xmssmt_metrics('WC', int(h), 1, 256)
        want = [m['size'], m['kg'], m['sg'], m['sg_cold'], m['state'], m['sv']]
        assert got == want, (h, got, want)
    u = M.uxmss_metrics('WC', 256)
    want = [u['hsf'], u['sz_q1'], u['sz_max'], u['kg'], u['sg'], u['sv_max']]
    assert out['uxmss'] == want, (out['uxmss'], want)
    p = out['pinned_uxmss']
    pw, phsf = p['w'], p['hsf']
    pu = M.uxmss_metrics('WC', pw)
    assert phsf == pu['hsf']
    assert p['size'] == [pu['sz_q1'], pu['sz_max']], p['size']
    assert p['sign'] == [M.uxmss_sign_c(1, phsf, pw, 'WC'),
                         M.uxmss_sign_c(phsf + 1, phsf, pw, 'WC')], p['sign']
    assert p['sign'][0] == pu['sg'] and p['sign'][0] - p['sign'][1] == phsf - 1
    assert p['cold'] == pu['sg_cold'], p['cold']
    assert p['verify'] == [M.uxmss_verify_c(1, phsf, pw, 'WC'), pu['sv_max']], p['verify']


def test_site_stateful():
    js = _page_js('stateful.html')
    js += """
const out = { slh: null, uxmss: {}, xmssmt: {} };
const s = buildSLH().metrics;
out.slh = [s.size, s.keygen, s.siggen, s.sigver, s.sigverWorst];
for (const ots of ['TW','WC']) for (const w of [16,32,64,128,256,65536]) {
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


# site/data.json

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
    P = M.PARAMETERS
    assert d['meta']['grid'] == P['stateless']['grid']
    assert d['meta']['w_optional'] == P['stateless']['w_optional']
    assert d['meta']['wc_pairs'] == [[w, M.SWN[w]] for w in P['stateless']['wc_w']]
    assert d['meta']['uxmss_ref_size'] == P['stateful']['uxmss_ref_size']
    assert d['meta']['hsf_max'] == P['stateful']['hsf_max']
    assert 'SPX' in d['meta']['schemes']
    for s in d['meta']['schemes']:
        p = d['pools'][s]
        assert p['count'] == len(p['rows']), s
    assert d['pools']['SPX']['considered'] == 34580


def test_data_json_stateless():
    if _missing(DATA_JSON, *CSVS):
        return
    d = _site_data()
    b = FIX['baseline']
    for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
        assert d['baseline'][k] == b[k], k
    p = d['pools']['SPX']
    idx = {f: i for i, f in enumerate(p['fields'])}
    rows = p['rows']
    assert len(rows) == FIX['site_pool_count']
    core_w = set(d['meta']['grid']['w'])
    extra_w = set(d['meta']['w_optional'])
    csv_tuples = {tuple(int(r[x]) for x in 'hdkaw')
                  for r in _csv_rows('all_size_capped_candidates.csv')
                  if r['label'] != 'STANDARD'}
    core_tuples, extra_tuples = set(), {}
    for r in rows:
        t = (r[idx['h']], r[idx['d']], r[idx['k']], r[idx['a']], r[idx['w']])
        if t[4] in core_w:
            core_tuples.add(t)
        else:
            assert t[4] in extra_w, t
            extra_tuples.setdefault(t[4], set()).add(t[:4])
        m = M.spx_metrics(*t)
        got = tuple(r[idx[k]] for k in ('size', 'kg', 'sg', 'sv', 'sv_worst'))
        want = (m['size'], m['kg'], m['sg'], m['sv'], m['sv_worst'])
        assert got == want, (t, got, want)
        assert r[idx['swn']] == 0 and r[idx['mmax']] == 0
    assert core_tuples == csv_tuples
    # Optional-w rows must be exactly the security-pass set (recovered from
    # the unbound sweep CSV — FORS security is w-independent) capped by the
    # same size bound; their per-w counts are pinned in the fixtures.
    sec_pass = {tuple(int(r[x]) for x in 'hdka')
                for r in _csv_rows('all_unbound_candidates.csv')
                if r['label'] != 'STANDARD'}
    max_size = d['meta']['grid']['max_size']
    for w_str, cnt in FIX['optional_pool_counts'].items():
        w = int(w_str)
        expected = {t for t in sec_pass
                    if M.spx_metrics(*t, w)['size'] < max_size}
        assert len(expected) == cnt, (w, len(expected), cnt)
        assert extra_tuples.get(w, set()) == expected, w


def test_sage_preparser_hazards():
    import ast
    import glob
    import io
    import tokenize
    offenders = []
    for path in sorted(glob.glob(os.path.join(ROOT, '*.sage'))):
        name = os.path.basename(path)
        src = open(path, encoding='utf-8').read()
        for lineno, line in enumerate(src.splitlines(), 1):
            if line.endswith('\\'):
                offenders.append(f'{name}:{lineno} backslash continuation')
        try:
            ast.parse(src)
        except SyntaxError as e:
            offenders.append(f'{name}:{e.lineno} {e.msg}')
        try:
            for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                if tok.type == tokenize.NAME and not tok.string.isascii():
                    offenders.append(
                        f'{name}:{tok.start[0]} non-ASCII identifier {tok.string!r}')
        except tokenize.TokenError:
            pass  # unterminated construct — already reported via ast.parse
    assert not offenders, f'sage-file hazards: {offenders}'


def _js_code_chars(src):
    NORMAL, SQ, DQ, TPL, LINE_C, BLOCK_C = range(6)
    state, tpl_depth, line = NORMAL, [], 1
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if c == '\n':
            line += 1
            if state == LINE_C:
                state = NORMAL
            i += 1
            continue
        if state == NORMAL:
            if c == "'":
                state = SQ
            elif c == '"':
                state = DQ
            elif c == '`':
                state = TPL
            elif c == '/' and nxt == '/':
                state = LINE_C; i += 1
            elif c == '/' and nxt == '*':
                state = BLOCK_C; i += 1
            elif c == '}' and tpl_depth and tpl_depth[-1] == 0:
                tpl_depth.pop(); state = TPL
            else:
                if c == '{' and tpl_depth:
                    tpl_depth[-1] += 1
                elif c == '}' and tpl_depth:
                    tpl_depth[-1] -= 1
                yield line, c
        elif state in (SQ, DQ):
            if c == '\\':
                i += 1
            elif c == ("'" if state == SQ else '"'):
                state = NORMAL
        elif state == TPL:
            if c == '\\':
                i += 1
            elif c == '`':
                state = NORMAL
            elif c == '$' and nxt == '{':
                tpl_depth.append(0); state = NORMAL; i += 1
        elif state == BLOCK_C:
            if c == '*' and nxt == '/':
                state = NORMAL; i += 1
        i += 1


def test_site_js_hazards():
    import glob
    offenders = []

    def scan(name, js, base_line):
        for lineno, ch in _js_code_chars(js):
            if not ch.isascii():
                offenders.append(
                    f'{name}:{base_line + lineno - 1} non-ASCII code char {ch!r} (U+{ord(ch):04X})')

    for path in sorted(glob.glob(os.path.join(ROOT, 'site', '*.html'))):
        html = open(path, encoding='utf-8').read()
        for m in re.finditer(r'<script>(.*?)</script>', html, re.S):
            scan(os.path.basename(path), m.group(1), html[:m.start(1)].count('\n') + 1)
    for path in sorted(glob.glob(os.path.join(ROOT, 'site', '*.js')) +
                       glob.glob(os.path.join(ROOT, 'site', 'js', '*.js'))):
        scan(os.path.relpath(path, os.path.join(ROOT, 'site')), open(path, encoding='utf-8').read(), 1)
    assert not offenders, f'site-JS hazards: {offenders}'


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
    assert len(d['uxmss']['rows']) == 12
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
    js = _page_js('stateless.html')
    js += f"""
const data = JSON.parse(require('fs').readFileSync({json.dumps(data_path)}, 'utf8'));
const pool = poolFromData(data, 'SPX');
let ok = pool.length === data.pools.SPX.count;
// the page's optional w set must be the one the dataset was exported with
ok = ok && JSON.stringify(OPTIONAL_W) === JSON.stringify(data.meta.w_optional);
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
    js2 = _page_js('stateful.html')
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


# Sage, if installed

def test_sage_costs():
    if not shutil.which('sage'):
        print('  [skip] sage not available')
        return
    args = ['sage', 'costs.sage', '--params', 'SPX', '64', '14', '12', '63', '7', '16', '0']
    p = subprocess.run(args, capture_output=True, text=True, cwd=ROOT, timeout=600)
    assert p.returncode == 0, p.stderr[:2000]
    b = FIX['baseline']
    assert f"Size:       {b['size']} bytes" in p.stdout, p.stdout
    assert 'Security:   128.0 bits' in p.stdout, p.stdout
    assert 'C/byte:     0.28  (worst: 0.50)' in p.stdout, p.stdout


# A runner without pytest

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
