"""The site's JavaScript under node: each page's numbers against tests/model.py
and the fixtures, its copies of parameters.json, its loading of site/data.json,
and constructs the pages must avoid. Skipped without node."""
import json
import os
import re

import model as M
from common import FIX, ROOT, DATA_JSON, missing, tuple_of, page_js, run_node


def test_site_explorer():
    js = page_js('stateless.html')
    tuples = [list(tuple_of(k)) for k in FIX['stateless']]
    js += f"""
const _tuples = {json.dumps(tuples)};
const out = {{ metrics: {{}} }};
for (const t of _tuples) {{
  const m = metrics({{h:t[0], d:t[1], k:t[2], a:t[3], w:t[4]}});
  out.metrics[t.join(',')] = [m.size, m.kg, m.sg, m.sv, m.sv_worst];
}}
console.log(JSON.stringify(out));
"""
    out = run_node(js)
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
    js = page_js('stateless.html')
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
    out = run_node(js)
    if out is None:
        return
    assert 0 <= out['h14'] < 1e-3 and 0 <= out['h7'] < 1e-3, out
    assert abs(out['h14_a40'] - 196) < 1e-3, out
    assert abs(out['h28'] - 9.2530) < 1e-3 and abs(out['h35'] - 94.7784) < 1e-3, out
    assert out['ms'] < 5000, out     # about 0.1 s


def test_site_parameters():
    """The JavaScript model's copies of parameters.json, kept so the pages also
    work without data.json."""
    js = page_js('stateless.html') + """
console.log(JSON.stringify({ w: ALLOWED_W, w_optional: OPTIONAL_W, swn: WOTS_C_SWN,
  uxmss_ref_size: UXMSS_TARGET_SIZE, hsf_max: HSF_MAX, slh: SLH, q_s_log2: Q_S_LOG2 }));
"""
    out = run_node(js)
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
    js = page_js('index.html')
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
    out = run_node(js)
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
    js = page_js('stateful.html')
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
    out = run_node(js)
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


def test_site_data_integration():
    """Run both pages' data-loading paths under node against site/data.json."""
    if missing(DATA_JSON):
        return
    data_path = os.path.join(ROOT, 'site', 'data.json')
    # stateless.html: poolFromData must reproduce the pool; STD_M must equal baseline
    js = page_js('stateless.html')
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
    out = run_node(js)
    if out is not None:
        assert out['ok'] and out['n'] == FIX['site_pool_count'], out
    # stateful.html: the page's own self-check must pass on the shipped data
    js2 = page_js('stateful.html')
    js2 += f"""
SITE_DATA = JSON.parse(require('fs').readFileSync({json.dumps(data_path)}, 'utf8'));
const okCheck = selfCheckStateful(SITE_DATA);
const slh = buildSLH().metrics;
const okSlh = slh.size === SITE_DATA.stateful.slh.size && slh.qsLog2 === 64;
console.log(JSON.stringify({{ok: okCheck && okSlh}}));
"""
    out2 = run_node(js2)
    if out2 is not None:
        assert out2['ok'], out2


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
