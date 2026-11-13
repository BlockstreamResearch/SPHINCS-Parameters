"""The generated files, the sweep CSVs and site/data.json, against tests/model.py
and the fixtures. Without them (make generate) these tests are skipped, or fail
with GENERATED_REQUIRED=1."""
import model as M
from common import FIX, CSVS, DATA_JSON, missing, csv_rows, site_data


def test_csv_row_counts():
    if missing(*CSVS):
        return
    for name, expected in FIX['csv_rows'].items():
        assert len(csv_rows(name)) == expected, name


def test_csv_full_consistency():
    """Every row of both sweep CSVs must match the reference model exactly."""
    if missing(*CSVS):
        return
    for name in FIX['csv_rows']:
        for r in csv_rows(name):
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
    if missing(CSVS[0]):
        return
    std = [r for r in csv_rows('all_size_capped_candidates.csv')
           if r['label'] == 'STANDARD']
    assert len(std) == 1
    assert int(std[0]['size']) == FIX['baseline']['size']


def test_data_json_meta():
    if missing(DATA_JSON):
        return
    d = site_data()
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
    if missing(DATA_JSON, *CSVS):
        return
    d = site_data()
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
                  for r in csv_rows('all_size_capped_candidates.csv')
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
                for r in csv_rows('all_unbound_candidates.csv')
                if r['label'] != 'STANDARD'}
    max_size = d['meta']['grid']['max_size']
    for w_str, cnt in FIX['optional_pool_counts'].items():
        w = int(w_str)
        expected = {t for t in sec_pass
                    if M.spx_metrics(*t, w)['size'] < max_size}
        assert len(expected) == cnt, (w, len(expected), cnt)
        assert extra_tuples.get(w, set()) == expected, w


def test_data_json_variant_pools():
    if missing(DATA_JSON):
        return
    d = site_data()
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
    if missing(DATA_JSON):
        return
    d = site_data()['stateful']
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
