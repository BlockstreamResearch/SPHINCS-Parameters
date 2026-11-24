"""tests/model.py against tests/fixtures.json: the WOTS chain counts, SLH-DSA-128s,
the stateless and stateful parameter sets, the report's variants, and BGS-CC
against the tables of its paper."""
from math import floor

import model as M
from common import FIX, tuple_of


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
        m = M.spx_metrics(*tuple_of(key))
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


def test_variant_fixtures():
    """Frozen values from a real `sage costs.sage` run vs the reference model."""
    for key, f in FIX['variants'].items():
        scheme, rest = key.split('|')
        h, d, k, a, w, swn = (int(x) for x in rest.split(','))
        m = M.scheme_metrics(scheme, h, d, k, a, w, swn)
        for fld in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
            assert m[fld] == f[fld], (key, fld, m[fld], f[fld])


def test_bgs_fixtures():
    """BGS-CC under both hypertrees; the first two sets are frozen from a real
    `sage model/bgs_cc.sage` run."""
    for key, f in FIX['bgs'].items():
        scheme, dw, cfg = key.split('|', 2)
        d, w = (int(x) for x in dw.split(','))
        h, *fts = M.bgs_key(cfg)
        m = M.bgs_metrics(scheme, h, d, w, *fts)
        for fld in ('size', 'kg', 'sg', 'sv', 'sv_worst'):
            assert m[fld] == f[fld], (key, fld, m[fld], f[fld])


def test_bgs_paper():
    """The few-time part and its coverage bound against the paper's tables."""
    for key, f in FIX['bgs_paper'].items():
        if key == '_about':
            continue
        m = M.bgs_fts_metrics(*M.bgs_key(key))
        for fld in ('size', 'sg', 'sv'):
            assert m[fld] == f[fld], (f['set'], fld, m[fld], f[fld])
        if 'bits' in f:
            bits = M.bgs_cover_bits(*M.bgs_key(key), f['q_s_log2'])
            assert floor(bits * 1000) / 1000 == f['bits'], (f['set'], bits, f['bits'])


def test_bgs_hypertree_with_fors():
    """What surrounds the few-time signature, with FORS added, is the SPX and
    W+C of the other tests."""
    def fors(k, a):
        return {'size': k * (a + 1) * M.N,
                'sg': k * 2**a * (M.C_PRF + M.C_TH1) + k * (2**a - 1) * M.C_TH2 + M.compute_th(k),
                'sv': k * M.C_TH1 + k * a * M.C_TH2 + M.compute_th(k)}

    cases = [('SPX',) + tuple_of(key) + (0,) for key in FIX['stateless']]
    for key in FIX['variants']:
        scheme, rest = key.split('|')
        if scheme == 'W+C':
            cases.append((scheme,) + tuple_of(rest))
    for scheme, h, d, k, a, w, swn in cases:
        ht, f, m = M.hypertree_metrics(h, d, w, swn), fors(k, a), M.scheme_metrics(scheme, h, d, k, a, w, swn)
        got = (ht['size'] + f['size'], ht['kg'], ht['sg'] + f['sg'], ht['sv'] + f['sv'],
               ht['sv_worst'] + f['sv'])
        want = (m['size'], m['kg'], m['sg'], m['sv'], m['sv_worst'])
        assert got == want, ((scheme, h, d, k, a, w, swn), got, want)


def test_bgs_cover_bits():
    """third_party/bgs_cc: every configuration is at the security target by
    its own search and comes with hypertrees of the grid, and a sample of the
    cover bits is re-evaluated here."""
    rows = M.bgs_fts_rows()
    assert len(rows) == FIX['bgs_fts_count'], len(rows)
    grid = M.PARAMETERS['stateless']['grid']
    bits = {}
    for r in rows:
        assert r['bits'] >= M.PARAMETERS['security_bits'], r
        key = tuple(tuple(r[k]) if k == 'c' else r[k] for k in M.BGS_FTS_FIELDS)
        assert key not in bits, key
        bits[key] = r['bits']
        assert any(r['trees'].values()), r
        for scheme, trees in r['trees'].items():
            assert len(set(trees)) == len(trees), r
            for d, w in trees:
                assert r['h'] % d == 0 and grid['d'][0] <= d <= grid['d'][1], (r, d)
                assert w in M.bgs_w(scheme), (r, scheme, w)
    search = M.bgs_search()
    assert search['sets'] == len(rows), search['sets']
    assert search['candidates'] == {scheme: sum(len(r['trees'][scheme]) for r in rows)
                                    for scheme in M.BGS_SCHEMES}, search['candidates']
    assert (search['region']['q_s_log2'], search['region']['security_bits'],
            search['region']['max_size']) == (M.PARAMETERS['bgs_cc']['q_s_log2'],
                                              M.PARAMETERS['security_bits'], grid['max_size'])
    q_s_log2 = M.PARAMETERS['bgs_cc']['q_s_log2']
    for key, want in FIX['bgs_cover_bits'].items():
        cfg = M.bgs_key(key)
        assert bits[cfg[:6] + (tuple(cfg[6]),) + cfg[7:]] == want, key
        here = M.bgs_cover_bits(*cfg, q_s_log2)
        assert abs(here - want) < 6e-4, (key, here, want)    # the file rounds to 0.001
