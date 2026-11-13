"""tests/model.py against tests/fixtures.json: the WOTS chain counts, SLH-DSA-128s,
the stateless and stateful parameter sets, and the report's variants."""
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
