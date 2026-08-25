"""Independent reference model for the regression tests.

Ports the cost formulas of costs.sage (all schemes) and stateful.sage using
only the Python standard library (plus the repo's octopus_pmf, itself pure
Python, for PORS+FP grinding work). Written during the 2026-07-05 audit and
verified against the sage scripts, both site pages, and the published CSVs.

Deliberately does NOT reuse any sage code: its value is being a second,
independent implementation that the real code is diffed against.
"""
import os
import sys
from math import ceil, floor, log2, comb

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from octopus_pmf import interleave_cost_table  # noqa: E402  (pure python, MIT)

N = 16                       # hashbytes (128-bit security level)
C_SIZE = 4                   # WOTS+C grinding counter (bytes)
R_SIZE = 16                  # message randomness = n bytes

# Hash-cost convention, mirroring costs.sage
CONVENTION = os.environ.get('HASH_CONVENTION', 'cached').lower()

C_TH1 = 1; C_TH1C = 1; C_HMSG = 2; C_PRFMSG = 2; C_PRF = 1
C_TH2 = 1 if CONVENTION == 'cached' else 2


def set_convention(mode):
    """Switch the active convention at runtime (used by the tests)."""
    global CONVENTION, C_TH2
    assert mode in ('cached', 'uncached'), mode
    CONVENTION = mode
    C_TH2 = 1 if mode == 'cached' else 2


SWN = {16: 240, 32: 403, 64: 693, 128: 1206, 256: 2040,
       65536: 262140}   # WOTS+C target chain sums S_{w,n} = floor(l1*(w-1)/2)

HSF_MAX = 255                # FXMSS encodes the node height as a single byte


def compute_th(x):
    """Compressions for a tweakable hash over x hash-sized values (SHA-256)."""
    if CONVENTION == 'cached':
        return ceil((22 * 8 + 128 * x + 65) / 512)
    return ceil((128 + 96 + 128 * x + 65) / 512)


def wots_len1(w):
    return ceil(8 * N / log2(w))


def wots_len(w, wc=False):
    """Chain count: l1 + l2 for WOTS-TW/classic, l1 for WOTS+C (FIPS 205 form)."""
    l1 = wots_len1(w)
    if wc:
        return l1
    l2 = floor(log2(l1 * (w - 1)) / log2(w)) + 1
    return l1 + l2


def wots_worst_steps(w):
    """Worst-case WOTS-TW verification chain steps (all message digits 0)."""
    l1 = wots_len1(w)
    l2 = floor(log2(l1 * (w - 1)) / log2(w)) + 1
    c = l1 * (w - 1)
    ds, rem = 0, c
    while rem:
        ds += rem % w
        rem //= w
    return l1 * (w - 1) + l2 * (w - 1) - ds


# ---------------------------------------------------------------------------
# Stateless: SLH-DSA / SPX (plain WOTS-TW + FORS), matches costs.sage
# ---------------------------------------------------------------------------

def spx_metrics(h, d, k, a, w):
    assert h % d == 0
    hp = h // d
    l = wots_len(w)
    thl = compute_th(l)
    thk = compute_th(k)

    size = N * (1 + k * (a + 1) + h + d * l)

    c_merkle = 2**hp * (l * C_PRF + l * (w - 1) * C_TH1 + thl) + (2**hp - 1) * C_TH2
    kg = c_merkle

    c_fors = (k * 2**a * C_PRF + k * 2**a * C_TH1
              + k * (2**a - 1) * C_TH2 + thk)
    sg = c_fors + (C_HMSG + C_PRFMSG) + d * c_merkle

    c_fts = k * C_TH1 + k * a * C_TH2 + thk
    c_wots_avg = (w - 1) * l // 2 * C_TH1 + thl
    c_wots_worst = wots_worst_steps(w) * C_TH1 + thl
    sv = C_HMSG + c_fts + d * c_wots_avg + h * C_TH2
    sv_worst = C_HMSG + c_fts + d * c_wots_worst + h * C_TH2

    return {
        'size': size, 'kg': kg, 'sg': sg, 'sv': sv, 'sv_worst': sv_worst,
        'cpb': sv / size, 'cpb_worst': sv_worst / size,
    }


# ---------------------------------------------------------------------------
# Stateless variants: W+C, W+C_F+C, W+C_P+FP — matches costs.sage
# ---------------------------------------------------------------------------

_INTERLEAVE_CACHE = {}


def _log2_exp_work(t, k, mmax):
    key = (t, k)
    table = _INTERLEAVE_CACHE.get(key)
    if table is None:
        table = dict(interleave_cost_table(t, k))
        _INTERLEAVE_CACHE[key] = table
    if mmax in table:
        return table[mmax]
    lowers = [m for m in table if m <= mmax]
    if not lowers:
        raise ValueError('mmax below supported range')
    return table[max(lowers)]


def _nu_int(l, swn, w):
    nu = 0
    for j in range(l + 1):
        n_val = (swn + l) - j * w - 1
        b2 = comb(n_val, l - 1) if n_val >= l - 1 else 0
        nu += (-1)**j * comb(l, j) * b2
    return nu if nu > 0 else 1


def _pors_geometry(k, a):
    t = k * 2**a
    sub = floor(log2(t))
    return t, sub, t - 2**sub


def _compute_mmax(hp, l, w, d_search, d, k, a):
    """Port of costs.sage compute_mmax (PORS+FP grinding budget)."""
    thl = compute_th(l)
    thk1 = compute_th(k - 1)
    merkle = 2**hp * (l * C_PRF + l * (w - 1) * C_TH1 + thl) + (2**hp - 1) * C_TH2
    hyper = d * merkle + d_search * C_TH1C
    fors_c_fixed = ((k - 1) * 2**a * C_PRF + (k - 1) * 2**a * C_TH1
                    + (k - 1) * (2**a - 1) * C_TH2 + thk1)
    fors_c_search = 2**a * (C_HMSG + C_PRFMSG)
    spx_fc = hyper + fors_c_fixed + fors_c_search
    t, sub, extra = _pors_geometry(k, a)
    pors_fixed = t * C_PRF + t * C_TH1 + ((2**sub - 1) + extra) * C_TH2
    mmax = (k - 1) * a - ceil(350 / N)
    for i in range(20):
        attempts = ceil(2.0 ** _log2_exp_work(t, k, mmax))
        spx_pors = hyper + pors_fixed + attempts * (C_HMSG + C_PRFMSG)
        if spx_pors / spx_fc < 1.11 or i == 19:
            return mmax
        mmax += 1
    return mmax


def scheme_metrics(scheme, h, d, k, a, w, swn=0):
    """Metrics for any costs.sage scheme: SPX, W+C, W+C_F+C, W+C_P+FP.

    Returns dict with size/kg/sg/sv/sv_worst/mmax. Mirrors costs.sage
    compute_size / compute_keygen_time / compute_signing_time /
    compute_verification_time exactly (expected-cost outputs only).
    """
    if scheme == 'SPX':
        m = spx_metrics(h, d, k, a, w)
        m['mmax'] = 0
        return m
    assert h % d == 0
    hp = h // d
    l = wots_len(w, wc=True)
    thl = compute_th(l)
    ctr = C_SIZE

    # WOTS+C grinding: expected search attempts (exact integer ceil)
    nu = _nu_int(l, swn, w)
    d_search = d * (-(-(w**l) // nu))

    c_merkle = 2**hp * (l * C_PRF + l * (w - 1) * C_TH1 + thl) + (2**hp - 1) * C_TH2
    c_hyper = d * c_merkle + d_search * C_TH1C
    c_msg = C_HMSG + C_PRFMSG
    kg = c_merkle

    mmax = 0
    if scheme == 'W+C':
        fts_size = k * N + k * a * N
        c_fors = (k * 2**a * C_PRF + k * 2**a * C_TH1
                  + k * (2**a - 1) * C_TH2 + compute_th(k))
        sg = c_fors + c_msg + c_hyper
        c_fts = k * C_TH1 + k * a * C_TH2 + compute_th(k)
    elif scheme == 'W+C_F+C':
        fts_size = (k - 1) * N + (k - 1) * a * N
        c_fors = ((k - 1) * 2**a * C_PRF + (k - 1) * 2**a * C_TH1
                  + (k - 1) * (2**a - 1) * C_TH2 + compute_th(k - 1))
        sg = c_hyper + c_fors + 2**a * c_msg
        c_fts = (k - 1) * C_TH1 + (k - 1) * a * C_TH2 + compute_th(k - 1)
    elif scheme == 'W+C_P+FP':
        mmax = _compute_mmax(hp, l, w, d_search, d, k, a)
        fts_size = (k + mmax) * N
        t, sub, extra = _pors_geometry(k, a)
        c_pors = t * C_PRF + t * C_TH1 + ((2**sub - 1) + extra) * C_TH2
        attempts = ceil(2.0 ** _log2_exp_work(t, k, mmax))
        sg = c_hyper + c_pors + attempts * c_msg
        c_fts = k * C_TH1 + mmax * C_TH2
    else:
        raise ValueError(scheme)

    size = d * (hp * N + l * N + ctr) + fts_size + R_SIZE
    # WOTS+C verification is deterministic: worst == average
    c_wots = ((w - 1) * l - swn) * C_TH1 + C_TH1C + thl
    sv = C_HMSG + c_fts + d * c_wots + h * C_TH2
    return {'size': size, 'kg': kg, 'sg': sg, 'sv': sv, 'sv_worst': sv,
            'cpb': sv / size, 'cpb_worst': sv / size, 'mmax': mmax}


# ---------------------------------------------------------------------------
# Stateful: XMSS / XMSS-MT / UXMSS, matches stateful.sage (R = n = 16 B)
# ---------------------------------------------------------------------------

def _wc(ots):
    return ots == 'WC'


def wots_pk_c(w, ots):
    l = wots_len(w, _wc(ots))
    return l * C_PRF + l * (w - 1) * C_TH1 + compute_th(l)


def _nu(l, swn, w):
    """Number of valid WOTS+C encodings with digit sum exactly swn."""
    nu = 0
    for j in range(l + 1):
        n_val = (swn + l) - j * w - 1
        b2 = comb(n_val, l - 1) if n_val >= l - 1 else 0
        nu += (-1)**j * comb(l, j) * b2
    return nu if nu > 0 else 1


def wots_sign_c(w, ots):
    l = wots_len(w, _wc(ots))
    if _wc(ots):
        swn = SWN[w]
        nu = _nu(l, swn, w)
        search = -(-(w**l) // nu)          # ceil division, exact integers
        return search * C_TH1C + l * C_PRF + swn * C_TH1
    return l * C_PRF + l * (w - 1) // 2 * C_TH1


def wots_verify_c(w, ots, worst=False):
    l = wots_len(w, _wc(ots))
    thl = compute_th(l)
    if _wc(ots):
        return ((w - 1) * l - SWN[w]) * C_TH1 + C_TH1C + thl
    if worst:
        return wots_worst_steps(w) * C_TH1 + thl
    return l * (w - 1) // 2 * C_TH1 + thl


def idx_bytes(h):
    return max(1, ceil(h / 8))


def xmssmt_metrics(ots, h, d, w):
    assert h % d == 0
    hp = h // d
    l = wots_len(w, _wc(ots))
    ctr = C_SIZE if _wc(ots) else 0
    size = R_SIZE + d * (hp * N + l * N + ctr) + idx_bytes(h)
    pk = wots_pk_c(w, ots)
    kg = 2**hp * pk + (2**hp - 1) * C_TH2
    sg = C_HMSG + C_PRFMSG + wots_sign_c(w, ots) + d * (hp * pk + hp * C_TH2)
    sg_cold = C_HMSG + C_PRFMSG + d * (kg + wots_sign_c(w, ots)) - pk
    sv = C_HMSG + d * (wots_verify_c(w, ots, False) + hp * C_TH2)
    sv_worst = C_HMSG + d * (wots_verify_c(w, ots, True) + hp * C_TH2)
    state = d * ceil(3.5 * hp) * N + (d - 1) * l * N
    return {'size': size, 'kg': kg, 'sg': sg, 'sg_cold': sg_cold,
            'sv': sv, 'sv_worst': sv_worst, 'state': state}


def uxmss_idx_bytes(hsf):
    if hsf <= 0:
        return 1
    return max(1, ceil(log2(hsf + 1) / 8))


def uxmss_find_hsf(w, ots, target_size):
    l = wots_len(w, _wc(ots))
    ctr = C_SIZE if _wc(ots) else 0
    hsf = 0
    for _ in range(64):
        avail = target_size - 1 - R_SIZE - ctr - l * N - uxmss_idx_bytes(hsf)
        new = max(0, min(avail // N, HSF_MAX))
        if new == hsf:
            return hsf
        hsf = new
    return hsf


def uxmss_metrics(ots, w, target_size=5712):
    hsf = uxmss_find_hsf(w, ots, target_size)
    l = wots_len(w, _wc(ots))
    ctr = C_SIZE if _wc(ots) else 0

    def size(q):
        return R_SIZE + ctr + l * N + min(q, hsf) * N + uxmss_idx_bytes(hsf)

    kg = (hsf + 1) * wots_pk_c(w, ots) + hsf * C_TH2
    sg = C_HMSG + C_PRFMSG + wots_sign_c(w, ots)
    sg_cold = sg + hsf * wots_pk_c(w, ots) + hsf * C_TH2
    return {
        'hsf': hsf,
        'sz_q1': size(1),
        'sz_max': size(hsf),
        'kg': kg,
        'sg': sg,
        'sg_cold': sg_cold,
        'sv_max': C_HMSG + wots_verify_c(w, ots, False) + hsf * C_TH2,
        'sv_max_worst': C_HMSG + wots_verify_c(w, ots, True) + hsf * C_TH2,
        'state': (hsf + 1) * N, 
    }
