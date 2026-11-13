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
from fractions import Fraction
from functools import lru_cache
from math import ceil, floor, log2, comb

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from octopus_pmf import interleave_cost_table  # noqa: E402  (pure python, MIT)

N = 16                       # hashbytes (128-bit security level)
C_SIZE = 4                   # WOTS+C grinding counter of the stateless variants (bytes)
R_SIZE = 16                  # message randomness = n bytes
IND_SIZE = 1                 # SHRINCS indicator byte (first byte of every signature)

# Compressions per hash call, with the PK.seed block cached as in costs.sage
C_TH1 = 1; C_TH1C = 1; C_PRF = 1; C_TH2 = 1
# 32-byte message, empty context: H_msg is two nested SHA-256 calls
# (2 + 2 compressions), PRF_msg is HMAC with its key-pad blocks cached (2 + 1).
C_HMSG = 4
C_PRFMSG = 3


SWN = {16: 240, 32: 403, 64: 693, 128: 1206, 256: 2040,
       65536: 262140}   # WOTS+C target chain sums S_{w,n} = floor(l1*(w-1)/2)

HSF_MAX = 255                # FXMSS encodes the node height as a single byte


def compute_th(x):
    """Compressions for a tweakable hash over x hash-sized values (SHA-256)."""
    return ceil((22 * 8 + 128 * x + 65) / 512)


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


def _digit_sum(x, w):
    ds = 0
    while x:
        ds += x % w
        x //= w
    return ds


@lru_cache(maxsize=None)
def _checksum_digit_sum_total(l1, w):
    """Sum, over all w^l1 message digit strings, of the base-w digit sum of the
    WOTS-TW checksum.

    The checksum l1*(w-1) - S has the same distribution as the digit sum S
    itself (map every digit m to w-1-m). The number of strings with sum
    exactly s is counted by inclusion-exclusion and weighted by the digit sum
    of s. costs.sage and the site never form a digit sum: they use
    digit_sum(x) = x - (w-1) * sum_j floor(x / w^j) and tail counts
    P(S >= m*w^j), so the two computations are independent.
    """
    top = l1 * (w - 1)
    binom_l = [comb(l1, j) for j in range(l1 + 1)]

    def count(s):
        return sum((-1)**j * binom_l[j] * comb(s - j * w + l1 - 1, l1 - 1)
                   for j in range(min(l1, s // w) + 1))

    total = 0
    for s in range(top // 2 + 1):        # count(s) == count(top - s)
        c = count(s)
        total += c * _digit_sum(s, w)
        if top - s != s:
            total += c * _digit_sum(top - s, w)
    return total


def wots_tw_mean_steps(w, count=1):
    """Mean chain steps to verify `count` WOTS-TW signatures on random digests,
    rounded to the nearest integer (ties up): l1*(w-1)/2 + l2*(w-1) minus the
    mean checksum digit sum.
    """
    l1 = wots_len1(w)
    l2 = wots_len(w) - l1
    mean = (Fraction(l1 * (w - 1), 2) + l2 * (w - 1)
            - Fraction(_checksum_digit_sum_total(l1, w), w**l1))
    return floor(count * mean + Fraction(1, 2))


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
    c_wots_avg = wots_tw_mean_steps(w, d) * C_TH1 + d * thl     # all d layers
    c_wots_worst = wots_worst_steps(w) * C_TH1 + thl            # one layer
    sv = C_HMSG + c_fts + c_wots_avg + h * C_TH2
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
#
# Signature layout (SHRINCS stateful path), used for every scheme here:
#   indicator (1 B) | R (16 B) | leaf index | WOTS signature | auth path
# A WOTS+C signature starts with its grinding counter.

def _wc(ots):
    return ots == 'WC'


def counter_bytes(w):
    """WOTS+C grinding counter: 2 bytes as in SHRINCS; w = 65536 needs more
    attempts than 2 bytes can count and keeps 4."""
    return 2 if w <= 256 else 4


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
    # WOTS-TW: the signer walks what the verifier does not
    return l * C_PRF + (l * (w - 1) - wots_tw_mean_steps(w)) * C_TH1


def wots_verify_c(w, ots, worst=False, count=1):
    """Compressions to verify `count` WOTS signatures."""
    l = wots_len(w, _wc(ots))
    thl = compute_th(l)
    if _wc(ots):
        return count * (((w - 1) * l - SWN[w]) * C_TH1 + C_TH1C + thl)
    if worst:
        return count * (wots_worst_steps(w) * C_TH1 + thl)
    return wots_tw_mean_steps(w, count) * C_TH1 + count * thl


def idx_bytes(h):
    return max(1, ceil(h / 8))


# BDS traversal bounds (Buchmann-Dahmen-Schneider 2008) for a tree of height hp

def bds_k(hp):
    if hp < 2:
        return hp
    return 2 if hp % 2 == 0 else 3


def bds_leaves(hp):
    return (hp - bds_k(hp)) // 2 + 1


def bds_hashes(hp):
    return 3 * max(0, hp - bds_k(hp) - 1) // 2 + 1


def bds_state_nodes(hp):
    k = bds_k(hp)
    auth, keep, retain = hp, hp // 2, 2**k - k - 1
    treehash = max(0, hp - k) + max(0, hp - k - 1)
    return auth + keep + retain + treehash


def xmssmt_metrics(ots, h, d, w):
    assert h % d == 0
    hp = h // d
    l = wots_len(w, _wc(ots))
    ctr = counter_bytes(w) if _wc(ots) else 0
    size = IND_SIZE + R_SIZE + idx_bytes(h) + d * (ctr + l * N + hp * N)
    pk = wots_pk_c(w, ots)
    kg = 2**hp * pk + (2**hp - 1) * C_TH2
    msg = C_HMSG + C_PRFMSG
    # cached signer: one BDS update per layer and signature (upper bound)
    sg = msg + wots_sign_c(w, ots) + d * (bds_leaves(hp) * pk + bds_hashes(hp) * C_TH2)
    # cold signer: rebuild every tree; the top one only needs its auth path
    sg_cold = msg + d * (kg + wots_sign_c(w, ots)) - pk - hp * C_TH2
    sv = C_HMSG + wots_verify_c(w, ots, False, d) + d * hp * C_TH2
    sv_worst = C_HMSG + wots_verify_c(w, ots, True, d) + d * hp * C_TH2
    state = d * bds_state_nodes(hp) * N + (d - 1) * l * N
    return {'size': size, 'kg': kg, 'sg': sg, 'sg_cold': sg_cold,
            'sv': sv, 'sv_worst': sv_worst, 'state': state}


def uxmss_idx_bytes(depth):
    """Leaf-index width for a leaf at this depth: ceil(min(depth, 64) / 8)."""
    return max(1, -(-min(depth, 64) // 8))


def uxmss_size(q, hsf, w, ots):
    """Size of the q-th UXMSS signature (q = 1 is the first)."""
    l = wots_len(w, _wc(ots))
    ctr = counter_bytes(w) if _wc(ots) else 0
    depth = min(q, hsf)
    return IND_SIZE + R_SIZE + uxmss_idx_bytes(depth) + ctr + l * N + depth * N


def uxmss_find_hsf(w, ots, target_size):
    """Largest hsf <= HSF_MAX whose largest signature is below target_size."""
    hsf = HSF_MAX
    while hsf > 0 and uxmss_size(hsf, hsf, w, ots) >= target_size:
        hsf -= 1
    return hsf


def uxmss_sign_c(q, hsf, w, ots):
    """Cached signer (hsf + 1 leaf public keys kept), q-th signature: the spine
    sibling of the signing leaf is recombined with hsf - q node hashes."""
    return (C_HMSG + C_PRFMSG + wots_sign_c(w, ots)
            + (hsf - min(q, hsf)) * C_TH2)


def uxmss_verify_c(q, hsf, w, ots, worst=False):
    return C_HMSG + wots_verify_c(w, ots, worst) + min(q, hsf) * C_TH2


def uxmss_metrics(ots, w, target_size=5712):
    hsf = uxmss_find_hsf(w, ots, target_size)
    sg = uxmss_sign_c(1, hsf, w, ots)                 # first signature: the worst
    return {
        'hsf': hsf,
        'sz_q1': uxmss_size(1, hsf, w, ots),
        'sz_max': uxmss_size(hsf, hsf, w, ots),
        'kg': (hsf + 1) * wots_pk_c(w, ots) + hsf * C_TH2,
        'sg': sg,
        'sg_cold': sg + hsf * wots_pk_c(w, ots),      # rebuild the other hsf leaves
        'sv_max': uxmss_verify_c(hsf, hsf, w, ots, False),
        'sv_max_worst': uxmss_verify_c(hsf, hsf, w, ots, True),
        'state': (hsf + 1) * N,
    }
