"""A second implementation of the cost model for the regression tests.

Ports model/costs.sage, model/bgs_cc.sage and model/stateful.sage to the Python standard library,
with third_party/octopus_pmf.py for the PORS+FP grinding work. It shares no code with them, so
the tests compare two independent implementations. For BGS-CC it also evaluates the coverage
bound that the parameter sets of third_party/bgs_cc rest on. docs/model.md has the
model, parameters.json the grids and fixed parameters.
"""
import csv
import json
import os
import sys
from fractions import Fraction
from functools import lru_cache
from math import ceil, comb, exp, floor, lgamma, log, log1p, log2

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'third_party'))
from octopus_pmf import interleave_cost_table  # noqa: E402  (pure python, MIT)

with open(os.path.join(ROOT, 'parameters.json')) as _f:
    PARAMETERS = json.load(_f)

# Sizes in bytes
N = 16                       # n
C_SIZE = 4                   # the WOTS+C counter of the stateless variants
R_SIZE = 16                  # the randomizer R
IND_SIZE = 1                 # the SHRINCS indicator byte that starts every signature

# Compressions per hash call (docs/model.md, Hash calls)
C_TH1 = 1; C_TH1C = 1; C_PRF = 1; C_TH2 = 1
C_HMSG = 4
C_PRFMSG = 3

SWN = {int(w): swn for w, swn in PARAMETERS['swn'].items()}   # WOTS+C target digit sums
HSF_MAX = PARAMETERS['stateful']['hsf_max']


def stateless_grid(q_s_log2):
    """The stateless grid at a signature budget: the grid of parameters.json
    with its h range moved along with the budget."""
    grid = dict(PARAMETERS['stateless']['grid'])
    shift = q_s_log2 - grid['q_s_log2']
    grid['h'] = [h + shift for h in grid['h']]
    grid['q_s_log2'] = q_s_log2
    return grid


def compute_th(x):
    """Compressions for a tweakable hash over x hash-sized values (SHA-256)."""
    return ceil((22 * 8 + 128 * x + 65) / 512)


def wots_len1(w):
    return ceil(8 * N / log2(w))


def wots_len(w, wc=False):
    """Chain count: l1 + l2 for WOTS-TW, l1 for WOTS+C (FIPS 205 form)."""
    l1 = wots_len1(w)
    if wc:
        return l1
    l2 = floor(log2(l1 * (w - 1)) / log2(w)) + 1
    return l1 + l2


def wots_worst_steps(w):
    """Chain steps to verify one WOTS-TW signature when every message digit is 0."""
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
    """The base-w digit sum of the WOTS-TW checksum, summed over all w^l1
    message digit strings.

    The checksum l1*(w-1) - S is distributed like S itself, so this weights
    the digit sum of every s by the number of strings that sum to s. costs.sage
    and the site take tail counts P(S >= m*w^j) instead, so the two
    computations are independent.
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
    """Mean chain steps to verify count WOTS-TW signatures of uniform digests,
    rounded once to the nearest integer (ties up): l1*(w-1)/2 + l2*(w-1) minus
    the mean checksum digit sum.
    """
    l1 = wots_len1(w)
    l2 = wots_len(w) - l1
    mean = (Fraction(l1 * (w - 1), 2) + l2 * (w - 1)
            - Fraction(_checksum_digit_sum_total(l1, w), w**l1))
    return floor(count * mean + Fraction(1, 2))


# SLH-DSA (SPX)

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
    # A layer costs a full tree, to sign and to verify. The top tree is never
    # rebuilt: its root is the published public key, so the signature saves
    # one WOTS-TW verification and its h' authentication path there.
    c_top_saved = wots_tw_mean_steps(w, 1) * C_TH1 + thl + hp * C_TH2
    sg = c_fors + (C_HMSG + C_PRFMSG) + d * c_merkle - c_top_saved

    c_fts = k * C_TH1 + k * a * C_TH2 + thk
    c_wots_avg = wots_tw_mean_steps(w, d) * C_TH1 + d * thl     # all d layers
    c_wots_worst = wots_worst_steps(w) * C_TH1 + thl            # one layer
    sv = C_HMSG + c_fts + c_wots_avg + h * C_TH2
    sv_worst = C_HMSG + c_fts + d * c_wots_worst + h * C_TH2

    return {
        'size': size, 'kg': kg, 'sg': sg, 'sv': sv, 'sv_worst': sv_worst,
        'cpb': sv / size, 'cpb_worst': sv_worst / size,
    }


# W+C, W+C_F+C and W+C_P+FP

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


def _nu(l, swn, w):
    """The number of strings of l base-w digits that sum to swn, at least 1."""
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


def _compute_mmax(hp, l, w, swn, d_search, d, k, a):
    """The PORS+FP authentication-set bound, as costs.sage compute_mmax."""
    thl = compute_th(l)
    thk1 = compute_th(k - 1)
    merkle = 2**hp * (l * C_PRF + l * (w - 1) * C_TH1 + thl) + (2**hp - 1) * C_TH2
    # the top layer saves its WOTS+C verification and its h' path, as in sg
    hyper = (d * merkle + d_search * C_TH1C
             - ((w - 1) * l - swn) * C_TH1 - C_TH1C - thl - hp * C_TH2)
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
    """Size, costs (kg, sg, sv, sv_worst, cpb, cpb_worst) and mmax of one
    parameter set of SPX, W+C, W+C_F+C or W+C_P+FP."""
    if scheme == 'SPX':
        m = spx_metrics(h, d, k, a, w)
        m['mmax'] = 0
        return m
    assert h % d == 0
    hp = h // d
    l = wots_len(w, wc=True)
    thl = compute_th(l)
    ctr = C_SIZE

    # WOTS+C grinding: expected attempts, rounded up exactly
    nu = _nu(l, swn, w)
    d_search = d * (-(-(w**l) // nu))

    c_merkle = 2**hp * (l * C_PRF + l * (w - 1) * C_TH1 + thl) + (2**hp - 1) * C_TH2
    # WOTS+C verification is deterministic: worst == average
    c_wots = ((w - 1) * l - swn) * C_TH1 + C_TH1C + thl
    # as in spx_metrics, the top layer saves its verification and h' path
    c_hyper = d * c_merkle + d_search * C_TH1C - c_wots - hp * C_TH2
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
        mmax = _compute_mmax(hp, l, w, swn, d_search, d, k, a)
        fts_size = (k + mmax) * N
        t, sub, extra = _pors_geometry(k, a)
        c_pors = t * C_PRF + t * C_TH1 + ((2**sub - 1) + extra) * C_TH2
        attempts = ceil(2.0 ** _log2_exp_work(t, k, mmax))
        sg = c_hyper + c_pors + attempts * c_msg
        c_fts = k * C_TH1 + mmax * C_TH2
    else:
        raise ValueError(scheme)

    size = d * (hp * N + l * N + ctr) + fts_size + R_SIZE
    sv = C_HMSG + c_fts + d * c_wots + h * C_TH2
    return {'size': size, 'kg': kg, 'sg': sg, 'sv': sv, 'sv_worst': sv,
            'cpb': sv / size, 'cpb_worst': sv / size, 'mmax': mmax}


# XMSS, XMSS-MT and UXMSS, in the SHRINCS stateful signature layout
# (docs/model.md, Stateful schemes)

def _wc(ots):
    return ots == 'WC'


def counter_bytes(w):
    """Bytes of the WOTS+C counter: 2 as in SHRINCS, 4 for w = 65536."""
    return 2 if w <= 256 else 4


def wots_pk_c(w, ots):
    l = wots_len(w, _wc(ots))
    return l * C_PRF + l * (w - 1) * C_TH1 + compute_th(l)


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


# BDS traversal bounds for a tree of height hp (docs/model.md, XMSS and XMSS-MT)

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


def uxmss_metrics(ots, w, target_size=PARAMETERS['stateful']['uxmss_ref_size']):
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


# BGS-CC (docs/model.md, BGS-CC): the few-time signature of ePrint 2026/2502 in
# place of FORS, under the hypertree of SPX or of W+C

BGS_SCHEMES = {'BGS': False, 'W+C_BGS': True}      # scheme -> WOTS+C hypertree
BGS_FTS_FIELDS = ('h', 'K', 'L', 'r', 'b', 'u', 'c', 'E', 'delta')


def bgs_code_size(c, e):
    """Codewords of the constant-sum code: the vectors x with 0 <= x_j <= c_j
    that sum to e (the paper's N)."""
    if any(cap < 0 for cap in c):
        return 0
    counts = [1]
    for cap in c:
        nxt = [0] * (len(counts) + cap)
        for s, n in enumerate(counts):
            for x in range(cap + 1):
                nxt[s + x] += n
        counts = nxt
    return counts[e] if 0 <= e < len(counts) else 0


def bgs_fts_metrics(h, K, L, r, b, u, c, E, delta):
    """Size (bytes) and signing and verification compressions of the BGS-CC
    signature of one configuration at hypertree height h; the height only sets
    how many blocks the encoder reads."""
    assert len(c) == L + 1 and 0 <= E <= sum(c) and 1 <= delta <= 2**32
    t, B, O = 2**L, 2**b, 2**u
    words = bgs_code_size(c, E)**(r * K)        # codeword choices of one encoding
    e_bits = (words - 1).bit_length()           # ceil(log2 words)
    blocks = -(-(32 + h + K * (b + u + r * L) + e_bits) // (8 * N))
    # one owner tree: t sources, their guard chains and leaves, the edge chains
    # and the t - 1 nodes
    owner = t * (c[L] + 3) + sum(2**(d + 1) * c[d] for d in range(L)) - 1
    graph = K * B * ((O + (r - 1) * t) * owner + O) - 1
    # encoder blocks until a counter passes: one per attempt, the other
    # blocks - 1 for the attempts below the threshold
    search = ceil(Fraction(2**e_bits * (2**32 + (blocks - 1) * delta), delta * words))
    return {
        'size': 4 + N * K * (b + u + r * (L + 1)),
        'sg': graph + search,
        'sv': blocks + K * (b + u + r * (E + sum(c[:L]) + L + 1)) + K - 1,
    }


def hypertree_metrics(h, d, w, swn=0):
    """What surrounds the few-time signature: R, the d layers of the hypertree
    and the message hashing. WOTS+C layers with target sum swn, WOTS-TW for
    swn = 0. Adding FORS gives spx_metrics or scheme_metrics('W+C')."""
    assert h % d == 0
    hp = h // d
    wc = swn > 0
    l = wots_len(w, wc)
    thl = compute_th(l)
    merkle = 2**hp * (l * C_PRF + l * (w - 1) * C_TH1 + thl) + (2**hp - 1) * C_TH2
    msg = C_HMSG + C_PRFMSG
    if wc:
        search = d * (-(-(w**l) // _nu(l, swn, w)))
        verify = ((w - 1) * l - swn) * C_TH1 + C_TH1C + thl       # one layer
        size = d * (hp * N + l * N + C_SIZE) + R_SIZE
        sg = msg + d * merkle + search * C_TH1C - verify - hp * C_TH2
        sv = sv_worst = C_HMSG + d * verify + h * C_TH2
    else:
        size = d * (hp * N + l * N) + R_SIZE
        sg = msg + d * merkle - (wots_tw_mean_steps(w, 1) * C_TH1 + thl + hp * C_TH2)
        sv = C_HMSG + wots_tw_mean_steps(w, d) * C_TH1 + d * thl + h * C_TH2
        sv_worst = C_HMSG + d * (wots_worst_steps(w) * C_TH1 + thl) + h * C_TH2
    return {'size': size, 'kg': merkle, 'sg': sg, 'sv': sv, 'sv_worst': sv_worst}


def bgs_metrics(scheme, h, d, w, K, L, r, b, u, c, E, delta):
    """Size and costs of BGS-CC under a hypertree: the two parts add up."""
    ht = hypertree_metrics(h, d, w, SWN[w] if BGS_SCHEMES[scheme] else 0)
    fts = bgs_fts_metrics(h, K, L, r, b, u, c, E, delta)
    m = {k: ht[k] + fts[k] for k in ('size', 'sg', 'sv')}
    m.update(kg=ht['kg'], sv_worst=ht['sv_worst'] + fts['sv'])
    m.update(cpb=m['sv'] / m['size'], cpb_worst=m['sv_worst'] / m['size'])
    return m


def bgs_key(key):
    """'h|K,L,r,b,u|c|E,delta', the few-time configuration of a fixture key,
    as the arguments of bgs_fts_metrics."""
    h, shape, c, tail = key.split('|')
    K, L, r, b, u = (int(x) for x in shape.split(','))
    E, delta = (int(x) for x in tail.split(','))
    return int(h), K, L, r, b, u, [int(x) for x in c.split(',')], E, delta


def bgs_path(q_s_log2=None, ext='.csv'):
    """The file of the BGS-CC search for a signature budget, by default that
    of parameters.json, relative to the repository."""
    q = PARAMETERS['bgs_cc']['q_s_log2'] if q_s_log2 is None else q_s_log2
    return os.path.splitext(PARAMETERS['bgs_cc']['fts'].format(q=q))[0] + ext


def bgs_budgets():
    """The budgets of the stateless page that have a BGS-CC search."""
    return [q for q in PARAMETERS['stateless']['budgets']
            if os.path.exists(os.path.join(ROOT, bgs_path(q)))]


def bgs_fts_rows(q_s_log2=None):
    """The few-time configurations of the search (third_party/bgs_cc), as dicts
    with the BGS_FTS_FIELDS, 'bits', the search's cover bits, and 'trees': per
    scheme the (d, w) of the hypertrees the search kept for the configuration."""
    path = os.path.join(ROOT, bgs_path(q_s_log2))
    rows = []
    with open(path, newline='') as fh:
        for r in csv.DictReader(fh):
            row = {k: int(r[k]) for k in BGS_FTS_FIELDS if k != 'c'}
            row['c'] = [int(x) for x in r['c'].split()]
            row['bits'] = float(r['cover_bits'])
            row['trees'] = {scheme: [tuple(int(x) for x in tree.split('/'))
                                     for tree in r[scheme].split()] for scheme in BGS_SCHEMES}
            rows.append(row)
    return rows


def bgs_search(q_s_log2=None):
    """What the search covered: the .json beside the configurations."""
    with open(os.path.join(ROOT, bgs_path(q_s_log2, '.json'))) as fh:
        return json.load(fh)


def bgs_w(scheme):
    """The w of a BGS-CC scheme's hypertrees: the standard ones of the scheme
    it builds on, then w_optional."""
    stateless = PARAMETERS['stateless']
    standard = stateless['wc_w'] if BGS_SCHEMES[scheme] else stateless['grid']['w']
    return list(standard) + list(stateless['w_optional'])


def bgs_hypertrees(scheme, heights):
    """(h, d, w, swn) of the stateless grid for the heights of the few-time
    configurations: every d of the grid that divides h, and every w of the
    scheme."""
    grid = PARAMETERS['stateless']['grid']
    pairs = [(w, SWN[w] if BGS_SCHEMES[scheme] else 0) for w in bgs_w(scheme)]
    return [(h, d, w, swn) for w, swn in pairs for h in sorted(heights)
            for d in range(grid['d'][0], grid['d'][1] + 1) if h % d == 0]


def bgs_site_data(q_s_log2=None):
    """The bgs_cc section of site/data.json, or of the file of another budget:
    the few-time configurations with their size and costs and, per scheme, the
    hypertrees of their heights and the candidates. A candidate is a
    configuration under one of the hypertrees the search kept for it: 'trees'
    holds, per configuration, their rows."""
    q = PARAMETERS['bgs_cc']['q_s_log2'] if q_s_log2 is None else q_s_log2
    max_size = PARAMETERS['stateless']['grid']['max_size']
    configs = bgs_fts_rows(q)
    search = bgs_search(q)
    assert search['region']['q_s_log2'] == q, (q, search['region'])
    fts_rows = []
    for r in configs:
        m = bgs_fts_metrics(*[r[k] for k in BGS_FTS_FIELDS])
        fts_rows.append([r[k] for k in BGS_FTS_FIELDS] + [r['bits'], m['size'], m['sg'], m['sv']])
    hyper = {}
    for scheme in BGS_SCHEMES:
        rows, row_of = [], {}
        for h, d, w, swn in bgs_hypertrees(scheme, {r['h'] for r in configs}):
            m = hypertree_metrics(h, d, w, swn)
            row_of[h, d, w] = len(rows)
            rows.append([h, d, w, swn, m['size'], m['kg'], m['sg'], m['sv'], m['sv_worst']])
        trees = [[row_of[r['h'], d, w] for d, w in r['trees'][scheme]] for r in configs]
        for fts, ks in zip(fts_rows, trees):
            assert all(fts[-3] + rows[k][4] < max_size for k in ks), fts
        hyper[scheme] = {'fields': ['h', 'd', 'w', 'swn', 'size', 'kg', 'sg', 'sv', 'sv_worst'],
                         'rows': rows, 'count': sum(len(ks) for ks in trees), 'trees': trees}
    return {
        'source': bgs_path(q),
        'q_s_log2': q,
        'search': search,
        'schemes': list(BGS_SCHEMES),
        'fts': {'fields': list(BGS_FTS_FIELDS) + ['bits', 'size', 'sg', 'sv'], 'rows': fts_rows},
        'hypertrees': hyper,
    }


# BGS-CC coverage (docs/model.md, BGS-CC security), in floats. The local
# table is exact; everything after it is a sum of non-negative terms.

def _bgs_local(c, E, m_cut):
    """f[m][v], eqs. (21)-(24) of the paper: the probability that the openings
    a target needs in one owner tree are covered by m signatures that visit
    the tree, v of them at the target's leaf."""
    L = len(c) - 1
    k = L + 1
    words = []

    def walk(prefix, left):
        j = len(prefix)
        if j == k:
            if left == 0:
                words.append(tuple(prefix))
            return
        for x in range(min(c[j], left) + 1):
            walk(prefix + [x], left - x)

    walk([], E)
    n_code = len(words)
    below = {}                                  # bounds -> codewords within them

    def avoid(e, S):                            # A_e(S), eq. (21)
        key = tuple(e[j] - 1 if S >> j & 1 else c[j] for j in range(k))
        if key not in below:
            below[key] = bgs_code_size(key, E)
        return below[key]

    terms = {}                                  # (A, D) -> sum of (-1)^|S|
    for e in words:
        A = [avoid(e, S) for S in range(2**k)]
        for S in range(2**k):
            # D_e(S), eq. (22): a signature that leaves the target's path at
            # depth j opens requirement j, so j is not in S
            D = sum(2**(L - j - 1) * A[S & (2**j - 1)]
                    for j in range(L) if not S >> j & 1)
            sign = -1 if bin(S).count('1') % 2 else 1
            terms[(A[S], D)] = terms.get((A[S], D), 0) + sign
    f = [[0.0] * (m_cut + 1) for _ in range(m_cut + 1)]
    for m in range(1, m_cut + 1):
        for v in range(1, m + 1):
            num = sum(s * a**v * dd**(m - v) for (a, dd), s in terms.items())
            f[m][v] = float(Fraction(num, n_code**(m + 1) * (2**L - 1)**(m - v)))
    return f


def _binomial_rows(n_max, p):
    """rows[n][j] = Pr[Bin(n, p) = j]."""
    rows = [[1.0]]
    for n in range(1, n_max + 1):
        prev = rows[-1] + [0.0]
        rows.append([prev[j] * (1 - p) + (prev[j - 1] * p if j else 0.0)
                     for j in range(n + 1)])
    return rows


def bgs_cover_bits(h, K, L, r, b, u, c, E, delta, q_s_log2, m_cut=24):
    """-log2 of the coverage bound of BGS-CC after 2^q_s_log2 signatures
    (the paper's eq. (28) with the tail of eq. (31)): the probability that one
    encoding attempt is accepted and all its openings are already disclosed."""
    t = 2**L
    f = _bgs_local(c, E, m_cut)
    # signatures per instance: Bin(q_s, theta). For K = 1 an instance is one
    # bucket of one address; for K > 1 the K coordinates share the address.
    x = h + b if K == 1 else h
    q_s = 2**q_s_log2

    def log_choose(q):                          # ln C(q_s, q), without cancellation
        return sum(log(q_s - i) for i in range(q)) - lgamma(q + 1)

    def log_pmf(q):
        return log_choose(q) - x * q * log(2) + (q_s - q) * log1p(-2.0**-x)

    def log_tail(q):                            # Pr[more than q], eq. (31)
        return min(0.0, log_choose(q + 1) - x * (q + 1) * log(2))

    q_max = 8
    while q_max < 160 and log_tail(q_max) > -170 * log(2):
        q_max += 1
    in_owner = _binomial_rows(q_max, 1 / t)     # of n signatures, those at one leaf
    in_first = _binomial_rows(q_max, 1 / 2**u)  # ... those at one initial owner
    cover = [0.0]                               # cover[q] = C(q), Lemma 1
    for q in range(1, q_max + 1):
        # step[j][j2]: j signatures visit the target's owner, the layer is
        # covered and j2 signatures visit the target's next owner, eq. (25)
        step = [None]
        for j in range(1, q + 1):
            row = [0.0] * (q + 1)
            rest = in_owner[q - j]
            for v in range(1, j + 1):
                a = in_owner[j][v] * (f[j][v] if j <= m_cut else 1.0)
                if a:
                    for extra, pr in enumerate(rest):
                        row[v + extra] += a * pr
            step.append(row)
        vec = [0.0] + [1.0] * q
        for _ in range(r):
            vec = [0.0] + [sum(step[j][j2] * vec[j2] for j2 in range(1, q + 1))
                           for j in range(1, q + 1)]
        cover.append(sum(in_first[q][j] * vec[j] for j in range(1, q + 1)))
    if K == 1:
        per_instance = cover
    else:                                       # bucket thinning, eq. (27), then K coordinates
        in_bucket = _binomial_rows(q_max, 1 / 2**b)
        per_instance = [sum(in_bucket[q][j] * cover[j] for j in range(q + 1))**K
                        for q in range(q_max + 1)]
    total = exp(log_tail(q_max)) + sum(exp(log_pmf(q)) * per_instance[q]
                                       for q in range(1, q_max + 1))
    words = bgs_code_size(c, E)**(r * K)
    accept = (delta / 2**32) * words / 2**((words - 1).bit_length())
    return -log2(accept * total)
