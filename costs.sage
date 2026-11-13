#!/usr/bin/env sage
"""
Sizes in bytes and costs in SHA-256 compressions of SLH-DSA (SPX) and the
report's variants W+C, W+C_F+C and W+C_P+FP for (h, d, k, a, w), and the sweep
that slhdsa-2to40.sage and export_site_data.sage share. docs/model.md has the
model; PARAMETER_SETS holds the parameter sets of the report's tables.

  sage costs.sage [--table [log2 q_s]]   (those sets as CSV, or as tables)
  sage costs.sage --params scheme log2_q_s k a h d w swn
"""

from sage.all import *
from functools import lru_cache
import json
import os

from octopus_pmf import interleave_cost_table

_dir = os.path.dirname(os.path.abspath(__file__))
load(os.path.join(_dir, "security.sage"))

# Search grids and fixed parameters. Integers become Sage Integers, as if they
# were written in this file.
def _sage_numbers(x):
    if isinstance(x, bool):
        return x
    if isinstance(x, int):
        return Integer(x)
    if isinstance(x, list):
        return [_sage_numbers(v) for v in x]
    if isinstance(x, dict):
        return {key: _sage_numbers(v) for key, v in x.items()}
    return x

with open(os.path.join(_dir, "parameters.json")) as _f:
    PARAMETERS = _sage_numbers(json.load(_f))
SWN = {Integer(w): swn for w, swn in PARAMETERS['swn'].items()}   # WOTS+C target digit sum per w

# Sizes in bytes

hashbytes = 16         # n
counter_size = 4       # the WOTS+C counter of the stateless variants
randomness_size = 16   # the randomizer R

# Compressions per hash call: SHA-256 as SHRINCS (github.com/SHRINCS/shrincs-bip)
# runs it, with the PK.seed block compressed once per key (docs/model.md, Hash calls)

C_Th1 = 1     # tweakable hash of one value: a chain step or a leaf
C_Th1c = 1    # tweakable hash of one value and the WOTS+C counter
C_Th2 = 1     # tweakable hash of two values: a tree node
C_PRF = 1     # PRF of an address with SK.seed
C_Hmsg = 4    # for a 32-byte message and an empty context
C_PRFmsg = 3

def compute_Th(m):
    """Compressions for a tweakable hash of m values: a 22-byte address, the
    values and the SHA-256 padding."""
    return ceil((22*8 + 128*m + 65)/512)

# The parameter sets of the report's tables, in their order:
# (scheme, log2 q_s, h, d, a, k, w, l, S_wn, bold), bold for the rows the
# report highlights. The code computes l again from w.
PARAMETER_SETS = [
    # Table 1: 2^64 signatures (SPX)
    ("SPX", 64, 63, 7, 12, 14, 16, 35, 0, True),

    # Table 1: 2^40 signatures
    # W+C (5 rows)
    ("W+C", 40, 44, 4, 16, 8, 16, 32, 240, False),
    ("W+C", 40, 44, 4, 16, 8, 16, 32, 304, False),
    ("W+C", 40, 44, 4, 16, 8, 256, 16, 2040, False),
    ("W+C", 40, 40, 5, 14, 11, 256, 16, 2040, False),
    ("W+C", 40, 40, 5, 14, 11, 256, 16, 2840, False),
    # W+C F+C (2 rows)
    ("W+C_F+C", 40, 44, 4, 16, 8, 16, 32, 240, False),
    ("W+C_F+C", 40, 40, 5, 14, 11, 256, 16, 2040, True),
    # W+C P+FP (2 rows)
    ("W+C_P+FP", 40, 44, 4, 16, 8, 16, 32, 240, False),
    ("W+C_P+FP", 40, 40, 5, 14, 11, 256, 16, 2040, True),

    # Table 1: 2^30 signatures
    # W+C (6 rows)
    ("W+C", 30, 36, 3, 14, 9, 16, 32, 240, False),
    ("W+C", 30, 33, 3, 15, 9, 16, 32, 240, False),
    ("W+C", 30, 33, 3, 15, 9, 16, 32, 304, False),
    ("W+C", 30, 33, 3, 15, 9, 256, 16, 2040, False),
    ("W+C", 30, 32, 4, 14, 10, 256, 16, 2040, False),
    ("W+C", 30, 32, 4, 14, 10, 256, 16, 2840, False),
    # W+C F+C (4 rows)
    ("W+C_F+C", 30, 36, 3, 14, 9, 16, 32, 240, False),
    ("W+C_F+C", 30, 33, 3, 15, 9, 16, 32, 240, False),
    ("W+C_F+C", 30, 33, 3, 15, 9, 256, 16, 2040, False),
    ("W+C_F+C", 30, 32, 4, 14, 10, 256, 16, 2040, True),
    # W+C P+FP (3 rows)
    ("W+C_P+FP", 30, 36, 3, 14, 9, 16, 32, 240, False),
    ("W+C_P+FP", 30, 33, 3, 15, 9, 16, 32, 240, False),
    ("W+C_P+FP", 30, 32, 4, 14, 10, 256, 16, 2040, True),

    # Table 2: 2^20 signatures (grouped by h)
    # h=24
    ("W+C", 20, 24, 2, 16, 8, 16, 32, 240, False),
    ("W+C", 20, 24, 2, 16, 8, 256, 16, 2040, False),
    ("W+C_F+C", 20, 24, 2, 16, 8, 16, 32, 240, False),
    ("W+C_P+FP", 20, 24, 2, 16, 8, 16, 32, 240, False),
    # h=20
    ("W+C", 20, 20, 2, 15, 10, 256, 16, 2040, False),
    ("W+C_F+C", 20, 20, 2, 15, 10, 256, 16, 2040, False),
    ("W+C_P+FP", 20, 20, 2, 15, 10, 256, 16, 2040, False),
]

# WOTS

@lru_cache(maxsize=None)   # the symbolic logs are slow, and w takes few values
def wots_lengths(w):
    """(l1, l2): the message and checksum chains of WOTS-TW (FIPS 205,
    Section 5). l1 rounds up, so for w = 32 the 26 chains carry 130 bits."""
    l1 = ceil(hashbytes*8/log(w, 2))
    l2 = floor(log(l1*(w-1), 2)/log(w, 2)) + 1
    return l1, l2

def compute_wots_l(scheme, w):
    """Number of WOTS chains: l1 + l2 for WOTS-TW (SPX), l1 for WOTS+C,
    which grinds a counter instead of signing a checksum."""
    l1, l2 = wots_lengths(w)
    return l1 + l2 if scheme == "SPX" else l1

def compute_wots_tw_worst_steps(l1, l2, w):
    """Chain steps to verify one WOTS-TW signature in the worst case, when
    every message digit is 0 (docs/model.md, WOTS-TW verification)."""
    C = l1 * (w - 1)
    ds, rem = 0, int(C)
    while rem > 0:
        ds += rem % int(w)
        rem //= int(w)
    return int(l1) * (int(w) - 1) + int(l2) * (int(w) - 1) - ds

def _round_div(num, den):
    """Nearest integer to num/den for non-negative integers (ties round up)."""
    return (2*num + den) // (2*den)

_wots_tw_floor_cache = {}

def _wots_tw_floor_sum(l1, l2, w):
    """w^l1 * sum_{j=1}^{l2-1} E[floor(S / w^j)] as an exact integer, S the sum
    of l1 uniform base-w digits (docs/model.md, WOTS-TW verification)."""
    l1, l2, w = int(l1), int(l2), int(w)
    key = (l1, l2, w)
    if key in _wots_tw_floor_cache:
        return _wots_tw_floor_cache[key]
    top = l1 * (w - 1)
    W = w**l1

    def count_le(t):
        total = 0
        for i in range(min(l1, t // w) + 1):
            total += (-1)**i * binomial(l1, i) * binomial(t - i*w + l1, l1)
        return total

    acc = 0
    for j in range(1, l2):
        step = w**j
        for m in range(1, top // step + 1):
            acc += W - count_le(m*step - 1)
    _wots_tw_floor_cache[key] = acc
    return acc

def compute_wots_tw_mean_steps(l1, l2, w, count=1):
    """Mean chain steps to verify count WOTS-TW signatures of uniform digests,
    rounded once to the nearest integer (docs/model.md, WOTS-TW verification)."""
    W = int(w)**int(l1)
    T = _wots_tw_floor_sum(l1, l2, w)
    return _round_div(count * (w - 1) * (l2*W + T), W)   # count*(w-1)*(l2 + T/W)

def compute_nu(l: int, paramsum: int, w: int) -> int:
    """ν, the number of strings of l base-w digits that sum to paramsum
    (docs/model.md, WOTS+C). 1, with a warning, where there are none."""
    nu = 0
    for j in range(l + 1):
        sign = (-1) ** j
        binom1 = binomial(l, j)
        n = (paramsum + l) - j * w - 1
        binom2 = binomial(n, l - 1) if n >= l - 1 and l - 1 >= 0 else 0
        nu += sign * binom1 * binom2
    if nu == 0:
        print(f"Warning: ν computed as zero for l={l}, paramsum={paramsum}, w={w}. This may lead to division by zero.")
        nu = 1  # Avoid division by zero
    return nu

# PORS+FP

def compute_pors_tree_geometry(k, a):
    """(t, subtree_height, extra_leaves) of the PORS+FP tree: its t = k*2^a
    leaves, the height of its largest complete subtree, and the leaves
    outside that subtree."""
    t = k * (2**a)
    subtree_height = floor(log(t, 2))
    extra_leaves = t - 2**subtree_height
    return t, subtree_height, extra_leaves

_interleave_table_cache = {}

def log2_exp_work_from_mmax(t, k, mmax):
    """log2 of the expected attempts for PORS+FP grinding to an authentication
    set of at most mmax nodes. The (t, k) tables are cached: a sweep asks for
    the same (k, a) at every (h, d), and compute_mmax for several mmax."""
    key = (int(t), int(k))
    table = _interleave_table_cache.get(key)
    if table is None:
        table = dict(interleave_cost_table(*key))
        _interleave_table_cache[key] = table
    if mmax in table:
        return table[mmax]
    lowers = [m for m in table if m <= mmax]
    if not lowers:
        raise ValueError("mmax below supported range for these (t,k).")
    return table[max(lowers)]

def exp_work_from_mmax(t, k, mmax):
    """Expected attempts for PORS+FP grinding to at most mmax nodes."""
    return 2.0 ** log2_exp_work_from_mmax(t, k, mmax)

# Sizes and costs (docs/model.md, SLH-DSA)

def compute_size(h, d, a, k, w, scheme, mmax=0):
    """Signature size in bytes: R, then per layer the authentication path, the
    WOTS signature and, for WOTS+C, the counter, then the FORS, FORS+C or
    PORS+FP signature; mmax bounds the PORS+FP authentication set."""
    assert h % d == 0, "h must be divisible by d"
    has_wc = (scheme != "SPX")
    l = compute_wots_l(scheme, w)
    h_prime = h // d
    hyper_tree_size = d*(h_prime*hashbytes + l*hashbytes + counter_size*int(has_wc))
    if scheme == "W+C_P+FP":
        fts_size = (k + mmax)*hashbytes
    elif scheme == "W+C_F+C":
        fts_size = (k-1)*hashbytes + (k-1)*a*hashbytes
    else:  # FORS
        fts_size = k*hashbytes + k*a*hashbytes
    return hyper_tree_size + fts_size + randomness_size


def compute_mmax(h_prime, l, w, d_wots_expected_search, d, k, a):
    """The PORS+FP authentication-set bound: from (k-1)*a - ceil(350/n) up,
    the first for which signing costs less than 1.11 times signing with
    FORS+C, and at most 19 steps up (docs/model.md, W+C, FORS+C and PORS+FP)."""
    Thl = compute_Th(l)
    Thk1 = compute_Th(k-1)
    merkle_tree_fixed_part_time = (2**h_prime * (l*C_PRF + l*(w-1)*C_Th1 + Thl)) + (2**h_prime-1)*C_Th2
    hyper_tree_expected_time = d*merkle_tree_fixed_part_time + d_wots_expected_search*C_Th1c
    fors_c_fixed_part_time = (k-1)*(2**a)*C_PRF + (k-1)*(2**a)*C_Th1 + (k-1)*(2**a-1)*C_Th2 + Thk1
    fors_c_expected_search_time = 2**a*(C_Hmsg + C_PRFmsg)
    fors_c_expected_total_time = fors_c_fixed_part_time + fors_c_expected_search_time
    spx_fc_expected_total_time = hyper_tree_expected_time + fors_c_expected_total_time
    t, subtree_height, extra_leaves = compute_pors_tree_geometry(k, a)
    pors_fixed_part_time = t*(C_PRF) + t*(C_Th1) + ((2**subtree_height-1) + extra_leaves)*(C_Th2)
    mmax = (k-1)*a - ceil(350/hashbytes)
    for i in range(20):
        pors_search_attempts = ceil(exp_work_from_mmax(t, k, mmax))
        pors_expected_search_time = pors_search_attempts*(C_Hmsg + C_PRFmsg)
        pors_expected_total_time = pors_fixed_part_time + pors_expected_search_time
        spx_pors_expected_total_time = hyper_tree_expected_time + pors_expected_total_time
        ratio = spx_pors_expected_total_time/spx_fc_expected_total_time
        if (ratio < 1.11 or i == 19):
            return mmax
        mmax += 1
    return mmax


def compute_keygen_time(h, d, w, scheme):
    """Compressions for KeyGen: the top tree, 2^h' WOTS public keys and
    2^h' - 1 nodes. Nothing is ground, since KeyGen signs nothing."""
    assert h % d == 0, "h must be divisible by d"
    h_prime = h // d
    l = compute_wots_l(scheme, w)
    Thl = compute_Th(l)

    return 2**h_prime * (l*C_PRF + l*(w-1)*C_Th1 + Thl) + (2**h_prime - 1)*C_Th2


def compute_signing_time(h, d, a, k, w, swn, scheme):
    """{'compressions': mean compressions for SigGen, 'mmax': the PORS+FP
    authentication-set bound, 0 for the other schemes}."""
    assert h % d == 0, "h must be divisible by d"
    has_wc = (scheme != "SPX")
    h_prime = h // d
    l = compute_wots_l(scheme, w)
    Thl = compute_Th(l)
    Thk = compute_Th(k)

    if has_wc:
        # One counter search per layer, w^l / ν attempts each
        nu = compute_nu(l, swn, w)
        d_wots_expected_search = d*ceil((w**l) / nu)
    else:
        d_wots_expected_search = 0

    # One tree per layer: 2^h' WOTS public keys and 2^h' - 1 nodes
    c_merkle = 2**h_prime * (l*C_PRF + l*(w-1)*C_Th1 + Thl) + (2**h_prime - 1)*C_Th2
    c_hyper_exp = d*c_merkle + d_wots_expected_search*C_Th1c
    c_msg = C_Hmsg + C_PRFmsg

    mmax = 0
    if scheme == "W+C_F+C":
        # k - 1 trees; about 2^a message hashes until the last tree's index is 0
        Thk1 = compute_Th(k-1)
        c_fors_fixed = (k-1)*(2**a)*C_PRF + (k-1)*(2**a)*C_Th1 + (k-1)*(2**a - 1)*C_Th2 + Thk1
        fors_exp_search = 2**a
        c_fors_search = fors_exp_search * c_msg
        return {
            'compressions': c_hyper_exp + c_fors_fixed + c_fors_search,
            'mmax': mmax,
        }
    elif scheme == "W+C_P+FP":
        # One tree of t leaves; message hashes until the Octopus authentication
        # set has at most mmax nodes
        t, subtree_height, extra_leaves = compute_pors_tree_geometry(k, a)
        c_pors_fixed = t*C_PRF + t*C_Th1 + ((2**subtree_height - 1) + extra_leaves)*C_Th2
        mmax = compute_mmax(h_prime, l, w, d_wots_expected_search, d, k, a)
        pors_search_attempts = ceil(exp_work_from_mmax(t, k, mmax))
        c_pors_search = pors_search_attempts * c_msg
        return {
            'compressions': c_hyper_exp + c_pors_fixed + c_pors_search,
            'mmax': mmax,
        }
    else:  # FORS
        c_fors_fixed = k*(2**a)*C_PRF + k*(2**a)*C_Th1 + k*(2**a - 1)*C_Th2 + Thk
        return {
            'compressions': c_fors_fixed + c_msg + c_hyper_exp,
            'mmax': mmax,
        }

def compute_verification_time(h, d, a, k, w, swn, scheme, mmax=0):
    """{'compressions': mean compressions for SigVer, 'compressions_worst':
    the most for any message}; mmax bounds the PORS+FP authentication set."""
    has_wc = (scheme != "SPX")
    l = compute_wots_l(scheme, w)
    Thl = compute_Th(l)
    Thk = compute_Th(k)

    # WOTS over all d layers; WOTS+C costs the same for every message
    if has_wc:
        c_wots = d*(((w-1)*l - swn)*C_Th1 + C_Th1c + Thl)
        c_wots_worst = c_wots
    else:  # WOTS-TW
        l1, l2 = wots_lengths(w)
        c_wots = compute_wots_tw_mean_steps(l1, l2, w, d)*C_Th1 + d*Thl
        c_wots_worst = d*(compute_wots_tw_worst_steps(l1, l2, w)*C_Th1 + Thl)

    if scheme == "W+C_F+C":
        Thk1 = compute_Th(k-1)
        c_fts = (k-1)*C_Th1 + (k-1)*a*C_Th2 + Thk1
    elif scheme == "W+C_P+FP":
        c_fts = k*C_Th1 + mmax*C_Th2
    else:  # FORS
        c_fts = k*C_Th1 + k*a*C_Th2 + Thk

    return {
        'compressions': C_Hmsg + c_fts + c_wots + h*C_Th2,
        'compressions_worst': C_Hmsg + c_fts + c_wots_worst + h*C_Th2,
    }

# Sweep

def security_model(scheme):
    """The model compute_security uses for scheme."""
    return "PORS+FP" if scheme == "W+C_P+FP" else "FORS"


_security_cache = {}

def cached_security(q_s_log2, h, k, a, model):
    """compute_security for 2^q_s_log2 signatures, once per (h, k, a): a sweep
    asks again for every d and w."""
    key = (int(q_s_log2), int(h), int(k), int(a), model)
    if key not in _security_cache:
        _security_cache[key] = compute_security(2**q_s_log2, h, k, a, model, hashbytes)
    return _security_cache[key]


def evaluate(q_s_log2, h, d, k, a, w, swn, scheme):
    """Security (bits), size (bytes) and costs (compressions) of one parameter
    set for 2^q_s_log2 signatures. None below the security target, and for
    PORS+FP where the grinding cost table has no entry for mmax."""
    security = cached_security(q_s_log2, h, k, a, security_model(scheme))
    if security < PARAMETERS['security_bits']:
        return None
    try:
        sign = compute_signing_time(h, d, a, k, w, swn, scheme)
    except ValueError:
        return None
    mmax = sign['mmax']
    verify = compute_verification_time(h, d, a, k, w, swn, scheme, mmax)
    return {
        'h': h, 'd': d, 'k': k, 'a': a, 'w': w, 'swn': swn, 'mmax': mmax,
        'l': compute_wots_l(scheme, w),
        'security': security,
        'size': compute_size(h, d, a, k, w, scheme, mmax),
        'keygen': compute_keygen_time(h, d, w, scheme),
        'sign': sign['compressions'],
        'verify': verify['compressions'],
        'verify_worst': verify['compressions_worst'],
    }


def sweep(scheme, w_swn_pairs, h_values, d_values, k_values, a_values, q_s_log2):
    """evaluate() for every parameter set of a grid, (w, swn) outermost and a
    innermost, skipping the d that do not divide h. Yields
    ((w, swn, h, d, k, a), result)."""
    for w, swn in w_swn_pairs:
        for h in h_values:
            for d in d_values:
                if h % d != 0:
                    continue
                for k in k_values:
                    for a in a_values:
                        yield ((w, swn, h, d, k, a),
                               evaluate(q_s_log2, h, d, k, a, w, swn, scheme))

# The report's parameter sets: CSV and tables

def compute_all_results():
    """A dict of sizes and costs for each of PARAMETER_SETS."""
    results = []
    for scheme, q_s, h, d, a, k, w, _, swn, bold in PARAMETER_SETS:
        l = compute_wots_l(scheme, w)

        security = compute_security(2**q_s, h, k, a, security_model(scheme), hashbytes)
        target = PARAMETERS['security_bits']
        assert security >= target, f"Security {security:.1f} < {target} for {scheme} q_s=2^{q_s} h={h} a={a} k={k}"

        sign = compute_signing_time(h, d, a, k, w, swn, scheme)
        verify = compute_verification_time(h, d, a, k, w, swn, scheme, sign['mmax'])
        keygen_compressions = compute_keygen_time(h, d, w, scheme)
        size = compute_size(h, d, a, k, w, scheme, sign['mmax'])
        compressions_per_byte = float(verify['compressions']) / float(size)
        compressions_per_byte_worst = float(verify['compressions_worst']) / float(size)

        results.append({
            'scheme': scheme,
            'q_s': q_s,
            'h': h,
            'd': d,
            'a': a,
            'k': k,
            'w': w,
            'l': l,
            'swn': swn,
            'size': size,
            'keygen_compressions': keygen_compressions,
            'sign_compressions': sign['compressions'],
            'verify_compressions': verify['compressions'],
            'verify_compressions_worst': verify['compressions_worst'],
            'compressions_per_byte': compressions_per_byte,
            'compressions_per_byte_worst': compressions_per_byte_worst,
            'bold': bold,
        })
    return results


def generate_csv():
    print("scheme,q_s,h,d,a,k,w,l,paramsum,size,keygen_compressions,sign_compressions,verify_compressions,verify_compressions_worst,compressions_per_byte,compressions_per_byte_worst,bold")

    for r in compute_all_results():
        bold_str = "True" if r['bold'] else "False"
        print(f"{r['scheme']},2^{r['q_s']},{r['h']},{r['d']},{r['a']},{r['k']},{r['w']},{r['l']},{r['swn']},{r['size']},{r['keygen_compressions']},{r['sign_compressions']},{r['verify_compressions']},{r['verify_compressions_worst']},{r['compressions_per_byte']:.2f},{r['compressions_per_byte_worst']:.2f},{bold_str}")


def format_num(n):
    """n with a K or M suffix."""
    n = float(n)
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n/1_000:.1f}K"
    else:
        return str(int(n))


def generate_table(q_s_filter=None):
    """Prints the tables, only for 2^q_s_filter signatures if given."""
    results = compute_all_results()

    if q_s_filter is not None:
        results = [r for r in results if r['q_s'] == q_s_filter]

    if not results:
        print(f"No parameter sets found for q_s=2^{q_s_filter}")
        return

    # Group results by q_s for section headers
    q_s_groups = {}
    for r in results:
        q_s_groups.setdefault(r['q_s'], []).append(r)

    # Column definitions: (header, key, width, format_func)
    columns = [
        ("Scheme", 'scheme', 10, str),
        ("h", 'h', 4, str),
        ("d", 'd', 3, str),
        ("a", 'a', 3, str),
        ("k", 'k', 3, str),
        ("w", 'w', 4, str),
        ("l", 'l', 3, str),
        ("S_wn", 'swn', 5, str),
        ("Size", 'size', 6, str),
        ("Keygen(C)", 'keygen_compressions', 10, format_num),
        ("Sign(C)", 'sign_compressions', 9, format_num),
        ("Verify(C)", 'verify_compressions', 10, format_num),
        ("C/byte", 'compressions_per_byte', 6, lambda x: f"{x:.2f}"),
    ]

    # Calculate total width
    total_width = sum(w for _, _, w, _ in columns) + len(columns) - 1

    for q_s in sorted(q_s_groups.keys(), reverse=True):
        group = q_s_groups[q_s]

        # Section header
        print()
        print("=" * total_width)
        print(f" 2^{q_s} signatures ".center(total_width, "="))
        print("=" * total_width)

        # Column headers
        header_line = " ".join(h.center(w) for h, _, w, _ in columns)
        print(header_line)
        print("-" * total_width)

        # Data rows
        for r in group:
            row_parts = []
            for _, key, width, fmt in columns:
                val = fmt(r[key])
                row_parts.append(val.rjust(width) if key != 'scheme' else val.ljust(width))
            print(" ".join(row_parts))

    print()
    print("Legend: Size=bytes, Keygen(C)/Sign(C)/Verify(C)=compression calls, C/byte=verify compressions per signature byte")


def compute_single(scheme, q_s_log2, h, d, a, k, w, swn):
    """Prints the size, costs and security of one parameter set."""
    q_s = 2**q_s_log2
    l = compute_wots_l(scheme, w)
    security = compute_security(q_s, h, k, a, security_model(scheme), hashbytes)
    sign = compute_signing_time(h, d, a, k, w, swn, scheme)
    mmax = sign['mmax']
    verify = compute_verification_time(h, d, a, k, w, swn, scheme, mmax)
    keygen_compressions = compute_keygen_time(h, d, w, scheme)
    size = compute_size(h, d, a, k, w, scheme, mmax)
    c_per_byte = float(verify['compressions']) / float(size)

    print("Scheme:     " + scheme)
    print("q_s:        2^" + str(q_s_log2))
    print("(k,a,H,d):  (" + str(int(k)) + ", " + str(int(a)) + ", " + str(int(h)) + ", " + str(int(d)) + ")")
    print("w:          " + str(int(w)))
    print("S_wn:       " + str(int(swn)))
    print("l:          " + str(int(l)))
    print("mmax:       " + str(int(mmax)))
    print("Security:   " + "{:.1f}".format(security) + " bits")
    print("Size:       " + str(int(size)) + " bytes")
    print("Keygen(C):  " + format_num(keygen_compressions))
    print("Sign(C):    " + format_num(sign['compressions']))
    print("Verify(C):  " + format_num(verify['compressions']) + "  (worst: " + format_num(verify['compressions_worst']) + ")")
    print("C/byte:     " + "{:.2f}".format(c_per_byte) + "  (worst: " + "{:.2f}".format(float(verify['compressions_worst'])/float(size)) + ")")


# Scripts that load this file for its functions set COSTS_SAGE_NO_MAIN: load()
# runs it in their namespace, where __name__ is '__main__'.
if __name__ == "__main__" and not os.environ.get("COSTS_SAGE_NO_MAIN"):
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--table":
        # Optional: --table 40 to filter by q_s
        q_s_filter = int(sys.argv[2]) if len(sys.argv) > 2 else None
        generate_table(q_s_filter)
    elif len(sys.argv) > 1 and sys.argv[1] == "--params":
        # Usage: sage costs.sage --params scheme q_s k a h d w swn
        if len(sys.argv) != 10:
            print("Usage: sage costs.sage --params scheme q_s k a h d w swn")
            print("  scheme: SPX, W+C, W+C_F+C, W+C_P+FP")
            print("  q_s: log2 of max signatures (e.g., 10 for 2^10)")
            print("Example: sage costs.sage --params W+C_P+FP 10 8 17 12 1 16 240")
            sys.exit(1)
        scheme = sys.argv[2]
        q_s_log2 = int(sys.argv[3])
        k = int(sys.argv[4])
        a = int(sys.argv[5])
        h = int(sys.argv[6])
        d = int(sys.argv[7])
        w = int(sys.argv[8])
        swn = int(sys.argv[9])
        compute_single(scheme, q_s_log2, h, d, a, k, w, swn)
    elif len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: sage costs.sage [OPTIONS]")
        print()
        print("Options:")
        print("  (no args)                                  Output CSV format")
        print("  --table [N]                                Output pretty ASCII table [filtered to 2^N]")
        print("  --params scheme q_s k a h d w swn          Compute single parameter set")
        print("  --help                                     Show this help message")
        print()
        print("Example:")
        print("  sage costs.sage --params W+C_P+FP 10 8 17 12 1 16 240")
    else:
        generate_csv()
