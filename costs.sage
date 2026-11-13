#!/usr/bin/env sage
"""
SPHINCS+ Parameter Efficiency and Size Calculator

Computes signature sizes and signing/verification times for SPHINCS+ variants:
- SPX: Plain SPHINCS+ (WOTS-TW + FORS)
- W+C: SPHINCS+ with WOTS+C (counter-based WOTS, no checksum chains)
- W+C_F+C: SPHINCS+ with WOTS+C and FORS+C (grinding to remove last FORS tree)
- W+C_P+FP: SPHINCS+ with WOTS+C and PORS+FP (single tree with Octopus auth)

Notation:
- h: hypertree height (total)
- d: number of layers in the hypertree
- h' = h/d: height of each XMSS tree layer
- n: hash output size in bits (fixed at 128 = hashbytes*8)
- a: log2 of leaves per FORS tree (t = 2^a leaves per tree)
- k: number of FORS trees (or leaf indices for PORS)
- w: Winternitz parameter
- l: number of WOTS chains
- S_{w,n} (swn): target chain sum for WOTS+C
- q_s: max number of signatures supported
"""

from sage.all import *
from functools import lru_cache
import json
import os

from octopus_pmf import interleave_cost_table

# Load security.sage from the same directory
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

# =============================================================================
# Constants
# =============================================================================

hashbytes = 16  # 16 bytes = 128 bits
counter_size = 4 # 4 bytes = 32 bits
randomness_size = 16  # 16 bytes = 128 bits

# -----------------------------------------------------------------------------
# Compressions per hash call
# -----------------------------------------------------------------------------
# The FIPS 205 SHA-2 instantiation as SHRINCS (github.com/SHRINCS/shrincs-bip)
# runs it: the PK.seed block is compressed once per key and its state reused.

C_Th1 = 1     # Tweakable hash, 1 value: address (22 B) + m1 (16 B)
C_Th1c = 1    # Tweakable hash, 1 value + counter
C_Th2 = 1     # Tweakable hash, 2 values (a tree node)
C_PRF = 1     # PRF: address + SK.seed

# Message hash and message PRF, for a 32-byte message and an empty context.
#
#   H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
#     is two nested SHA-256 calls (98- and 68-byte inputs in SHRINCS), 2
#     compressions each. Its input starts with the randomizer R, so nothing
#     can be cached.                                                       -> 4
#   PRF_msg = HMAC-SHA-256(SK.prf, opt_rand || M) is two SHA-256 calls of
#     3 and 2 compressions. Their first blocks are the fixed HMAC key pads,
#     cached like the PK.seed block (it would be 5 otherwise).             -> 3
C_Hmsg = 4
C_PRFmsg = 3

def compute_Th(n):
    """
    Compression calls for a tweakable hash over n hash-sized values:
    ceil((22*8 + 128*n + 65) / 512)
    """
    return ceil((22*8 + 128*n + 65)/512)

# =============================================================================
# Parameter Sets
# =============================================================================

# Single consolidated list in table output order
# Format: (scheme, q_s, h, d, a, k, w, l, swn, bold)
#   q_s: log2 of max signatures (e.g., 40 means 2^40 signatures)
#   swn: S_{w,n} target chain sum for WOTS+C
# bold=True for rows highlighted in the paper tables
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

# =============================================================================
# Helper Functions
# =============================================================================

# -----------------------------------------------------------------------------
# WOTS helpers
# -----------------------------------------------------------------------------

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
    """
    Worst-case WOTS-TW verification steps per hypertree layer.

    Worst case: all l1 message digits = 0, so the verifier traverses w-1
    steps on every message chain. The checksum C = l1*(w-1) is then encoded
    in base w as l2 digits c_j; the verifier traverses w-1-c_j steps on each
    checksum chain. Total = l1*(w-1) + l2*(w-1) - digit_sum(C, w).

    This is the correct model for WOTS-TW. The old average-case formula
    (w-1)*l/2 was only valid for WOTS+C where chains sum to a constant.
    """
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
    """
    w^l1 * sum_{j=1}^{l2-1} E[floor(S / w^j)], as an exact integer, where S is
    the sum of l1 independent uniform base-w digits.

    E[floor(S / w^j)] = sum_{m>=1} P(S >= m*w^j), and the number of digit
    strings with sum <= t is, by inclusion-exclusion,

        sum_i (-1)^i * C(l1, i) * C(t - i*w + l1, l1).
    """
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
    """
    Mean number of chain steps to verify `count` WOTS-TW signatures on
    uniformly random digests, rounded to the nearest integer.

    A message digit m costs w-1-m steps, so the l1 message chains average
    (w-1)/2 steps each. The l2 checksum chains do not: the checksum
    C = l1*(w-1) - S (S = sum of the message digits) is concentrated around
    l1*(w-1)/2, so its base-w digits are far from uniform (the leading one
    is almost always 0 or 1) and the verifier walks more of those chains
    than (w-1)/2. Exactly:

        E[steps] = l1*(w-1)/2 + l2*(w-1) - E[digit_sum(C)]
                 = (w-1) * (l2 + sum_{j=1}^{l2-1} E[floor(S / w^j)]),

    using that C is distributed like S (map every digit m to w-1-m) and
    digit_sum(x) = x - (w-1) * sum_{j>=1} floor(x / w^j).

    For w = 16 this is 267.12 steps rather than the 262 that (w-1)*l/2
    gives, and the gap grows with w (2415.03 against 2295 for w = 256).
    """
    W = int(w)**int(l1)
    T = _wots_tw_floor_sum(l1, l2, w)
    # count * (w-1) * (l2 + T/W), rounded to the nearest integer
    return _round_div(count * (w - 1) * (l2*W + T), W)

def compute_nu(l: int, paramsum: int, w: int) -> int:
    """
    Compute ν (nu), the number of valid WOTS+C encodings for a given target sum.

    For WOTS+C, we need message digests whose base-w digits sum to exactly S_{w,n}.
    ν counts how many such encodings exist out of w^l total possibilities.

        ν = Σ_{j=0}^{l} (-1)^j * C(l,j) * C((S_{w,n} + l) - j*w - 1, l-1)

    Returns integer ν. If ν is zero, returns 1 and prints a warning.
    """
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

# -----------------------------------------------------------------------------
# PORS helpers
# -----------------------------------------------------------------------------

def compute_pors_tree_geometry(k, a):
    """
    Compute PORS tree geometry.

    Returns (t, subtree_height, extra_leaves) where:
    - t: total number of PORS leaves (k * 2^a)
    - subtree_height: height of the largest power-of-2 subtree
    - extra_leaves: leaves beyond the power-of-2 subtree
    """
    t = k * (2**a)
    subtree_height = floor(log(t, 2))
    extra_leaves = t - 2**subtree_height
    return t, subtree_height, extra_leaves

_interleave_table_cache = {}

def log2_exp_work_from_mmax(t, k, mmax):
    """Look up log2 of expected work for PORS+FP grinding given mmax.

    The (t, k) tables are cached: compute_mmax probes several mmax values per
    parameter set, and sweeps revisit the same (k, a) pairs for every (h, d) —
    without the cache a full PORS+FP sweep rebuilds each table thousands of times.
    """
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
    """Compute expected work (attempts) for PORS+FP grinding given mmax."""
    return 2.0 ** log2_exp_work_from_mmax(t, k, mmax)

# =============================================================================
# Core Computation Functions
# =============================================================================

def compute_size(h, d, a, k, w, scheme, mmax=0):
    """
    Compute signature size in bytes.

    Signature structure:
    - Randomness R (randomness_size bytes)
    - d XMSS layers, each containing:
        - WOTS signature: l hash values
        - Auth path: h' = h/d hash values
        - Counter (for W+C variants): counter_size bytes
    - Few-time signature (FTS):
        - FORS: k leaves + k*a auth path nodes
        - FORS+C: (k-1) leaves + (k-1)*a auth path nodes (last tree omitted)
        - PORS+FP: k leaves + mmax auth set nodes

    mmax: for PORS+FP, max size of the authentication set
    """
    assert h % d == 0, "h must be divisible by d"
    has_wc = (scheme != "SPX")
    l = compute_wots_l(scheme, w)
    h_prime = h // d
    # Each XMSS layer: auth path (h') + WOTS sig (l) + optional counter
    hyper_tree_size = d*(h_prime*hashbytes + l*hashbytes + counter_size*int(has_wc))
    # fts = few-time signature (FORS, FORS+C, or PORS+FP)
    if scheme == "W+C_P+FP":
        # k revealed leaves + mmax authentication nodes
        fts_size = (k + mmax)*hashbytes
    elif scheme == "W+C_F+C":
        # k-1 trees (last tree omitted via grinding)
        fts_size = (k-1)*hashbytes + (k-1)*a*hashbytes
    else:  # Plain FORS (SPX or W+C)
        # k trees, each with 1 leaf + a auth path nodes
        fts_size = k*hashbytes + k*a*hashbytes
    return hyper_tree_size + fts_size + randomness_size


def compute_mmax(h_prime, l, w, d_wots_expected_search, d, k, a):
    """Compute mmax for PORS+FP such that signing time is close to FORS+C.

    mmax is the max size of the authentication set.
    """
    Thl = compute_Th(l)
    Thk1 = compute_Th(k-1)  # FORS+C has k-1 roots
    merkle_tree_fixed_part_time = (2**h_prime * (l*C_PRF + l*(w-1)*C_Th1 + Thl)) + (2**h_prime-1)*C_Th2
    hyper_tree_expected_time = d*merkle_tree_fixed_part_time + d_wots_expected_search*C_Th1c
    # Compute FORS+C time to relate PORS time in compression calls
    fors_c_fixed_part_time = (k-1)*(2**a)*C_PRF + (k-1)*(2**a)*C_Th1 + (k-1)*(2**a-1)*C_Th2 + Thk1
    fors_c_expected_search_time = 2**a*(C_Hmsg + C_PRFmsg)
    fors_c_expected_total_time = fors_c_fixed_part_time + fors_c_expected_search_time
    spx_fc_expected_total_time = hyper_tree_expected_time + fors_c_expected_total_time
    # Search for mmax such that PORS time is close to FORS+C time
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
    """
    Compute keygen time in compression function calls.

    Keygen builds the top-level XMSS tree (height h' = h/d) to derive PK.root.
    No WOTS+C counter search occurs during keygen: the WOTS keypairs at the
    leaves of the top tree are used as verification keys, not to sign anything.

    One XMSS tree with 2^h' leaves:
      - 2^h' WOTS keypairs, each requiring:
          - l PRF calls to generate secret keys
          - l*(w-1) chain hashes (Th1) to derive the public chain values
          - 1 hash to compress l public values into a leaf (Thl)
      - 2^h' - 1 internal Merkle tree nodes (Th2)

    Returns the keygen time as a number of compression function calls.
    """
    assert h % d == 0, "h must be divisible by d"
    h_prime = h // d
    l = compute_wots_l(scheme, w)
    Thl = compute_Th(l)

    return 2**h_prime * (l*C_PRF + l*(w-1)*C_Th1 + Thl) + (2**h_prime - 1)*C_Th2


def compute_signing_time(h, d, a, k, w, swn, scheme):
    """
    Compute the expected signing time in compression function calls.

    Returns a dict with keys:
    - 'compressions': expected signing time in compression calls
    - 'mmax': mmax value for PORS+FP (max authentication set size)
    """
    assert h % d == 0, "h must be divisible by d"
    has_wc = (scheme != "SPX")
    h_prime = h // d
    l = compute_wots_l(scheme, w)
    Thl = compute_Th(l)
    Thk = compute_Th(k)

    if has_wc:
        # WOTS+C search: find counter such that digest sums to S_{w,n}
        # Success probability p_ν = ν / w^l
        # By geometric distribution, expected attempts until success = 1/p_ν = w^l / ν
        # We need d successful searches (one per hypertree layer)
        nu = compute_nu(l, swn, w)
        d_wots_expected_search = d*ceil((w**l) / nu)
    else:
        d_wots_expected_search = 0

    # One XMSS tree layer with 2^h' leaves:
    #   - 2^h' WOTS keypairs, each requiring:
    #       - l PRF calls to generate secret keys
    #       - l*(w-1) chain hashes (Th1)
    #       - 1 hash to compress l public key values (Thl)
    #   - 2^h' - 1 internal Merkle tree nodes (Th2, hashing 2 children)
    c_merkle = 2**h_prime * (l*C_PRF + l*(w-1)*C_Th1 + Thl) + (2**h_prime - 1)*C_Th2

    # Full hypertree: d layers + WOTS+C counter search overhead
    c_hyper_exp = d*c_merkle + d_wots_expected_search*C_Th1c

    # Message hash cost (Hmsg + PRFmsg)
    c_msg = C_Hmsg + C_PRFmsg

    mmax = 0
    if scheme == "W+C_F+C":
        # FORS+C: k-1 trees (last tree omitted, grinding ensures first leaf is selected)
        # Each tree has 2^a leaves:
        #   - 2^a PRF calls to generate leaves
        #   - 2^a hashes to compute leaf nodes (Th1)
        #   - 2^a - 1 internal nodes (Th2)
        # Plus 1 hash to compress k-1 roots
        # Grinding: search for message hash with last a bits = 0, expected 2^a attempts
        Thk1 = compute_Th(k-1)  # k-1 roots to compress
        c_fors_fixed = (k-1)*(2**a)*C_PRF + (k-1)*(2**a)*C_Th1 + (k-1)*(2**a - 1)*C_Th2 + Thk1
        fors_exp_search = 2**a
        c_fors_search = fors_exp_search * c_msg
        return {
            'compressions': c_hyper_exp + c_fors_fixed + c_fors_search,
            'mmax': mmax,
        }
    elif scheme == "W+C_P+FP":
        # PORS+FP: single tree with t = k * 2^a leaves
        # Tree structure: largest power-of-2 subtree + extra leaves
        # Grinding: search for message hash where Octopus auth set size <= mmax
        t, subtree_height, extra_leaves = compute_pors_tree_geometry(k, a)
        # t PRF calls + t leaf hashes + internal nodes
        c_pors_fixed = t*C_PRF + t*C_Th1 + ((2**subtree_height - 1) + extra_leaves)*C_Th2
        mmax = compute_mmax(h_prime, l, w, d_wots_expected_search, d, k, a)
        pors_search_attempts = ceil(exp_work_from_mmax(t, k, mmax))
        c_pors_search = pors_search_attempts * c_msg
        return {
            'compressions': c_hyper_exp + c_pors_fixed + c_pors_search,
            'mmax': mmax,
        }
    else:
        # Plain FORS (SPX or W+C): k trees, each with 2^a leaves
        # No grinding, message hash directly selects k leaf indices
        c_fors_fixed = k*(2**a)*C_PRF + k*(2**a)*C_Th1 + k*(2**a - 1)*C_Th2 + Thk
        return {
            'compressions': c_fors_fixed + c_msg + c_hyper_exp,
            'mmax': mmax,
        }

def compute_verification_time(h, d, a, k, w, swn, scheme, mmax=0):
    """
    Compute the verification time in compression function calls, average and
    worst case.

    Verification involves:
    1. Hash the message (Hmsg)
    2. Verify FTS (FORS/FORS+C/PORS+FP)
    3. For each of d hypertree layers: verify WOTS signature
    4. Verify h auth path nodes up the hypertree

    mmax: for PORS+FP, max size of the authentication set
    """
    has_wc = (scheme != "SPX")
    l = compute_wots_l(scheme, w)
    Thl = compute_Th(l)
    Thk = compute_Th(k)

    # WOTS verification: complete each chain from signature value to public key.
    # c_wots is the total over all d hypertree layers.
    if has_wc:
        # WOTS+C: chain positions sum to S_{w,n}, so remaining steps = (w-1)*l - S_{w,n}
        # Plus: verify counter hash (Th1c) and compress public key (Thl)
        # Deterministic: worst case == average case.
        c_wots = d*(((w-1)*l - swn)*C_Th1 + C_Th1c + Thl)
        c_wots_worst = c_wots
    else:  # Plain WOTS
        l1, l2 = wots_lengths(w)
        # Average case: expected chain steps for a uniformly random digest,
        # see compute_wots_tw_mean_steps.
        avg_steps = compute_wots_tw_mean_steps(l1, l2, w, d)
        c_wots = avg_steps*C_Th1 + d*Thl
        # Worst case (all message digits 0): see compute_wots_tw_worst_steps.
        c_wots_worst = d*(compute_wots_tw_worst_steps(l1, l2, w)*C_Th1 + Thl)

    # FTS verification
    if scheme == "W+C_F+C":
        # FORS+C: k-1 leaves to hash, (k-1)*a auth path nodes, 1 root compression
        Thk1 = compute_Th(k-1)  # k-1 roots to compress
        c_fts = (k-1)*C_Th1 + (k-1)*a*C_Th2 + Thk1
    elif scheme == "W+C_P+FP":
        # PORS+FP: k leaves to hash, mmax auth set nodes
        c_fts = k*C_Th1 + mmax*C_Th2
    else:  # Plain FORS (SPX or W+C)
        # FORS: k leaves, k*a auth path nodes, 1 root compression
        c_fts = k*C_Th1 + k*a*C_Th2 + Thk

    # Total: Hmsg + FTS + d*WOTS + h auth path nodes
    # The FTS and auth-path costs are message-independent, so the worst case
    # differs from the average only in the WOTS-TW chain walks.
    return {
        'compressions': C_Hmsg + c_fts + c_wots + h*C_Th2,
        'compressions_worst': C_Hmsg + c_fts + c_wots_worst + h*C_Th2,
    }

# =============================================================================
# Sweep
# =============================================================================

def security_model(scheme):
    """The model compute_security uses for scheme."""
    return "PORS+FP" if scheme == "W+C_P+FP" else "FORS"


_security_cache = {}

def cached_security(q_s_log2, h, k, a, model):
    """compute_security for 2^q_s_log2 signatures, once per (h, k, a): a sweep
    asks again for every d and w."""
    key = (int(q_s_log2), int(h), int(k), int(a), model)
    if key not in _security_cache:
        _security_cache[key] = compute_security(2**q_s_log2, h, k, a, model, hashbytes=16)
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

# =============================================================================
# CSV Output
# =============================================================================

def compute_all_results():
    """Compute results for all parameter sets. Returns list of dicts."""
    results = []
    for scheme, q_s, h, d, a, k, w, _, swn, bold in PARAMETER_SETS:
        # Compute l dynamically based on scheme
        l = compute_wots_l(scheme, w)

        # Verify security level is at least 128 bits
        security = compute_security(2**q_s, h, k, a, security_model(scheme))
        assert security >= 128, f"Security {security:.1f} < 128 for {scheme} q_s=2^{q_s} h={h} a={a} k={k}"

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
    """Generate CSV output for all parameter sets."""
    print("scheme,q_s,h,d,a,k,w,l,paramsum,size,keygen_compressions,sign_compressions,verify_compressions,verify_compressions_worst,compressions_per_byte,compressions_per_byte_worst,bold")

    for r in compute_all_results():
        bold_str = "True" if r['bold'] else "False"
        print(f"{r['scheme']},2^{r['q_s']},{r['h']},{r['d']},{r['a']},{r['k']},{r['w']},{r['l']},{r['swn']},{r['size']},{r['keygen_compressions']},{r['sign_compressions']},{r['verify_compressions']},{r['verify_compressions_worst']},{r['compressions_per_byte']:.2f},{r['compressions_per_byte_worst']:.2f},{bold_str}")


def format_num(n):
    """Format large numbers with K/M suffixes for readability."""
    n = float(n)  # Convert Sage types to Python float
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n/1_000:.1f}K"
    else:
        return str(int(n))


def generate_table(q_s_filter=None):
    """Generate pretty ASCII table output for parameter sets.

    Args:
        q_s_filter: If specified, only show rows with this q_s value (e.g., 40 for 2^40 sigs)
    """
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


# =============================================================================
# Main
# =============================================================================

def compute_single(scheme, q_s_log2, h, d, a, k, w, swn):
    """Compute and display results for a single parameter set."""
    q_s = 2**q_s_log2
    l = compute_wots_l(scheme, w)
    security = compute_security(q_s, h, k, a, security_model(scheme))
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


# The env flag lets other scripts (stateful.sage, export_site_data.sage) load
# this file for its functions without triggering the CLI output (sage's
# load() executes in the caller's namespace, where __name__ is '__main__').
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
