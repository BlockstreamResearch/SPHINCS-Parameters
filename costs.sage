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
from scipy.stats import binom
import os

from octopus_pmf import interleave_cost_table

# Load security.sage from the same directory
_dir = os.path.dirname(os.path.abspath(__file__))
load(os.path.join(_dir, "security.sage"))

# =============================================================================
# Constants
# =============================================================================

hashbytes = 16  # 16 bytes = 128 bits
counter_size = 4 # 4 bytes = 32 bits
randomness_size = 32  # 32 bytes = 256 bits

# Compression function calls per hash operation
# SHA-256 block size = 512 bits, with 65 bits for padding/length
# Each value = number of compression calls for that operation
C_Th1 = 1     # Tweakable hash, 1-block: PKseed (128) + Tweak (96) + m1 (128)
C_Th1c = 1    # Tweakable hash, 1-block + counter: PKseed + Tweak + m1 + counter (32)
C_Th2 = 2     # Tweakable hash, 2-block: PKseed + Tweak + m1 + m2
C_Hmsg = 2    # Message hash: PKseed + PKroot (128) + R (256) + m (256)
C_PRFmsg = 2  # Message PRF: SKprf (128) + Opt + m (256) + counter
C_PRF = 1     # PRF: PKseed + SKseed + Tweak

def compute_Th(n):
    """
    Compute compression calls for tweakable hash of n values.

    Input: PKseed (128) + Tweak (96) + n*hashbytes (n*128) + padding (65)
    SHA-256 block size: 512 bits
    """
    return ceil((128 + 96 + 128*n + 65)/512)

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

# High precision arithmetic
F = RealField(100)

# -----------------------------------------------------------------------------
# WOTS helpers
# -----------------------------------------------------------------------------

def compute_wots_l(scheme, w):
    """
    Compute WOTS chain count l based on scheme type.

    For WOTS-TW (plain): l = l1 + l2
        l1 = n / log2(w)           -- message chains
        l2 = ceil(log_w(l1*(w-1))) -- checksum chains

    For WOTS+C: l = l1 (no checksum chains, replaced by counter)
    """
    if scheme == "SPX":
        l1 = hashbytes*8//log(w,2)
        l2 = ceil(log(l1*(w-1), 2)/log(w, 2))
        return l1 + l2
    else:
        return hashbytes*8//log(w,2)

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

def log2_exp_work_from_mmax(t, k, mmax):
    """Look up log2 of expected work for PORS+FP grinding given mmax."""
    table = dict(interleave_cost_table(t, k))
    if mmax in table:
        return table[mmax]
    lowers = [m for m in table if m <= mmax]
    if not lowers:
        raise ValueError("mmax below supported range for these (t,k).")
    return table[max(lowers)]

def exp_work_from_mmax(t, k, mmax):
    """Compute expected work (attempts) for PORS+FP grinding given mmax."""
    return 2.0 ** log2_exp_work_from_mmax(t, k, mmax)

# -----------------------------------------------------------------------------
# Search/Grinding helpers
# -----------------------------------------------------------------------------

def worst_case(p, q, d, max_k=10**11):
    """
    Find minimum trials k such that P(fewer than d successes in k trials) < q.

    Used to compute worst-case search time: how many attempts until we're
    confident (with probability 1-q) that we've found d valid encodings.

    P(X < d) = Σ_{i=0}^{d-1} C(k,i) * p^i * (1-p)^(k-i), where X ~ Binomial(k, p)

    Returns smallest k where P(X < d) < q.
    """
    # Convert Sage types to Python native types
    p_float = float(p)
    q_float = float(q)
    d_int = int(d)

    def tail_prob(k):
        if k < d_int:
            return 1.0
        # binom.cdf(d-1, k, p) = P(X <= d-1) = P(X < d)
        return binom.cdf(d_int - 1, int(k), p_float)
    # Find an upper bound for k
    k_low = d_int - 1
    k_high = max(d_int, 1)
    while tail_prob(k_high) >= q_float:
        k_high *= 2
        if k_high > max_k:
            raise RuntimeError("Could not find k below given max_k; try increasing max_k.")
    # Binary search between k_low and k_high
    while k_low + 1 < k_high:
        k_mid = (k_low + k_high) // 2
        if tail_prob(k_mid) < q_float:
            k_high = k_mid
        else:
            k_low = k_mid
    return k_high

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


def compute_signing_time(h, d, a, k, w, swn, scheme):
    """
    Compute signing time in both hash calls and compression function calls.

    Returns a dict with keys:
    - 'hashes': expected signing time in hash calls
    - 'compressions': expected signing time in compression calls
    - 'exp_search': expected search attempts
    - 'worst_search': worst-case search attempts
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
        d_wots_worst_search = worst_case(nu/(w**l), F(2)**(-30), d)
    else:
        d_wots_expected_search = 0
        d_wots_worst_search = 0

    # Compute times for both hash calls (h_) and compressions (c_)
    # One XMSS tree layer with 2^h' leaves:
    #   - 2^h' WOTS keypairs, each requiring:
    #       - l PRF calls to generate secret keys
    #       - l*(w-1) chain hashes (Th1)
    #       - 1 hash to compress l public key values (Thl)
    #   - 2^h' - 1 internal Merkle tree nodes (Th2, hashing 2 children)
    h_merkle = 2**h_prime * (l + l*(w-1) + 1) + (2**h_prime - 1)
    c_merkle = 2**h_prime * (l*C_PRF + l*(w-1)*C_Th1 + Thl) + (2**h_prime - 1)*C_Th2

    # Full hypertree: d layers + WOTS+C counter search overhead
    h_hyper_exp = d*h_merkle + d_wots_expected_search
    c_hyper_exp = d*c_merkle + d_wots_expected_search*C_Th1c

    # Message hash cost (2 hash calls: Hmsg + PRFmsg)
    h_msg = 2
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
        h_fors_fixed = (k-1)*(2**a) + (k-1)*(2**a) + (k-1)*(2**a - 1) + 1
        c_fors_fixed = (k-1)*(2**a)*C_PRF + (k-1)*(2**a)*C_Th1 + (k-1)*(2**a - 1)*C_Th2 + Thk1
        fors_exp_search = 2**a
        fors_worst_search = worst_case(F(1)/F(2**a), F(2)**(-30), 1)
        h_fors_search = fors_exp_search * h_msg
        c_fors_search = fors_exp_search * c_msg
        return {
            'hashes': h_hyper_exp + h_fors_fixed + h_fors_search,
            'compressions': c_hyper_exp + c_fors_fixed + c_fors_search,
            'exp_search': d_wots_expected_search + h_fors_search,
            'worst_search': d_wots_worst_search + fors_worst_search * h_msg,
            'mmax': mmax,
        }
    elif scheme == "W+C_P+FP":
        # PORS+FP: single tree with t = k * 2^a leaves
        # Tree structure: largest power-of-2 subtree + extra leaves
        # Grinding: search for message hash where Octopus auth set size <= mmax
        t, subtree_height, extra_leaves = compute_pors_tree_geometry(k, a)
        # t PRF calls + t leaf hashes + internal nodes
        h_pors_fixed = 2*t + (2**subtree_height - 1) + extra_leaves
        c_pors_fixed = t*C_PRF + t*C_Th1 + ((2**subtree_height - 1) + extra_leaves)*C_Th2
        mmax = compute_mmax(h_prime, l, w, d_wots_expected_search, d, k, a)
        pors_search_attempts = ceil(exp_work_from_mmax(t, k, mmax))
        h_pors_search = pors_search_attempts * h_msg
        c_pors_search = pors_search_attempts * c_msg
        pors_worst_search = worst_case(F(1)/pors_search_attempts, F(2)**(-30), 1)
        return {
            'hashes': h_hyper_exp + h_pors_fixed + h_pors_search,
            'compressions': c_hyper_exp + c_pors_fixed + c_pors_search,
            'exp_search': d_wots_expected_search + h_pors_search,
            'worst_search': d_wots_worst_search + pors_worst_search * h_msg,
            'mmax': mmax,
        }
    else:
        # Plain FORS (SPX or W+C): k trees, each with 2^a leaves
        # No grinding, message hash directly selects k leaf indices
        h_fors_fixed = k*(2**a) + k*(2**a) + k*(2**a - 1) + 1
        c_fors_fixed = k*(2**a)*C_PRF + k*(2**a)*C_Th1 + k*(2**a - 1)*C_Th2 + Thk
        return {
            'hashes': h_fors_fixed + h_msg + h_hyper_exp,
            'compressions': c_fors_fixed + c_msg + c_hyper_exp,
            'exp_search': d_wots_expected_search,
            'worst_search': d_wots_worst_search,
            'mmax': mmax,
        }

def compute_verification_time(h, d, a, k, w, swn, scheme, mmax=0):
    """
    Compute verification time in both hash calls and compression function calls.

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

    # WOTS verification: complete each chain from signature value to public key
    if has_wc:
        # WOTS+C: chain positions sum to S_{w,n}, so remaining steps = (w-1)*l - S_{w,n}
        # Plus: verify counter hash (Th1c) and compress public key (Thl)
        h_wots = (w-1)*l - swn + 2
        c_wots = ((w-1)*l - swn)*C_Th1 + C_Th1c + Thl
    else:  # Plain WOTS
        # Expected chain position is (w-1)/2, so expected remaining steps = (w-1)*l/2
        h_wots = (w-1)*l//2 + 1
        c_wots = (w-1)*l//2*C_Th1 + Thl

    # FTS verification
    if scheme == "W+C_F+C":
        # FORS+C: k-1 leaves to hash, (k-1)*a auth path nodes, 1 root compression
        Thk1 = compute_Th(k-1)  # k-1 roots to compress
        h_fts = (k-1) + (k-1)*a + 1
        c_fts = (k-1)*C_Th1 + (k-1)*a*C_Th2 + Thk1
    elif scheme == "W+C_P+FP":
        # PORS+FP: k leaves to hash, mmax auth set nodes
        h_fts = k + mmax
        c_fts = k*C_Th1 + mmax*C_Th2
    else:  # Plain FORS (SPX or W+C)
        # FORS: k leaves, k*a auth path nodes, 1 root compression
        h_fts = k + k*a + 1
        c_fts = k*C_Th1 + k*a*C_Th2 + Thk

    # Total: Hmsg + FTS + d*WOTS + h auth path nodes
    return {
        'hashes': 1 + h_fts + d*h_wots + h,
        'compressions': C_Hmsg + c_fts + d*c_wots + h*C_Th2,
    }

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
        scheme_type = "PORS+FP" if scheme == "W+C_P+FP" else "FORS"
        security = compute_security(2**q_s, h, k, a, scheme_type)
        assert security >= 128, f"Security {security:.1f} < 128 for {scheme} q_s=2^{q_s} h={h} a={a} k={k}"

        sign = compute_signing_time(h, d, a, k, w, swn, scheme)
        verify = compute_verification_time(h, d, a, k, w, swn, scheme, sign['mmax'])
        size = compute_size(h, d, a, k, w, scheme, sign['mmax'])
        compressions_per_byte = float(verify['compressions']) / float(size)

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
            'sign_hashes': sign['hashes'],
            'sign_compressions': sign['compressions'],
            'exp_search': sign['exp_search'],
            'worst_search': sign['worst_search'],
            'verify_hashes': verify['hashes'],
            'verify_compressions': verify['compressions'],
            'compressions_per_byte': compressions_per_byte,
            'bold': bold,
        })
    return results


def generate_csv():
    """Generate CSV output for all parameter sets."""
    print("scheme,q_s,h,d,a,k,w,l,paramsum,size,sign_hashes,sign_compressions,exp_search,worst_search,verify_hashes,verify_compressions,compressions_per_byte,bold")

    for r in compute_all_results():
        bold_str = "True" if r['bold'] else "False"
        print(f"{r['scheme']},2^{r['q_s']},{r['h']},{r['d']},{r['a']},{r['k']},{r['w']},{r['l']},{r['swn']},{r['size']},{r['sign_hashes']},{r['sign_compressions']},{r['exp_search']},{r['worst_search']},{r['verify_hashes']},{r['verify_compressions']},{r['compressions_per_byte']:.2f},{bold_str}")


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
    print("Legend: Size=bytes, Sign(C)/Verify(C)=compression calls, C/byte=verify compressions per signature byte")


# =============================================================================
# Main
# =============================================================================

def compute_single(scheme, q_s_log2, h, d, a, k, w, swn):
    """Compute and display results for a single parameter set."""
    q_s = 2**q_s_log2
    l = compute_wots_l(scheme, w)
    scheme_type = "PORS+FP" if scheme == "W+C_P+FP" else "FORS"
    security = compute_security(q_s, h, k, a, scheme_type)
    sign = compute_signing_time(h, d, a, k, w, swn, scheme)
    mmax = sign['mmax']
    verify = compute_verification_time(h, d, a, k, w, swn, scheme, mmax)
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
    print("Sign(C):    " + format_num(sign['compressions']))
    print("Verify(C):  " + format_num(verify['compressions']))
    print("C/byte:     " + "{:.2f}".format(c_per_byte))


if __name__ == "__main__":
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
