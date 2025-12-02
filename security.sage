#!/usr/bin/env sage
from sage.all import *

"""
SPHINCS+ FORS / PORS+FP Security Analysis

This script computes the security level for various parameter sets, considering
both forgery and hash preimage attacks.

Methodology follows the original SPHINCS+ submission:
https://sphincs.org/data/sphincs+-specification.pdf (Appendix A)

Differences from the original SPHINCS+ parameter script:
  1. The original uses upper bound (r/t)^k for P(FORS forgery | r signatures hit
     instance). This script uses the exact formula (1 - (1 - 1/t)^r)^k.
  2. To compute total security, the original sums attack probabilities:
       -log2(2^-n + P(forgery))
     This script takes the max:
       -log2(max(2^-n, P(forgery)))
     Rationale: A query targeting forgery cannot simultaneously serve as a
     preimage query for tree nodes or WOTS chains, because the tweaks are
     different. These are independent attack strategies.

Attack Model:
-------------
The adversary can win by making a hash query that either:
  1. Finds a preimage (probability per query ≈ 2^-n), or
  2. Results in a FORS/PORS+FP forgery

FORS/PORS+FP Forgery Attack:
----------------------------
SPHINCS+ uses 2^h instances (one per hypertree leaf). After q_s signatures,
some instances will have been used multiple times (birthday paradox). The
adversary forges by finding an instance that was used r times, then creating
a message that maps to only revealed leaves in that instance.

Total FORS/PORS+FP forgery probability:
  P(FORS/PORS+FP forgery) = Σ_r P(r signatures hit instance and FORS/PORS+FP forgery)
                          = Σ_r P(r signatures hit instance) × P(FORS/PORS+FP forgery | r signatures hit instance)

where:
  - P(r signatures hit instance) follows a binomial distribution with q_s trials
    and success probability 2^-h. Therefore:
    P(r signatures hit instance) = C(q_s, r) × (2^-h)^r × (1-2^-h)^(q_s-r)
    where C(q_s, r) is the binomial coefficient

  - P(FORS/PORS+FP forgery | r signatures hit instance) is scheme-specific (see below)

FORS Forgery:
-------------
  P(FORS forgery | r signatures hit instance) = (1 - (1 - 1/t)^r)^k,  where t = 2^a

Each of the k FORS trees has t leaves. After r signatures, each tree has r
leaves revealed (one per signature). For forgery, all k trees must have their
required leaf already revealed.
  P(required leaf NOT revealed in single tree) = (1 - 1/t)^r
    (each of r signatures has probability (1 - 1/t) of missing the required leaf)
  P(required leaf revealed in single tree) = 1 - (1 - 1/t)^r
  P(all k trees have required leaf revealed) = (1 - (1 - 1/t)^r)^k

PORS+FP Forgery:
----------------
  P(PORS+FP forgery | r signatures hit instance) = C(min(r*k, t), k) / C(t, k),  where t = k * 2^a

PORS+FP has a single tree with t = k * 2^a leaves. Each signature reveals k
distinct leaves. After r signatures, at most min(r*k, t) leaves are revealed.
For forgery, the adversary must find a message whose k indices all fall within
the revealed set. The number of such "good" messages is C(min(r*k, t), k), out
of C(t, k) total possible index selections.

Total Security:
---------------
-log2(max(2^-n, P(FORS/PORS+FP forgery)))
"""

hashbytes = 16  # 16 bytes = 128 bits

# Parameter sets matching the table order in parameters.tex
# Format: (type, q_s_bits, h, a, k)
# type: "FORS" for FORS/FORS+C, "PORS+FP" for PORS+FP
# Note that parameter a is called "b" in the original SPHINCS+ script
parameter_sets = [
    # Table 1: 2^64 signatures (SPX)
    ("FORS", 64, 63, 12, 14),

    # Table 1: 2^40 signatures - W+C (FORS)
    ("FORS", 40, 44, 16, 8),
    ("FORS", 40, 44, 16, 8),
    ("FORS", 40, 44, 16, 8),
    ("FORS", 40, 40, 14, 11),
    ("FORS", 40, 40, 14, 11),
    # Table 1: 2^40 signatures - W+C F+C (FORS)
    ("FORS", 40, 44, 16, 8),
    ("FORS", 40, 40, 14, 11),
    # Table 1: 2^40 signatures - W+C P+FP (PORS+FP)
    ("PORS+FP", 40, 44, 16, 8),
    ("PORS+FP", 40, 40, 14, 11),

    # Table 1: 2^30 signatures - W+C (FORS)
    ("FORS", 30, 36, 14, 9),
    ("FORS", 30, 33, 15, 9),
    ("FORS", 30, 33, 15, 9),
    ("FORS", 30, 33, 15, 9),
    ("FORS", 30, 32, 14, 10),
    ("FORS", 30, 32, 14, 10),
    # Table 1: 2^30 signatures - W+C F+C (FORS)
    ("FORS", 30, 36, 14, 9),
    ("FORS", 30, 33, 15, 9),
    ("FORS", 30, 33, 15, 9),
    ("FORS", 30, 32, 14, 10),
    # Table 1: 2^30 signatures - W+C P+FP (PORS+FP)
    ("PORS+FP", 30, 36, 14, 9),
    ("PORS+FP", 30, 33, 15, 9),
    ("PORS+FP", 30, 32, 14, 10),

    # Table 2: 2^20 signatures - W+C (FORS)
    ("FORS", 20, 24, 16, 8),
    ("FORS", 20, 24, 16, 8),
    # Table 2: 2^20 signatures - W+C F+C (FORS)
    ("FORS", 20, 24, 16, 8),
    # Table 2: 2^20 signatures - W+C P+FP (PORS+FP)
    ("PORS+FP", 20, 24, 16, 8),
    # Table 2: 2^20 signatures - W+C (FORS)
    ("FORS", 20, 20, 15, 10),
    # Table 2: 2^20 signatures - W+C F+C (FORS)
    ("FORS", 20, 20, 15, 10),
    # Table 2: 2^20 signatures - W+C P+FP (PORS+FP)
    ("PORS+FP", 20, 20, 15, 10),
]

# High precision arithmetic
F = RealField(100)

def pow(p,e):
    """Power function with high precision"""
    return F(p)**e

def qhitprob(q_s, r, leaves):
    """
    Probability that exactly r out of q_s signatures hit the same FORS instance.
    Follows binomial distribution with q_s trials and success probability p = 1/leaves
    """
    p = F(1/leaves)
    return binomial(q_s, r) * pow(p, r) * pow(1-p, q_s-r)

def p_forge_fors(r, k, t):
    """
    P(FORS forgery | r signatures hit instance) = (1 - (1 - 1/t)^r)^k
    """
    return pow(1 - pow(1 - F(1)/F(t), r), k)

def p_forge_pors_fp(r, k, t):
    """
    P(PORS+FP forgery | r signatures hit instance) = C(min(r*k, t), k) / C(t, k)
    """
    return F(binomial(min(r*k, t), k)) / F(binomial(t, k))

def compute_security(q_s, h, k, a, scheme_type):
    """
    Compute security level for given FORS or PORS+FP parameters.

    Args:
        q_s: Number of signatures
        h: Hypertree height (number of instances = 2^h)
        k: Number of trees (FORS) or leaf indices per signature (PORS+FP)
        a: Tree height parameter
        scheme_type: "FORS" or "PORS+FP"

    Returns:
        (forgery_only_security, total_security_bits)
    """
    leaves = 2**h

    if scheme_type == "FORS":
        t = 2**a
        p_forge = p_forge_fors
    else:  # PORS+FP
        t = k * 2**a
        p_forge = p_forge_pors_fp

    # Compute sigma
    # = Σ_r P(r signatures hit instance) × P(forgery | r signatures hit instance)
    sigma = F(0)
    r = 1

    while True:
        # Probability of exactly r collisions to any specific instance
        p_r_collisions = qhitprob(q_s, r, leaves)

        # Contribution to total attack probability
        contribution = p_r_collisions * p_forge(r, k, t)
        sigma += contribution

        r += 1

        # Stop when contribution is negligible (well below target security level)
        # Also require r > q_s/leaves to ensure we're past the peak contribution
        if r > q_s/leaves and contribution < F(2)**(-1250):
            break

    # Compute security bits accounting for hash preimage attack
    preimage_attack_prob = F(1) / F(2**(8*hashbytes))
    total_attack_prob = max(preimage_attack_prob, sigma)

    security_bits = -log(total_attack_prob, 2)
    forgery_only_security = -log(sigma, 2)

    return float(forgery_only_security), float(security_bits)


# Run computation for all parameter sets
print("=" * 75)
print("FORS / PORS+FP Security Analysis")
print("=" * 75)
print()

# Table header
print(f"{'Type':<10} {'q_s':<8} {'h':<4} {'a':<4} {'k':<4} {'Forgery-only':<14} {'Total':<14}")
print("-" * 75)

for scheme_type, q_s_bits, h, a, k in parameter_sets:
    q_s = 2**q_s_bits
    forgery_security, total_security = compute_security(q_s, h, k, a, scheme_type)

    # Print row
    q_s_str = f"2^{q_s_bits}"
    forgery_str = f"{forgery_security:.1f}"
    total_str = f"{total_security:.1f}"
    print(f"{scheme_type:<10} {q_s_str:<8} {h:<4} {a:<4} {k:<4} {forgery_str:<14} {total_str:<14}")

print("=" * 75)
print()
print("Notes:")
print("- Forgery-only: Security against FORS or PORS+FP forgery only")
print("- Total: Security against both forgery and hash preimage attack")
print("=" * 75)
