#!/usr/bin/env sage
from sage.all import *

"""
SPHINCS+ Parameters Security Analysis

This script computes the security level for various parameter sets, considering
both FORS forgery and hash preimage attacks.

Methodology follows the original SPHINCS+ submission:
https://sphincs.org/data/sphincs+-specification.pdf (Appendix A)

Attack Model:
-------------
The adversary can win by either:
  1. Finding a hash preimage (probability ≈ 2^-n)
  2. Forging a FORS signature

FORS Forgery Attack:
--------------------
SPHINCS+ uses 2^h FORS instances (one per hypertree leaf). After maxsigs
signatures, some instances will have been used multiple times (birthday paradox).
The adversary forges by finding an instance that was used r times, then creating
a message that maps to only the r revealed leaves in that instance.

Total FORS forgery probability:
  P(FORS forge) = Σ_r P(r signatures hit instance and FORS forge)
                = Σ_r P(r signatures hit instance) × P(FORS forge | r signatures hit instance)

where:
  - P(r signatures hit instance) follows a binomial distribution with maxsigs trials
    and success probability 2^-h. Therefore:
    P(r signatures hit instance) = C(maxsigs, r) × (2^-h)^r × (1-2^-h)^(maxsigs-r)
    where C(maxsigs, r) is the binomial coefficient

  - P(FORS forge | r signatures hit instance) = (r/2^a)^k
    Given r signatures to an instance, probability that a random message maps to only
    revealed leaves (r leaves revealed per tree, all k indices must hit: (r/2^a)^k)

Total Security: -log2(2^-n + P(FORS forge))
"""

hashbytes = 16  # 16 bytes = 128 bits

# Parameter sets
# Format: (maxsigs_bits, h, a, k)
# Note that parameter a is called "b" in the original SPHINCS+ script
parameter_sets = [
    # Table 1: 2^64 signatures (SPX)
    (64, 63, 12, 14),

    # Table 1: 2^40 signatures
    (40, 44, 16, 8),
    (40, 40, 14, 11),
    (40, 44, 16, 8),
    (40, 40, 14, 11),

    # Table 1: 2^30 signatures
    (30, 36, 14, 9),
    (30, 33, 15, 9),
    (30, 32, 14, 10),
    (30, 36, 14, 9),
    (30, 33, 15, 9),
    (30, 32, 14, 10),

    # Table 2: 2^20 signatures
    (20, 24, 16, 8),
    (20, 20, 15, 10),
]

# High precision arithmetic
F = RealField(100)

def pow(p,e):
    """Power function with high precision"""
    return F(p)**e

def qhitprob(qs, r, leaves):
    """
    Probability that exactly r out of maxsigs signatures hit the same FORS instance.
    Follows binomial distribution with qs trials and success probability p = 1/leaves
    """
    p = F(1/leaves)
    return binomial(qs, r) * pow(p, r) * pow(1-p, qs-r)

def compute_security(maxsigs, h, k, a):
    """
    Compute security level for given FORS parameters.

    Args:
        maxsigs: Number of signatures
        h: Tree height (number of FORS instances = 2^h)
        k: Number of FORS trees
        a: Height of each FORS tree

    Returns:
        (fors_only_security, total_security_bits)
        fors_only_security: Security in bits against FORS forgery only
        total_security_bits: Security in bits against both FORS forgery and hash preimage
    """
    leaves = 2**h

    # Compute sigma
    # = Σ_r P(r signatures hit instance) × P(FORS forge | r signatures hit instance)
    sigma = 0
    r = 1

    while True:
        # Probability of forgery given r signatures to a FORS instance
        # Each tree has r revealed leaves, probability of hitting all k trees: (r/2^a)^k
        p_forge = min(1, pow(F(r) / F(2**a), k))

        # Probability of exactly r collisions to any specific instance
        p_r_collisions = qhitprob(maxsigs, r, leaves)

        # Contribution to total attack probability
        contribution = p_r_collisions * p_forge
        sigma += contribution

        r += 1

        # Stop when contribution is negligible (well below target security level)
        # Also require r > maxsigs/leaves to ensure we're past the peak contribution
        if r > maxsigs/leaves and contribution < F(2)**(-1250):
            break

    # Compute security bits accounting for hash preimage attack
    preimage_attack_prob = F(1) / F(2**(8*hashbytes))
    total_attack_prob = preimage_attack_prob + sigma

    security_bits = -F(log(total_attack_prob) / log(2))
    fors_only_security = -F(log(sigma) / log(2))

    return float(fors_only_security), float(security_bits)

# Run computation for all parameter sets
print("=" * 60)
print("FORS Security Analysis")
print("=" * 60)
print()

# Table header
print(f"{'q_s':<8} {'h':<4} {'a':<4} {'k':<4} {'FORS-only':<14} {'Total':<14}")
print("-" * 60)

for maxsigs_bits, h, a, k in parameter_sets:
    maxsigs = 2**maxsigs_bits
    fors_only_security, total_security = compute_security(maxsigs, h, k, a)

    # Print row
    qs_str = f"2^{maxsigs_bits}"
    fors_str = f"{fors_only_security:.1f} bits"
    total_str = f"{total_security:.1f} bits"
    print(f"{qs_str:<8} {h:<4} {a:<4} {k:<4} {fors_str:<14} {total_str:<14}")

print("=" * 60)
print()
print("Notes:")
print("- FORS-only: Security against FORS forgery only")
print("- Total: Security against both FORS forgery and hash preimage attack")
print("=" * 60)
