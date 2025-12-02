#!/usr/bin/env sage
from sage.all import *

"""
SPHINCS+ with FORS Security Analysis

This script computes the security level for various parameter sets, considering
both FORS forgery and hash preimage attacks.

Methodology follows the original SPHINCS+ submission:
https://sphincs.org/data/sphincs+-specification.pdf (Appendix A)
Note: The original script uses an upper bound for P(FORS forgery | r signatures
hit instance), namely (r/t)^k, which slightly underestimates security.
This script uses the exact formula.

Attack Model:
-------------
The adversary can win by making a hash query that either:
  1. Finds a preimage (probability per query ≈ 2^-n), or
  2. Results in a FORS forgery

FORS Forgery Attack:
--------------------
SPHINCS+ uses 2^h FORS instances (one per hypertree leaf). After q_s
signatures, some instances will have been used multiple times (birthday paradox).
The adversary forges by finding an instance that was used r times, then creating
a message that maps to only revealed leaves in that instance.

Total FORS forgery probability:
  P(FORS forgery) = Σ_r P(r signatures hit instance and FORS forgery)
                  = Σ_r P(r signatures hit instance) × P(FORS forgery | r signatures hit instance)

where:
  - P(r signatures hit instance) follows a binomial distribution with q_s trials
    and success probability 2^-h. Therefore:
    P(r signatures hit instance) = C(q_s, r) × (2^-h)^r × (1-2^-h)^(q_s-r)
    where C(q_s, r) is the binomial coefficient

  - P(FORS forgery | r signatures hit instance) = (1 - (1 - 1/t)^r)^k,  where t = 2^a
    Each of the k FORS trees has t leaves. After r signatures, each tree has r
    leaves revealed (one per signature). For forgery, all k trees must have their
    required leaf already revealed.
    P(required leaf NOT revealed in single tree) = (1 - 1/t)^r
      (each of r signatures has probability (1 - 1/t) of missing the required leaf)
    P(required leaf revealed in single tree) = 1 - (1 - 1/t)^r
    P(all k trees have required leaf revealed) = (1 - (1 - 1/t)^r)^k

Total Security: -log2(2^-n + P(FORS forgery))
"""

hashbytes = 16  # 16 bytes = 128 bits

# Parameter sets
# Format: (q_s_bits, h, a, k)
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

def qhitprob(q_s, r, leaves):
    """
    Probability that exactly r out of q_s signatures hit the same FORS instance.
    Follows binomial distribution with q_s trials and success probability p = 1/leaves
    """
    p = F(1/leaves)
    return binomial(q_s, r) * pow(p, r) * pow(1-p, q_s-r)

def compute_security(q_s, h, k, a):
    """
    Compute security level for given FORS parameters.

    Args:
        q_s: Number of signatures
        h: Hypertree height (number of FORS instances = 2^h)
        k: Number of FORS trees
        a: Height of each FORS tree (t = 2^a leaves per tree)

    Returns:
        (fors_only_security, total_security_bits)
        fors_only_security: Security in bits against FORS forgery only
        total_security_bits: Security in bits against both FORS forgery and hash preimage
    """
    leaves = 2**h
    t = 2**a

    # Compute sigma
    # = Σ_r P(r signatures hit instance) × P(FORS forgery | r signatures hit instance)
    sigma = 0
    r = 1

    while True:
        # Probability of forgery given r signatures to a FORS instance
        # P(FORS forgery | r) = (1 - (1 - 1/t)^r)^k
        p_forge = pow(1 - pow(1 - F(1)/F(t), r), k)

        # Probability of exactly r collisions to any specific instance
        p_r_collisions = qhitprob(q_s, r, leaves)

        # Contribution to total attack probability
        contribution = p_r_collisions * p_forge
        sigma += contribution

        r += 1

        # Stop when contribution is negligible (well below target security level)
        # Also require r > q_s/leaves to ensure we're past the peak contribution
        if r > q_s/leaves and contribution < F(2)**(-1250):
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

for q_s_bits, h, a, k in parameter_sets:
    q_s = 2**q_s_bits
    fors_only_security, total_security = compute_security(q_s, h, k, a)

    # Print row
    q_s_str = f"2^{q_s_bits}"
    fors_str = f"{fors_only_security:.1f} bits"
    total_str = f"{total_security:.1f} bits"
    print(f"{q_s_str:<8} {h:<4} {a:<4} {k:<4} {fors_str:<14} {total_str:<14}")

print("=" * 60)
print()
print("Notes:")
print("- FORS-only: Security against FORS forgery only")
print("- Total: Security against both FORS forgery and hash preimage attack")
print("=" * 60)
