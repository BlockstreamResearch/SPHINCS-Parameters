#!/usr/bin/env sage
"""
Security in bits of FORS and PORS+FP after q_s signatures: the forgery
probability summed over how often the attacked instance was used, capped by
the 8n-bit preimage bound (docs/model.md, FORS security). costs.sage loads
this file; run alone, it prints the security of SLH-DSA-128s at 2^64 signatures.

  sage model/security.sage
"""
from sage.all import *
import sys

F = RealField(100)   # the terms reach 2^-1250, below what a double holds

def powF(p, e):
    return F(p)**e

def qhitprob(q_s, r, leaves):
    """P(a given instance among `leaves` is used by exactly r of q_s signatures)."""
    p = F(1/leaves)
    return binomial(q_s, r) * powF(p, r) * powF(1-p, q_s-r)

def p_forge_fors(r, k, t):
    """P(FORS forgery | r signatures on the instance) = (1 - (1 - 1/t)^r)^k."""
    return powF(1 - powF(1 - F(1)/F(t), r), k)

def p_forge_pors_fp(r, k, t):
    """P(PORS+FP forgery | r signatures on the instance) = C(min(r*k, t), k) / C(t, k)."""
    return F(binomial(min(r*k, t), k)) / F(binomial(t, k))

def compute_security(q_s, h, k, a, scheme_type, hashbytes=16):
    """Security in bits, at most 8*hashbytes, of 2^h instances of FORS (k trees
    of t = 2^a leaves) or PORS+FP (one tree of t = k*2^a leaves) after q_s
    signatures. scheme_type is "FORS" or "PORS+FP"."""
    leaves = 2**h

    if scheme_type == "FORS":
        t = 2**a
        p_forge = p_forge_fors
    else:  # PORS+FP
        t = k * 2**a
        p_forge = p_forge_pors_fp

    sigma = F(0)
    r = 1

    while True:
        contribution = qhitprob(q_s, r, leaves) * p_forge(r, k, t)
        sigma += contribution

        r += 1

        # Past the mean q_s/leaves, stop at the first term below 2^-1250.
        if r > q_s/leaves and contribution < F(2)**(-1250):
            break

    preimage_attack_prob = F(1) / F(2**(8*hashbytes))
    total_attack_prob = max(preimage_attack_prob, sigma)

    security_bits = -log(total_attack_prob, 2)

    return float(security_bits)


# Runs only when invoked directly, not when another script load()s this file.
if sys.argv[0].endswith('security.sage') or sys.argv[0].endswith('security.sage.py'):
    # SLH-DSA-128s
    q_s = 2**64
    h = 63
    a = 12
    k = 14
    scheme_type = "FORS"

    security = compute_security(q_s, h, k, a, scheme_type)

    print("=" * 40)
    print(f"Parameters: q_s=2^64, h={h}, a={a}, k={k}, type={scheme_type}")
    print(f"Security level: {security:.1f} bits")
    print("=" * 40)
