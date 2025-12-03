from __future__ import annotations

import math
from collections import defaultdict
from functools import lru_cache
from typing import Dict, Tuple, List


# ---------- Combinatorics helpers ----------

def comb(n: int, k: int) -> int:
    if n < 0 or k < 0 or k > n:
        return 0
    return math.comb(n, k)

def P(x: int, j: int, s: int) -> float:
    if x % 2 != 0 or j < 0 or s < 0 or j > x or 2 * s > j:
        return 0.0
    num = comb(x // 2, j - s) * comb(j - s, s) * (2 ** (j - 2 * s))
    den = comb(x, j)
    if den == 0:
        return 0.0
    return num / den


# ---------- Upper-level recursion M_h(L,R,k_L,k_R,c) with c ∈ {-1, 0, +1} ----------

@lru_cache(maxsize=None)
def M(ell: int, L: int, R: int, kL: int, kR: int, c: int = 0) -> Dict[int, float]:

    # Base case 
    if ell == 0:
        return {0: 1.0}

    # Impossible states yield empty distribution
    if not (0 <= kL <= L and 0 <= kR <= R):
        return {}

    out: Dict[int, float] = defaultdict(float)

    if L % 2 == 0:
        # -------- Even L: boundary does NOT cut a sibling pair
        if c == 0:
            # Independent pair-merge laws on left and right
            for rL in range(0, kL // 2 + 1):
                wL = P(L, kL, rL)
                if wL == 0.0:
                    continue
                for rR in range(0, kR // 2 + 1):
                    wR = P(R, kR, rR)
                    if wR == 0.0:
                        continue
                    singles = (kL + kR) - 2 * (rL + rR)
                    nxt = M(ell - 1, L // 2, R // 2, kL - rL, kR - rR, 0)  # c' = 0
                    w = wL * wR
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += w * p_sub

        elif c == +1:
            # Boundary index is forced selected
            if R < 1 or kR < 1:
                return {}
            if R == 1:
                # Only the forced index exists; sibling doesn't exist => Y=0 deterministically
                for rL in range(0, kL // 2 + 1):
                    wL = P(L, kL, rL)
                    if wL == 0.0:
                        continue
                    rR = 0
                    singles = (kL + kR) - 2 * (rL + rR)
                    nxt = M(ell - 1, L // 2, 0, kL - rL, kR - rR, +1)  # c' stays +1
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += wL * p_sub
            else:
                denom = comb(R - 1, kR - 1)
                if denom == 0:
                    return {}
                # Y: whether the sibling of the forced index is selected
                wY1 = comb(R - 2, kR - 2) / denom  
                wY0 = comb(R - 2, kR - 1) / denom  
                for rL in range(0, kL // 2 + 1):
                    wL = P(L, kL, rL)
                    if wL == 0.0:
                        continue
                    for y, wy in ((1, wY1), (0, wY0)):
                        if wy == 0.0:
                            continue
                        # Interior on the right has size R-2 and kR-1-y picks
                        for rRprime in range(0, (kR - 1 - y) // 2 + 1):
                            wRprime = P(R - 2, kR - 1 - y, rRprime)
                            if wRprime == 0.0:
                                continue
                            rR = y + rRprime
                            singles = (kL + kR) - 2 * (rL + rR)
                            nxt = M(
                                ell - 1, L // 2, R // 2, kL - rL, kR - rR, +1  # c' = +1
                            )
                            w = wL * wy * wRprime
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

        else:  # c == -1
            # Boundary index is forbidden
            if R == 0:
                if kR != 0:
                    return {}
                for rL in range(0, kL // 2 + 1):
                    wL = P(L, kL, rL)
                    if wL == 0.0:
                        continue
                    rRprime = 0
                    singles = (kL + kR) - 2 * (rL + rRprime)
                    nxt = M(ell - 1, L // 2, 0, kL - rL, kR - rRprime, -1)
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += wL * p_sub
            elif R == 1:
                if kR != 0:
                    return {}
                for rL in range(0, kL // 2 + 1):
                    wL = P(L, kL, rL)
                    if wL == 0.0:
                        continue
                    rRprime = 0
                    singles = (kL + kR) - 2 * (rL + rRprime)
                    nxt = M(ell - 1, L // 2, 0, kL - rL, kR - rRprime, -1)
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += wL * p_sub
            else:
                denom = comb(R - 1, kR)
                if denom == 0:
                    return {}
                # Z: whether position 1 (the sibling of forbidden 0) is selected
                wZ0 = comb(R - 2, kR - 0) / denom  # choose all kR from {2..R-1}
                wZ1 = comb(R - 2, kR - 1) / denom  # choose 1 at index 1, rest from {2..R-1}
                for rL in range(0, kL // 2 + 1):
                    wL = P(L, kL, rL)
                    if wL == 0.0:
                        continue
                    for z, wz in ((0, wZ0), (1, wZ1)):
                        if wz == 0.0:
                            continue
                        for rRprime in range(0, (kR - z) // 2 + 1):
                            wRprime = P(R - 2, kR - z, rRprime)
                            if wRprime == 0.0:
                                continue
                            singles = (kL + kR) - 2 * (rL + rRprime)
                            c_next = +1 if z == 1 else -1
                            nxt = M(
                                ell - 1, L // 2, R // 2, kL - rL, kR - rRprime, c_next
                            )
                            w = wL * wz * wRprime
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

    else:
        # -------- Odd L: boundary DOES cut a sibling pair (between positions L-1 and L)
        denomL = comb(L, kL)
        if denomL == 0:
            return {}

        if c == 0:
            denomR = comb(R, kR)
            if denomR == 0:
                return {}
            for xL in (0, 1):
                w_xL = comb(L - 1, kL - xL) / denomL if 0 <= kL - xL <= L - 1 else 0.0
                if w_xL == 0.0:
                    continue
                for xR in (0, 1):
                    w_xR = comb(R - 1, kR - xR) / denomR if 0 <= kR - xR <= R - 1 else 0.0
                    if w_xR == 0.0:
                        continue
                    kL_in = kL - xL
                    kR_in = kR - xR
                    for rL in range(0, kL_in // 2 + 1):
                        wL = P(L - 1, kL_in, rL)
                        if wL == 0.0:
                            continue
                        for rR in range(0, kR_in // 2 + 1):
                            wR = P(R - 1, kR_in, rR)
                            if wR == 0.0:
                                continue
                            boundary_merge = xL * xR
                            singles = (kL + kR) - 2 * (rL + rR + boundary_merge)
                            kL_next = kL - xL - rL
                            kR_next = kR - xR - rR + (xL + xR - boundary_merge)
                            L_next = (L - 1) // 2
                            R_next = (R - 1) // 2 + 1
                            c_next = +1 if (xL + xR) >= 1 else -1
                            nxt = M(ell - 1, L_next, R_next, kL_next, kR_next, c_next)
                            w = w_xL * w_xR * wL * wR
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

        elif c == +1:
            if R < 1 or kR < 1:
                return {}
            for xL in (0, 1):
                w_xL = comb(L - 1, kL - xL) / denomL if 0 <= kL - xL <= L - 1 else 0.0
                if w_xL == 0.0:
                    continue
                kL_in = kL - xL
                kR_in = kR - 1  # xR = 1 fixed
                for rL in range(0, kL_in // 2 + 1):
                    wL = P(L - 1, kL_in, rL)
                    if wL == 0.0:
                        continue
                    for rR in range(0, kR_in // 2 + 1):
                        wR = P(R - 1, kR_in, rR)
                        if wR == 0.0:
                            continue
                        boundary_merge = xL  # xR=1
                        singles = (kL + kR) - 2 * (rL + rR + boundary_merge)
                        kL_next = kL - xL - rL
                        kR_next = kR - rR  # = kR - 1 - rR + 1
                        L_next = (L - 1) // 2
                        R_next = (R - 1) // 2 + 1
                        c_next = +1  
                        nxt = M(ell - 1, L_next, R_next, kL_next, kR_next, c_next)
                        w = w_xL * wL * wR
                        for m_sub, p_sub in nxt.items():
                            out[singles + m_sub] += w * p_sub

        else:  # c == -1
            if R < 1:
                return {}
            for xL in (0, 1):
                w_xL = comb(L - 1, kL - xL) / denomL if 0 <= kL - xL <= L - 1 else 0.0
                if w_xL == 0.0:
                    continue
                kL_in = kL - xL
                kR_in = kR  # xR = 0 fixed
                for rL in range(0, kL_in // 2 + 1):
                    wL = P(L - 1, kL_in, rL)
                    if wL == 0.0:
                        continue
                    for rR in range(0, kR_in // 2 + 1):
                        wR = P(R - 1, kR_in, rR)
                        if wR == 0.0:
                            continue
                        boundary_merge = 0  # xR=0
                        singles = (kL + kR) - 2 * (rL + rR + boundary_merge)
                        kL_next = kL - xL - rL
                        kR_next = kR - rR + (xL + 0 - 0)  # add parent iff xL=1
                        L_next = (L - 1) // 2
                        R_next = (R - 1) // 2 + 1
                        c_next = +1 if xL == 1 else -1
                        nxt = M(ell - 1, L_next, R_next, kL_next, kR_next, c_next)
                        w = w_xL * wL * wR
                        for m_sub, p_sub in nxt.items():
                            out[singles + m_sub] += w * p_sub

    return dict(out)  


# ---------- Full PMF via Theorem 3 ----------

def pmf_leftfilled(t: int, k: int) -> Dict[int, float]:

    if not (1 <= k <= t):
        return {}

    # h = ceil(log2 t); p = 2^(h-1) for h>=1 (else 1); L = t - p; x = 2L (bottom-layer population)
    h = (t - 1).bit_length()
    p = 1 << (h - 1) if h > 0 else 1
    L = t - p
    x = 2 * L

    pmf: Dict[int, float] = defaultdict(float)

    denom = comb(t, k)
    if denom == 0:
        return {}

    # Hypergeometric j = #selected among bottom x leaves
    for j in range(0, min(k, x) + 1):
        wj = comb(x, j) * comb(t - x, k - j) / denom
        if wj == 0.0:
            continue

        # s = number of full sibling pairs among those j bottom selections
        for s in range(0, j // 2 + 1):
            ws = P(x, j, s)
            if ws == 0.0:
                continue

            singles_bottom = j - 2 * s  # bottom-layer contribution

            # Initialize upper process at level h-1:
            # left block size L, right block size (p - L)
            # counts: kL = j - s, kR = k - j; carry c=0
            upper = M(
                max(h - 1, 0),
                L if h > 0 else 0,
                (p - L) if h > 0 else 0,
                j - s,
                k - j,
                0,  # start with no constraint at boundary
            )
            w = wj * ws
            for m_up, p_up in upper.items():
                pmf[singles_bottom + m_up] += w * p_up

    return dict(pmf)


# ---------- Output: (m_max  log2 E[work]) ----------

def interleave_cost_table(t: int, k: int) -> List[Tuple[int, float]]:
    pmf = pmf_leftfilled(t, k)
    if not pmf:
        return []

    M_max = max(pmf)
    cdf = []
    run = 0.0
    for m in range(M_max + 1):
        run += pmf.get(m, 0.0)
        cdf.append(run)

    table: List[Tuple[int, float]] = []
    for m_max, prob in enumerate(cdf):
        if prob > 0:
            table.append((m_max, -math.log2(prob)))
    return table
