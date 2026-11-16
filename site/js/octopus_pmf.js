// PORS+FP grinding, a port of octopus_pmf.py, which is copied from https://github.com/MehdiAbri/PORS-FP.
// SPDX-License-Identifier: MIT
//
// The port returns the same doubles as the Python original: binomials are exact integers, every
// ratio is rounded once, and the sums run in the same order.
'use strict';

const interleaveCostTable = (function () {
  // Binomial coefficient as a BigInt; 0 outside 0 <= k <= n.
  function comb(n, k) {
    if (n < 0 || k < 0 || k > n) return 0n;
    if (k > n - k) k = n - k;
    let num = 1n, den = 1n;
    for (let i = 0; i < k; i++) { num *= BigInt(n - i); den *= BigInt(i + 1); }
    return num / den;
  }

  // x * 2^e without an intermediate overflow or underflow.
  function scale(x, e) {
    for (; e < -1000; e += 1000) x *= 2 ** -1000;
    for (; e > 1000; e -= 1000) x *= 2 ** 1000;
    return x * 2 ** e;
  }

  // num / den for BigInts num >= 0 and den > 0, rounded once to the nearest double.
  function ratio(num, den) {
    if (num === 0n) return 0;
    // Shift so that the quotient has about 64 bits; a sticky bit stands for the remainder.
    const shift = 64 + 4 * (den.toString(16).length - num.toString(16).length);
    let q, exact;
    if (shift >= 0) {
      const scaled = num << BigInt(shift);
      q = scaled / den;
      exact = q * den === scaled;
    } else {
      const scaled = den << BigInt(-shift);
      q = num / scaled;
      exact = q * scaled === num;
    }
    if (!exact) q |= 1n;
    return scale(Number(q), -shift);
  }

  // Probability that j leaves chosen at random among x, x even, hold s full sibling pairs.
  const pCache = new Map();
  function P(x, j, s) {
    if (x % 2 !== 0 || j < 0 || s < 0 || j > x || 2 * s > j) return 0;
    const key = x + ',' + j + ',' + s;
    let p = pCache.get(key);
    if (p === undefined) {
      const num = comb(x / 2, j - s) * comb(j - s, s) * (1n << BigInt(j - 2 * s));
      p = ratio(num, comb(x, j));
      pCache.set(key, p);
    }
    return p;
  }

  // A distribution is a Float64Array indexed by the number of nodes, cut after its last
  // non-zero entry; the empty array is the impossible event.
  const NONE = new Float64Array(0);
  function trimmed(dist) {
    let n = dist.length;
    while (n > 0 && dist[n - 1] === 0) n--;
    return dist.slice(0, n);
  }

  // out[singles + m] += w * dist[m] for every m.
  function addShifted(out, dist, singles, w) {
    for (let m = 0; m < dist.length; m++) out[singles + m] += w * dist[m];
  }

  // Distribution of the authentication nodes above level ell. The level has L nodes left of
  // the boundary and R right of it, with kL and kR of them selected; c says whether the first
  // node right of the boundary is forced selected (+1), forbidden (-1) or free (0).
  const mCache = new Map();
  function M(ell, L, R, kL, kR, c) {
    const key = ell + ',' + L + ',' + R + ',' + kL + ',' + kR + ',' + c;
    let out = mCache.get(key);
    if (out === undefined) {
      out = upperLevels(ell, L, R, kL, kR, c);
      mCache.set(key, out);
    }
    return out;
  }

  function upperLevels(ell, L, R, kL, kR, c) {
    if (ell === 0) return Float64Array.of(1);
    if (!(0 <= kL && kL <= L && 0 <= kR && kR <= R)) return NONE;

    // Each selected node adds at most one authentication node per level.
    const out = new Float64Array((kL + kR) * ell + 1);
    const half = n => Math.floor(n / 2);

    if (L % 2 === 0) {
      // Even L: the boundary does not cut a sibling pair.
      if (c === 0) {
        for (let rL = 0; rL <= half(kL); rL++) {
          const wL = P(L, kL, rL);
          if (wL === 0) continue;
          for (let rR = 0; rR <= half(kR); rR++) {
            const wR = P(R, kR, rR);
            if (wR === 0) continue;
            const singles = (kL + kR) - 2 * (rL + rR);
            addShifted(out, M(ell - 1, half(L), half(R), kL - rL, kR - rR, 0), singles, wL * wR);
          }
        }
      } else if (c === 1) {
        if (R < 1 || kR < 1) return NONE;
        if (R === 1) {
          // Only the forced node exists on the right.
          for (let rL = 0; rL <= half(kL); rL++) {
            const wL = P(L, kL, rL);
            if (wL === 0) continue;
            const singles = (kL + kR) - 2 * rL;
            addShifted(out, M(ell - 1, half(L), 0, kL - rL, kR, 1), singles, wL);
          }
        } else {
          const denom = comb(R - 1, kR - 1);
          if (denom === 0n) return NONE;
          // y: whether the sibling of the forced node is selected.
          const wY1 = ratio(comb(R - 2, kR - 2), denom);
          const wY0 = ratio(comb(R - 2, kR - 1), denom);
          for (let rL = 0; rL <= half(kL); rL++) {
            const wL = P(L, kL, rL);
            if (wL === 0) continue;
            for (const [y, wy] of [[1, wY1], [0, wY0]]) {
              if (wy === 0) continue;
              for (let rRp = 0; rRp <= half(kR - 1 - y); rRp++) {
                const wRp = P(R - 2, kR - 1 - y, rRp);
                if (wRp === 0) continue;
                const rR = y + rRp;
                const singles = (kL + kR) - 2 * (rL + rR);
                addShifted(out, M(ell - 1, half(L), half(R), kL - rL, kR - rR, 1), singles, wL * wy * wRp);
              }
            }
          }
        }
      } else {
        // c === -1: the first node right of the boundary is forbidden.
        if (R <= 1) {
          if (kR !== 0) return NONE;
          for (let rL = 0; rL <= half(kL); rL++) {
            const wL = P(L, kL, rL);
            if (wL === 0) continue;
            const singles = (kL + kR) - 2 * rL;
            addShifted(out, M(ell - 1, half(L), 0, kL - rL, kR, -1), singles, wL);
          }
        } else {
          const denom = comb(R - 1, kR);
          if (denom === 0n) return NONE;
          // z: whether the sibling of the forbidden node is selected.
          const wZ0 = ratio(comb(R - 2, kR), denom);
          const wZ1 = ratio(comb(R - 2, kR - 1), denom);
          for (let rL = 0; rL <= half(kL); rL++) {
            const wL = P(L, kL, rL);
            if (wL === 0) continue;
            for (const [z, wz] of [[0, wZ0], [1, wZ1]]) {
              if (wz === 0) continue;
              for (let rRp = 0; rRp <= half(kR - z); rRp++) {
                const wRp = P(R - 2, kR - z, rRp);
                if (wRp === 0) continue;
                const singles = (kL + kR) - 2 * (rL + rRp);
                addShifted(out, M(ell - 1, half(L), half(R), kL - rL, kR - rRp, z === 1 ? 1 : -1),
                  singles, wL * wz * wRp);
              }
            }
          }
        }
      }
      return trimmed(out);
    }

    // Odd L: the boundary cuts a sibling pair, the last node on the left and the first on the right.
    const denomL = comb(L, kL);
    if (denomL === 0n) return NONE;
    const lNext = half(L - 1), rNext = half(R - 1) + 1;
    // xL: whether the last node on the left is selected.
    const wXL = xL => (0 <= kL - xL && kL - xL <= L - 1) ? ratio(comb(L - 1, kL - xL), denomL) : 0;

    if (c === 0) {
      const denomR = comb(R, kR);
      if (denomR === 0n) return NONE;
      for (const xL of [0, 1]) {
        const wxL = wXL(xL);
        if (wxL === 0) continue;
        for (const xR of [0, 1]) {
          const wxR = (0 <= kR - xR && kR - xR <= R - 1) ? ratio(comb(R - 1, kR - xR), denomR) : 0;
          if (wxR === 0) continue;
          const kLin = kL - xL, kRin = kR - xR;
          for (let rL = 0; rL <= half(kLin); rL++) {
            const wL = P(L - 1, kLin, rL);
            if (wL === 0) continue;
            for (let rR = 0; rR <= half(kRin); rR++) {
              const wR = P(R - 1, kRin, rR);
              if (wR === 0) continue;
              const merge = xL * xR;
              const singles = (kL + kR) - 2 * (rL + rR + merge);
              addShifted(out,
                M(ell - 1, lNext, rNext, kL - xL - rL, kR - xR - rR + (xL + xR - merge), xL + xR >= 1 ? 1 : -1),
                singles, wxL * wxR * wL * wR);
            }
          }
        }
      }
    } else if (c === 1) {
      if (R < 1 || kR < 1) return NONE;
      for (const xL of [0, 1]) {
        const wxL = wXL(xL);
        if (wxL === 0) continue;
        const kLin = kL - xL, kRin = kR - 1;
        for (let rL = 0; rL <= half(kLin); rL++) {
          const wL = P(L - 1, kLin, rL);
          if (wL === 0) continue;
          for (let rR = 0; rR <= half(kRin); rR++) {
            const wR = P(R - 1, kRin, rR);
            if (wR === 0) continue;
            const singles = (kL + kR) - 2 * (rL + rR + xL);
            addShifted(out, M(ell - 1, lNext, rNext, kL - xL - rL, kR - rR, 1), singles, wxL * wL * wR);
          }
        }
      }
    } else {
      if (R < 1) return NONE;
      for (const xL of [0, 1]) {
        const wxL = wXL(xL);
        if (wxL === 0) continue;
        const kLin = kL - xL;
        for (let rL = 0; rL <= half(kLin); rL++) {
          const wL = P(L - 1, kLin, rL);
          if (wL === 0) continue;
          for (let rR = 0; rR <= half(kR); rR++) {
            const wR = P(R - 1, kR, rR);
            if (wR === 0) continue;
            const singles = (kL + kR) - 2 * (rL + rR);
            addShifted(out, M(ell - 1, lNext, rNext, kL - xL - rL, kR - rR + xL, xL === 1 ? 1 : -1),
              singles, wxL * wL * wR);
          }
        }
      }
    }
    return trimmed(out);
  }

  // Distribution of the size of the authentication set.
  function pmfLeftFilled(t, k) {
    if (!(1 <= k && k <= t)) return NONE;
    const denom = comb(t, k);
    if (denom === 0n) return NONE;

    // The tree has height h. Its bottom level holds x = 2 * L leaves; the level above holds
    // their L parents on the left and the other p - L leaves on the right.
    let h = 0;
    while (2 ** h < t) h++;
    const p = h > 0 ? 2 ** (h - 1) : 1;
    const L = t - p;
    const x = 2 * L;
    const pmf = new Float64Array(k * (h + 1) + 1);

    // j leaves selected on the bottom level, s full sibling pairs among them.
    for (let j = 0; j <= Math.min(k, x); j++) {
      const wj = ratio(comb(x, j) * comb(t - x, k - j), denom);
      if (wj === 0) continue;
      for (let s = 0; s <= Math.floor(j / 2); s++) {
        const ws = P(x, j, s);
        if (ws === 0) continue;
        const upper = M(Math.max(h - 1, 0), h > 0 ? L : 0, h > 0 ? p - L : 0, j - s, k - j, 0);
        addShifted(pmf, upper, j - 2 * s, wj * ws);
      }
    }
    return trimmed(pmf);
  }

  return function interleaveCostTable(t, k) {
    const pmf = pmfLeftFilled(t, k);
    // The caches only help within one (t, k).
    mCache.clear();
    pCache.clear();
    const table = new Map();
    let cdf = 0;
    for (let m = 0; m < pmf.length; m++) {
      cdf += pmf[m];
      if (cdf > 0) table.set(m, -Math.log2(cdf));
    }
    return table;
  };
})();
