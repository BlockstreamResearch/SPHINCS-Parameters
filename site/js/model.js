// Cost and security model shared by the three site pages.
'use strict';

// ---------- Cost-model constants  ----------

const N = 16;

const R_SIZE = 16;

// SHRINCS puts a one-byte indicator in front of every signature (the tree
// height for the stateless path, the leaf height for the stateful path).
const IND_SIZE = 1;

const C_Th1 = 1;

const C_Th1c = 1;

const C_Th2 = 1;

// Message hash and message PRF for a 32-byte message and an empty context,
// as executed by the SHRINCS reference implementation:
//   H_msg   = two nested SHA-256 calls of 2 compressions each (its input
//             starts with the randomizer R, so nothing can be cached);
//   PRF_msg = HMAC-SHA-256, 2 + 1 compressions once its two key-pad blocks
//             are cached like the PK.seed block.
const C_Hmsg = 4;

const C_PRFmsg = 3;

const C_PRF = 1;

const WOTS_C_SWN = { 16: 240, 32: 403, 64: 693, 128: 1206, 256: 2040, 65536: 262140 };

const UXMSS_TARGET_SIZE = 5712;

const SLH = { h: 63, d: 7, k: 14, a: 12, w: 16 };

const HSF_MAX = 255;


// ---------- Helpers ----------

function idxBytes(h) { return Math.max(1, Math.ceil(h / 8)); }

function computeTh(n) { return Math.ceil((176 + 128 * n + 65) / 512); }

// WOTS+C grinding counter. SHRINCS stores it in 2 bytes: 2^16 counters miss
// the target sum with probability below 2^-126 for every w <= 256. w = 65536
// needs about 137,000 attempts on average and keeps a 4-byte counter.
function counterBytes(w) { return w <= 256 ? 2 : 4; }


// ---------- WOTS-TW average verification ----------

function binomBig(n, k) {
  if (k < 0n || k > n) return 0n;
  if (k === 0n || k === n) return 1n;
  if (k > n - k) k = n - k;
  let num = 1n, den = 1n;
  for (let i = 0n; i < k; i++) { num *= (n - i); den *= (i + 1n); }
  return num / den;
}

// w^l1 * sum_{j=1}^{l2-1} E[floor(S / w^j)] as an exact BigInt, where S is
// the sum of l1 independent uniform base-w digits. Uses
//   E[floor(S / w^j)] = sum_{m>=1} P(S >= m*w^j)
// and the inclusion-exclusion count of digit strings with sum <= t:
//   sum_i (-1)^i * C(l1, i) * C(t - i*w + l1, l1).
const _wotsTwFloorCache = new Map();

function wotsTwFloorSum(l1, l2, w) {
  const key = l1 + ',' + l2 + ',' + w;
  if (_wotsTwFloorCache.has(key)) return _wotsTwFloorCache.get(key);
  const L1 = BigInt(l1), wB = BigInt(w);
  const top = L1 * (wB - 1n);
  const W = wB ** L1;
  const countLe = (t) => {
    let total = 0n;
    for (let i = 0n; i <= L1 && i * wB <= t; i++) {
      const term = binomBig(L1, i) * binomBig(t - i * wB + L1, L1);
      total += (i % 2n === 0n) ? term : -term;
    }
    return total;
  };
  let acc = 0n;
  for (let j = 1; j < l2; j++) {
    const step = wB ** BigInt(j);
    for (let m = 1n; m * step <= top; m++) acc += W - countLe(m * step - 1n);
  }
  _wotsTwFloorCache.set(key, acc);
  return acc;
}

// Mean chain steps to verify `count` WOTS-TW signatures on uniformly random
// digests, rounded to the nearest integer (compute_wots_tw_mean_steps in
// costs.sage).
//
// The l1 message chains average (w-1)/2 steps each, but the l2 checksum
// chains do not: the checksum is concentrated around l1*(w-1)/2, so its
// leading digit is almost always 0 or 1 and the verifier walks most of that
// chain. Exactly,
//   E[steps] = (w-1) * (l2 + sum_{j=1}^{l2-1} E[floor(S / w^j)])
// (267.12 for w = 16, where (w-1)*len/2 would give 262).
function wotsTwMeanSteps(w, count = 1) {
  const l1 = Math.ceil(8 * N / Math.log2(w));
  const l2 = Math.floor(Math.log2(l1 * (w - 1)) / Math.log2(w)) + 1;
  const W = BigInt(w) ** BigInt(l1);
  const num = BigInt(count) * BigInt(w - 1) * (BigInt(l2) * W + wotsTwFloorSum(l1, l2, w));
  return Number((2n * num + W) / (2n * W));   // round to nearest
}


// ---------- WOTS family ----------

function wotsL(w, ots) {
  const l1 = Math.ceil(8 * N / Math.log2(w));
  if (ots === 'WC') return l1;
  // FIPS 205 form: len2 = floor(log_w(len1*(w-1))) + 1
  const l2 = Math.floor(Math.log2(l1 * (w - 1)) / Math.log2(w)) + 1;
  return l1 + l2;
}

function wotsThl(l, ots) {
  return computeTh(l);
}

function wotsPkC(w, ots) {
  const l = wotsL(w, ots);
  return l * C_PRF + l * (w - 1) * C_Th1 + wotsThl(l, ots);
}

function computeNu(l, swn, w) {
  const lB = BigInt(l), swnB = BigInt(swn), wB = BigInt(w);
  let nu = 0n;
  for (let j = 0n; j <= lB; j++) {
    const sign = (j % 2n === 0n) ? 1n : -1n;
    const b1 = binomBig(lB, j);
    const nVal = (swnB + lB) - j * wB - 1n;
    let b2 = 0n;
    if (nVal >= lB - 1n && lB > 0n) b2 = binomBig(nVal, lB - 1n);
    nu += sign * b1 * b2;
  }
  return nu > 0n ? nu : 1n;
}

function wotsSignC(w, swn, ots) {
  const l = wotsL(w, ots);
  if (ots === 'WC') {
    const nu = computeNu(l, swn, w);
    const wToL = BigInt(w) ** BigInt(l);
    const searchBig = wToL / nu + ((wToL % nu === 0n) ? 0n : 1n);
    const search = Number(searchBig);   // typically small, fits in double
    return search * C_Th1c + l * C_PRF + swn * C_Th1;
  }
  // WOTS-TW: the signer walks the part of each chain the verifier does not.
  return l * C_PRF + (l * (w - 1) - wotsTwMeanSteps(w)) * C_Th1;
}

function wotsVerifyWorstSteps(w) {
  const l1 = Math.ceil(8 * N / Math.log2(w));
  const l2 = Math.floor(Math.log2(l1 * (w - 1)) / Math.log2(w)) + 1;
  const C = l1 * (w - 1);
  let ds = 0, rem = C;
  while (rem > 0) { ds += rem % w; rem = Math.floor(rem / w); }
  return l1 * (w - 1) + l2 * (w - 1) - ds;
}

// Compressions to verify `count` WOTS signatures.
function wotsVerifyC(w, swn, ots, worstCase, count = 1) {
  const l = wotsL(w, ots);
  const Thl = wotsThl(l, ots);
  if (ots === 'WC') return count * (((w - 1) * l - swn) * C_Th1 + C_Th1c + Thl);
  if (worstCase) return count * (wotsVerifyWorstSteps(w) * C_Th1 + Thl);
  return wotsTwMeanSteps(w, count) * C_Th1 + count * Thl;
}


// ---------- XMSS / XMSS-MT ----------

function treeSizePerLayer(hPrime, w, ots) {
  const l = wotsL(w, ots);
  const ctr = (ots === 'WC') ? counterBytes(w) : 0;
  return hPrime * N + l * N + ctr;
}

function treeKeygenC(hPrime, w, ots) {
  // 2^h' WOTS keypairs + 2^h' − 1 internal hashes
  const pk = wotsPkC(w, ots);
  const sz = Math.pow(2, hPrime);
  return sz * pk + (sz - 1) * C_Th2;
}

function treeVerifyC(hPrime, w, swn, ots, worstCase, count = 1) {
  return wotsVerifyC(w, swn, ots, worstCase, count) + count * hPrime * C_Th2;
}

// BDS tree traversal (Buchmann, Dahmen, Schneider 2008) for a tree of height
// h' with parameter K (K >= 2, h' - K even): per signature at most
// (h'-K)/2 + 1 leaf computations and 3(h'-K-1)/2 + 1 node hashes. The
// long-run average is about one leaf computation below the bound. The state
// is counted as for the SHRINCS signer caches: h' authentication nodes,
// floor(h'/2) keep nodes, 2^K - K - 1 retained nodes, h' - K completed
// treehash nodes and a stack of h' - K - 1 partial results.
function bdsK(hPrime) {
  if (hPrime < 2) return hPrime;
  return hPrime % 2 === 0 ? 2 : 3;
}

function bdsLeaves(hPrime) { return Math.floor((hPrime - bdsK(hPrime)) / 2) + 1; }

function bdsHashes(hPrime) {
  return Math.floor(3 * Math.max(0, hPrime - bdsK(hPrime) - 1) / 2) + 1;
}

function bdsStateNodes(hPrime) {
  const k = bdsK(hPrime);
  return hPrime + Math.floor(hPrime / 2) + (Math.pow(2, k) - k - 1)
       + Math.max(0, hPrime - k) + Math.max(0, hPrime - k - 1);
}

// Signature layout (SHRINCS stateful path), used for every scheme here:
//   indicator | R | leaf index | per layer: [counter] + WOTS chains + auth path
function xmssMtSize(h, d, w, ots) {
  const hPrime = h / d;
  return IND_SIZE + R_SIZE + idxBytes(h) + d * treeSizePerLayer(hPrime, w, ots);
}

function xmssMtKeygenC(h, d, w, ots) {
  // Build only the top tree (others are derived during signing).
  return treeKeygenC(h / d, w, ots);
}

function xmssMtSignBdsC(h, d, w, swn, ots) {
  // Cached signer: one BDS update per layer and signature (upper bound).
  const hPrime = h / d;
  const pk = wotsPkC(w, ots);
  const cSg = wotsSignC(w, swn, ots);
  return C_Hmsg + C_PRFmsg + cSg
       + d * (bdsLeaves(hPrime) * pk + bdsHashes(hPrime) * C_Th2);
}

function xmssMtSignColdC(h, d, w, swn, ots) {
  // State-minimized signer: rebuild d trees of height h' per signature. The
  // top tree only needs its authentication path: the other 2^h' - 1 leaves
  // and every internal node except the h' on the signing leaf's own path.
  const hPrime = h / d;
  return C_Hmsg + C_PRFmsg + d * (treeKeygenC(hPrime, w, ots) + wotsSignC(w, swn, ots))
       - wotsPkC(w, ots) - hPrime * C_Th2;
}

function xmssMtStateBytes(h, d, w, ots) {
  // Cached-signer state: the BDS state of every layer plus the cached
  // upper-layer WOTS signatures.
  const hPrime = h / d;
  return d * bdsStateNodes(hPrime) * N + (d - 1) * wotsL(w, ots) * N;
}

function xmssMtVerifyC(h, d, w, swn, ots, worstCase) {
  return C_Hmsg + treeVerifyC(h / d, w, swn, ots, worstCase, d);
}


// ---------- UXMSS (SHRINCS left-leaning) ----------

// Leaf-index width for a leaf at this depth: ceil(min(depth, 64) / 8) bytes.
// SHRINCS sizes the field by the depth of the signing leaf, also in the
// unbalanced tree, where the index is only ever 0 or 1.
function uxmssIdxBytes(depth) {
  return Math.max(1, Math.ceil(Math.min(depth, 64) / 8));
}

// Size of the q-th UXMSS signature (q = 1 is the first).
function uxmssSize(q, hsf, w, ots) {
  const l = wotsL(w, ots);
  const ctr = (ots === 'WC') ? counterBytes(w) : 0;
  const depth = Math.min(q, hsf);
  return IND_SIZE + R_SIZE + uxmssIdxBytes(depth) + ctr + l * N + depth * N;
}

// Largest hsf <= HSF_MAX whose largest signature is strictly below targetSize.
function findMaxHsf(w, ots, targetSize) {
  for (let hsf = HSF_MAX; hsf > 0; hsf--) {
    if (uxmssSize(hsf, hsf, w, ots) < targetSize) return hsf;
  }
  return 0;
}

function uxmssKeygenC(hsf, w, ots) {
  return (hsf + 1) * wotsPkC(w, ots) + hsf * C_Th2;
}

// Cached signer, q-th signature: the hsf + 1 leaf public keys are kept as
// state. Every authentication node is one of them except the sibling of the
// signing leaf on the spine, which is recombined from the cached leaves below
// it with hsf - q node hashes (none for the last two signatures).
function uxmssSignC(q, hsf, w, swn, ots) {
  return C_Hmsg + C_PRFmsg + wotsSignC(w, swn, ots)
       + (hsf - Math.min(q, hsf)) * C_Th2;
}

// State-minimal signer, first signature (the most expensive one): rebuild
// the hsf other leaves, then proceed like the cached signer.
function uxmssSignColdC(hsf, w, swn, ots) {
  return uxmssSignC(1, hsf, w, swn, ots) + hsf * wotsPkC(w, ots);
}

// Cached-signer state: the hsf + 1 leaf public keys.
function uxmssStateBytes(hsf) {
  return (hsf + 1) * N;
}

function uxmssVerifyC(q, hsf, w, swn, ots, worstCase) {
  return C_Hmsg + wotsVerifyC(w, swn, ots, worstCase) + Math.min(q, hsf) * C_Th2;
}


// ---------- SLH-DSA-128s baseline (SPX, for reference rows) ----------

function slhMetrics(p) {
  const hp = p.h / p.d;
  const l1 = Math.ceil(8 * N / Math.log2(p.w));
  const l2 = Math.floor(Math.log2(l1 * (p.w - 1)) / Math.log2(p.w)) + 1;
  const len = l1 + l2;
  const Thl = computeTh(len);
  const Thk = computeTh(p.k);

  // R (1·n) + FORS (k·(a+1)·n) + hypertree auth (h·n) + WOTS (d·len·n) — 7856 B for 128s
  const size = N * (1 + p.k * (p.a + 1) + p.h + p.d * len);

  // One XMSS layer: 2^h' WOTS keypairs (PRF + chains + leaf compress) + internal nodes
  const leaves = Math.pow(2, hp);
  const wotsCost = len * C_PRF + len * (p.w - 1) * C_Th1 + Thl;
  const cMerkle = leaves * wotsCost + (leaves - 1) * C_Th2;
  const kg = cMerkle;

  // FORS: k·2^a leaves (PRF + Th1) + k·(2^a − 1) internal nodes + root compress
  const forsLeaves = Math.pow(2, p.a);
  const cFors = p.k * forsLeaves * C_PRF + p.k * forsLeaves * C_Th1
              + p.k * (forsLeaves - 1) * C_Th2 + Thk;
  const sg = cFors + C_Hmsg + C_PRFmsg + p.d * cMerkle;

  // Verification: Hmsg + FORS paths + d WOTS verifies + h auth-path nodes
  const cFts = p.k * C_Th1 + p.k * p.a * C_Th2 + Thk;
  // Average case: exact expected chain steps over all d layers, see wotsTwMeanSteps.
  const cWotsAvg = wotsTwMeanSteps(p.w, p.d) * C_Th1 + p.d * Thl;
  const sv = C_Hmsg + cFts + cWotsAvg + p.h * C_Th2;
  const cWotsWorst = wotsVerifyWorstSteps(p.w) * C_Th1 + Thl;
  const svWorst = C_Hmsg + cFts + p.d * cWotsWorst + p.h * C_Th2;

  return { size, kg, sg, sv, svWorst };
}


// ---------- Security ----------
// Port of compute_security from BlockstreamResearch/SPHINCS-Parameters/security.sage.
// Computes SLH-DSA bit security against FORS subset-forgery attacks for q_s signatures.
// All probabilities accumulated in log2-space to avoid double-precision underflow.
const _LOG2_E = 1 / Math.LN2;

function _lgamma(z) {
  if (z < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * z)) - _lgamma(1 - z);
  z -= 1;
  const c = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
  ];
  let x = c[0];
  for (let i = 1; i < 9; i++) x += c[i] / (z + i);
  const t = z + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
}

function _log2Binom(n, k) {
  if (k < 0 || k > n) return -Infinity;
  if (k === 0 || k === n) return 0;
  // For small k, direct sum (more accurate than lgamma(huge) − lgamma(huge))
  if (k <= 500) {
    let num = 0, denom = 0;
    for (let i = 0; i < k; i++) num += Math.log2(n - i);
    for (let i = 2; i <= k; i++) denom += Math.log2(i);
    return num - denom;
  }
  return (_lgamma(n + 1) - _lgamma(k + 1) - _lgamma(n - k + 1)) * _LOG2_E;
}

function _log2OneMinusExp(x) {
  if (x >= 0) return -Infinity;
  return Math.log(-Math.expm1(x)) * _LOG2_E;
}

function _log2SumExp(a, b) {
  if (a === -Infinity) return b;
  if (b === -Infinity) return a;
  if (a < b) { const tmp = a; a = b; b = tmp; }
  return a + Math.log1p(Math.pow(2, b - a)) * _LOG2_E;
}

// Cap on the number of terms the forgery sum evaluates (see below).
const MAX_SUM_TERMS = 1 << 16;

/**
 * FORS subset-forgery exponent -log2(forgery probability) for
 * q_s = 2^q_s_log2 signatures (uncapped).
 *
 * The sum runs over r, the number of signatures that land on one FORS
 * instance: r ~ Binomial(q_s, 2^-h) with mean lambda = q_s / 2^h. Only
 * the terms within `spread` of lambda matter: further out the binomial
 * weight is below e^-450 of its peak, and the forgery factor
 * (1 - (1 - 1/t)^r)^k only grows with r, so the low side can be skipped
 * as well as the high side. The work is therefore O(sqrt(lambda)), not
 * O(lambda): a tuple with few hypertree leaves (h = 14 gives
 * lambda = 2^26) used to need 67 million terms and froze the page.
 * MAX_SUM_TERMS bounds the work for even smaller h, where the summand
 * is smooth on the scale of the stride and a strided sum is accurate
 * far beyond the displayed precision. For the canonical grid
 * (lambda <= 1) nothing changes: r starts at 1 with stride 1.
 */
function forsForgeryExponent(q_s_log2, h, k, a) {
  const q_s = Math.pow(2, q_s_log2);
  const t = Math.pow(2, a);
  const log2_p = -h;
  const p = Math.pow(2, -h);
  const log2_one_minus_p = p < 1e-15 ? -p * _LOG2_E : Math.log1p(-p) * _LOG2_E;
  const ln_one_minus_1_over_t = 1 / t < 1e-15 ? -1 / t : Math.log1p(-1 / t);
  const lambda = Math.pow(2, q_s_log2 - h);
  let log2_sigma = -Infinity;
  const spread = 30 * Math.sqrt(lambda + 1) + 30;
  const r_max = Math.min(q_s, Math.max(Math.ceil(lambda + spread), 200));
  const r_min = Math.max(1, Math.floor(lambda - spread));
  const stride = Math.max(1, Math.ceil((r_max - r_min + 1) / MAX_SUM_TERMS));
  const log2_stride = Math.log2(stride);
  for (let r = r_min; r <= r_max; r += stride) {
    const log2_C = _log2Binom(q_s, r);
    if (!isFinite(log2_C)) continue;
    const log2_qhp = log2_C + r * log2_p + (q_s - r) * log2_one_minus_p;
    const log2_pf = k * _log2OneMinusExp(r * ln_one_minus_1_over_t);
    const log2_contrib = log2_qhp + log2_pf + log2_stride;
    if (isFinite(log2_contrib)) log2_sigma = _log2SumExp(log2_sigma, log2_contrib);
    if (r > Math.max(lambda, 5) && log2_contrib < -500) break;
  }
  // sigma is a probability; rounding can leave it a hair above 1.
  return Math.max(0, -log2_sigma);
}

/**
 * Bit security: the forgery exponent capped by the hash preimage bound.
 * hashbytes=16 ⇒ 128-bit cap.
 */
function computeSecurityBits(q_s_log2, h, k, a, hashbytes = 16) {
  return Math.min(8 * hashbytes, forsForgeryExponent(q_s_log2, h, k, a));
}

// Report's q_s = 2^40
const Q_S_LOG2 = 40;


// ---------- Distance ----------

// The report's metric-normalised weighted distance: each ratio to SLH-DSA-128s
// is scaled to [0, 1] over the candidates within the bounds, so a weight sets
// its metric's share of the squared distance however loose the bounds are.
const DISTANCE_KEYS = ['size', 'kg', 'sg', 'sv', 'cb'];

// Per-metric min and max of a list of ratio sets; a flat metric spans [min, min + 1].
function ratioRanges(ratioSets) {
  const ranges = {};
  for (const k of DISTANCE_KEYS) {
    let min = Infinity, max = -Infinity;
    for (const r of ratioSets) {
      if (r[k] < min) min = r[k];
      if (r[k] > max) max = r[k];
    }
    ranges[k] = isFinite(min) ? { min, max: max === min ? min + 1 : max } : { min: 0, max: 1 };
  }
  return ranges;
}

function weightedDistance(ratios, ranges, W) {
  const sum = W.size + W.kg + W.sg + W.sv + W.cb;
  let d2 = 0;
  for (const k of DISTANCE_KEYS) {
    const norm = (ratios[k] - ranges[k].min) / (ranges[k].max - ranges[k].min);
    d2 += (W[k] / sum) * norm * norm;
  }
  return Math.sqrt(d2);
}


// ---------- Schnorr reference ----------

const SCHNORR_KAPPA_URL =
  'https://raw.githubusercontent.com/mjthatch/bip340-vs-sha256/main/results/kappa.json';

const SCHNORR_FALLBACK = {
  cb64: 1.98,
  impl: 'libsecp256k1',
  commit: null, run: null, machine: null, preliminary: false,
  live: false,
};

let SCHNORR = { ...SCHNORR_FALLBACK };

async function loadSchnorrRef() {
  try {
    const resp = await fetch(SCHNORR_KAPPA_URL, { cache: 'no-cache' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const k = await resp.json();
    const entry = k && k.cb && k.cb[SCHNORR_FALLBACK.impl];
    const cb = entry && entry.cb_64;
    if (!isFinite(cb) || cb <= 0) throw new Error('cb.' + SCHNORR_FALLBACK.impl + '.cb_64 missing');
    return {
      cb64: cb,
      impl: SCHNORR_FALLBACK.impl,
      commit: k.secp256k1_commit || null,
      run: typeof k.run_utc === 'string' ? k.run_utc.slice(0, 10) : null,
      machine: k.machine || null,
      preliminary: !!k.preliminary,
      live: true,
    };
  } catch (e) {
    console.warn('Schnorr reference kappa.json unavailable (' + e.message +
      ') — using the built-in ' + SCHNORR_FALLBACK.cb64.toFixed(2) + ' C/B.');
    return { ...SCHNORR_FALLBACK };
  }
}

