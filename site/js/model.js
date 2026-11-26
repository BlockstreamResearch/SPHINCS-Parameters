// The model behind the three site pages: sizes in bytes, costs in SHA-256
// compressions (C), security in bits. docs/model.md derives every formula.
'use strict';

const N = 16;          // hash output, bytes
const R_SIZE = 16;     // signature randomizer, bytes

// SHRINCS puts a one-byte indicator in front of every signature (the tree
// height for the stateless path, the leaf height for the stateful path).
const IND_SIZE = 1;

// Compressions per hash call (docs/model.md, Hash calls).
const C_Th1 = 1;       // chain step or leaf
const C_Th1c = 1;      // chain step with the WOTS+C counter
const C_Th2 = 1;       // tree node
const C_Hmsg = 4;      // message hash, 32-byte message
const C_PRFmsg = 3;    // message PRF
const C_PRF = 1;

// Target digit sum S_wn of WOTS+C for each w.
const WOTS_C_SWN = { 16: 240, 32: 403, 64: 693, 128: 1207, 256: 2040, 65536: 262140 };

// UXMSS signatures stay below the size of the report's candidate 2.
const UXMSS_TARGET_SIZE = 5712;

const SLH = { h: 63, d: 7, k: 14, a: 12, w: 16 };   // SLH-DSA-128s

const HSF_MAX = 255;   // the UXMSS tree height fits one byte

// Bytes of the leaf index in a hypertree of height h.
function idxBytes(h) { return Math.max(1, Math.ceil(h / 8)); }

// Compressions of a tweakable hash over n hash values.
function computeTh(n) { return Math.ceil((176 + 128 * n + 65) / 512); }

// WOTS+C grinding counter. SHRINCS stores it in 2 bytes: 2^16 counters miss
// the target sum with probability below 2^-126 for every w <= 256. w = 65536
// needs about 137,000 attempts on average and keeps a 4-byte counter.
function counterBytes(w) { return w <= 256 ? 2 : 4; }

// WOTS-TW verification, mean (docs/model.md, WOTS-TW verification)

function binomBig(n, k) {
  if (k < 0n || k > n) return 0n;
  if (k === 0n || k === n) return 1n;
  if (k > n - k) k = n - k;
  let num = 1n, den = 1n;
  for (let i = 0n; i < k; i++) { num *= (n - i); den *= (i + 1n); }
  return num / den;
}

// w^l1 * sum_{j=1}^{l2-1} E[floor(S / w^j)] as an exact BigInt, with S the sum
// of l1 uniform base-w digits.
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

// Mean chain steps to verify `count` WOTS-TW signatures on random digests,
// rounded once to the nearest integer.
function wotsTwMeanSteps(w, count = 1) {
  const l1 = Math.ceil(8 * N / Math.log2(w));
  const l2 = Math.floor(Math.log2(l1 * (w - 1)) / Math.log2(w)) + 1;
  const W = BigInt(w) ** BigInt(l1);
  const num = BigInt(count) * BigInt(w - 1) * (BigInt(l2) * W + wotsTwFloorSum(l1, l2, w));
  return Number((2n * num + W) / (2n * W));   // round to nearest
}

// WOTS (docs/model.md, WOTS)

// Chains of a WOTS key: l1 for WOTS+C, l1 + l2 for WOTS-TW (FIPS 205).
function wotsL(w, ots) {
  const l1 = Math.ceil(8 * N / Math.log2(w));
  if (ots === 'WC') return l1;
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

// Digit strings of length l in base w that sum to swn.
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

// Mean counter attempts of one WOTS+C signature, ceil(w^l / ν).
function wotsCSearch(w, swn) {
  const l = wotsL(w, 'WC');
  const nu = computeNu(l, swn, w);
  const wToL = BigInt(w) ** BigInt(l);
  return Number(wToL / nu + ((wToL % nu === 0n) ? 0n : 1n));   // small, fits in a double
}

function wotsSignC(w, swn, ots) {
  const l = wotsL(w, ots);
  if (ots === 'WC') return wotsCSearch(w, swn) * C_Th1c + l * C_PRF + swn * C_Th1;
  // WOTS-TW: the signer walks the part of each chain the verifier does not.
  return l * C_PRF + (l * (w - 1) - wotsTwMeanSteps(w)) * C_Th1;
}

// Worst case: every message digit is 0.
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

// XMSS and XMSS-MT (docs/model.md, XMSS and XMSS-MT)

function treeSizePerLayer(hPrime, w, ots) {
  const l = wotsL(w, ots);
  const ctr = (ots === 'WC') ? counterBytes(w) : 0;
  return hPrime * N + l * N + ctr;
}

function treeKeygenC(hPrime, w, ots) {
  const pk = wotsPkC(w, ots);
  const sz = Math.pow(2, hPrime);
  return sz * pk + (sz - 1) * C_Th2;
}

function treeVerifyC(hPrime, w, swn, ots, worstCase, count = 1) {
  return wotsVerifyC(w, swn, ots, worstCase, count) + count * hPrime * C_Th2;
}

// BDS traversal (Buchmann, Dahmen, Schneider 2008): the parameter K, the
// leaves and node hashes per signature, and the nodes of the state.
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

// SHRINCS stateful layout, used for every stateful scheme:
//   indicator | R | leaf index | per layer: [counter] + WOTS chains + auth path
function xmssMtSize(h, d, w, ots) {
  const hPrime = h / d;
  return IND_SIZE + R_SIZE + idxBytes(h) + d * treeSizePerLayer(hPrime, w, ots);
}

function xmssMtKeygenC(h, d, w, ots) {
  // The top tree; the signer builds the lower ones.
  return treeKeygenC(h / d, w, ots);
}

function xmssMtSignBdsC(h, d, w, swn, ots) {
  // Cached signer, upper bound: the upper-layer WOTS signatures are cached,
  // so one WOTS signature and one BDS update per layer.
  const hPrime = h / d;
  const pk = wotsPkC(w, ots);
  const cSg = wotsSignC(w, swn, ots);
  return C_Hmsg + C_PRFmsg + cSg
       + d * (bdsLeaves(hPrime) * pk + bdsHashes(hPrime) * C_Th2);
}

function xmssMtSignColdC(h, d, w, swn, ots) {
  // Cold signer: rebuilds the d trees. In the top tree it skips the signing
  // leaf and the h' nodes on its path to the root.
  const hPrime = h / d;
  return C_Hmsg + C_PRFmsg + d * (treeKeygenC(hPrime, w, ots) + wotsSignC(w, swn, ots))
       - wotsPkC(w, ots) - hPrime * C_Th2;
}

function xmssMtStateBytes(h, d, w, ots) {
  // Cached signer: the BDS state of every layer and the upper-layer WOTS
  // signatures.
  const hPrime = h / d;
  return d * bdsStateNodes(hPrime) * N + (d - 1) * wotsL(w, ots) * N;
}

function xmssMtVerifyC(h, d, w, swn, ots, worstCase) {
  return C_Hmsg + treeVerifyC(h / d, w, swn, ots, worstCase, d);
}

// UXMSS, the SHRINCS unbalanced tree (docs/model.md, UXMSS)

// Bytes of the leaf index for a leaf at this depth. SHRINCS sizes the field
// by the depth also in the unbalanced tree, where the index is only 0 or 1.
function uxmssIdxBytes(depth) {
  return Math.max(1, Math.ceil(Math.min(depth, 64) / 8));
}

// Size of the q-th signature (q = 1 is the first).
function uxmssSize(q, hsf, w, ots) {
  const l = wotsL(w, ots);
  const ctr = (ots === 'WC') ? counterBytes(w) : 0;
  const depth = Math.min(q, hsf);
  return IND_SIZE + R_SIZE + uxmssIdxBytes(depth) + ctr + l * N + depth * N;
}

// Largest hsf <= HSF_MAX whose largest signature is below targetSize.
function findMaxHsf(w, ots, targetSize) {
  for (let hsf = HSF_MAX; hsf > 0; hsf--) {
    if (uxmssSize(hsf, hsf, w, ots) < targetSize) return hsf;
  }
  return 0;
}

function uxmssKeygenC(hsf, w, ots) {
  return (hsf + 1) * wotsPkC(w, ots) + hsf * C_Th2;
}

// Cached signer, q-th signature: it keeps the leaf public keys and recombines
// the spine sibling of the signing leaf from them.
function uxmssSignC(q, hsf, w, swn, ots) {
  return C_Hmsg + C_PRFmsg + wotsSignC(w, swn, ots)
       + (hsf - Math.min(q, hsf)) * C_Th2;
}

// Cold signer, first signature, the most expensive: it rebuilds the hsf
// other leaves first.
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

// SLH-DSA (docs/model.md, SLH-DSA)

function slhMetrics(p) {
  const hp = p.h / p.d;
  const l1 = Math.ceil(8 * N / Math.log2(p.w));
  const l2 = Math.floor(Math.log2(l1 * (p.w - 1)) / Math.log2(p.w)) + 1;
  const len = l1 + l2;
  const Thl = computeTh(len);
  const Thk = computeTh(p.k);

  // randomizer, FORS, hypertree authentication path, WOTS signatures
  const size = N * (1 + p.k * (p.a + 1) + p.h + p.d * len);

  // one hypertree layer
  const leaves = Math.pow(2, hp);
  const wotsCost = len * C_PRF + len * (p.w - 1) * C_Th1 + Thl;
  const cMerkle = leaves * wotsCost + (leaves - 1) * C_Th2;
  const kg = cMerkle;

  const forsLeaves = Math.pow(2, p.a);
  const cFors = p.k * forsLeaves * C_PRF + p.k * forsLeaves * C_Th1
              + p.k * (forsLeaves - 1) * C_Th2 + Thk;
  // A layer costs a full tree, to sign and to verify. The top tree is never
  // rebuilt: its root is the published public key, so the signature saves one
  // WOTS-TW verification and its h' authentication path there.
  const cTopSaved = wotsTwMeanSteps(p.w, 1) * C_Th1 + Thl + hp * C_Th2;
  const sg = cFors + C_Hmsg + C_PRFmsg + p.d * cMerkle - cTopSaved;

  const cFts = p.k * C_Th1 + p.k * p.a * C_Th2 + Thk;
  const cWotsAvg = wotsTwMeanSteps(p.w, p.d) * C_Th1 + p.d * Thl;
  const sv = C_Hmsg + cFts + cWotsAvg + p.h * C_Th2;
  const cWotsWorst = wotsVerifyWorstSteps(p.w) * C_Th1 + Thl;
  const svWorst = C_Hmsg + cFts + p.d * cWotsWorst + p.h * C_Th2;

  return { size, kg, sg, sv, svWorst };
}

// W+C, FORS+C and PORS+FP (docs/model.md, W+C, FORS+C and PORS+FP)

// Bytes of the WOTS+C counter in each layer of a stateless signature.
const WOTS_C_COUNTER = 4;

// The PORS+FP grinding model takes seconds beyond this k, and t = k·2^a has
// to stay an exact integer.
const PORS_MAX_K = 32;
const PORS_MAX_A = 40;

// PORS+FP grinding: log2 of the mean attempts until the Octopus
// authentication set of k leaves among t has at most mmax nodes
// (js/octopus_pmf.js, which only stateless.html loads).
const _porsTables = new Map();

function porsLog2Attempts(t, k, mmax) {
  const key = t + ',' + k;
  let table = _porsTables.get(key);
  if (!table) {
    table = interleaveCostTable(t, k);
    _porsTables.set(key, table);
  }
  // The table ends at the largest set, where every attempt succeeds, and
  // starts at the smallest: below it none does.
  let best = -1;
  for (const m of table.keys()) if (m <= mmax && m > best) best = m;
  if (best < 0) throw new RangeError('mmax is below the smallest authentication set');
  return table.get(best);
}

// Size and costs of SPX, W+C, W+C_F+C or W+C_P+FP for p = { h, d, k, a, w }.
// With WOTS+C the target sum is the S_wn of w, unless p.swn gives another.
function schemeMetrics(scheme, p) {
  if (scheme === 'SPX') return { ...slhMetrics(p), swn: 0, mmax: 0 };
  const { h, d, k, a, w } = p;
  const swn = p.swn || WOTS_C_SWN[w];
  const l = wotsL(w, 'WC');

  // one hypertree layer; a signature rebuilds d of them and searches d counters
  const leaves = Math.pow(2, h / d);
  const cMerkle = leaves * wotsPkC(w, 'WC') + (leaves - 1) * C_Th2;
  // As in slhMetrics, the top layer saves its WOTS+C verification and its
  // h' authentication path: the top root is the published public key.
  const cVerifyWC = ((w - 1) * l - swn) * C_Th1 + C_Th1c + computeTh(l);
  const cHyper = d * cMerkle + d * wotsCSearch(w, swn) * C_Th1c
               - cVerifyWC - (h / d) * C_Th2;
  const cMsg = C_Hmsg + C_PRFmsg;

  // FORS with `trees` trees of 2^a leaves: to build them, and to verify a signature
  const forsLeaves = Math.pow(2, a);
  const forsBuild = trees => trees * forsLeaves * (C_PRF + C_Th1)
                           + trees * (forsLeaves - 1) * C_Th2 + computeTh(trees);
  const forsVerify = trees => trees * C_Th1 + trees * a * C_Th2 + computeTh(trees);
  // FORS+C leaves the last tree out and grinds about 2^a message hashes instead.
  const sgForsC = cHyper + forsBuild(k - 1) + forsLeaves * cMsg;

  let ftsSize, sg, cFts, mmax = 0;
  if (scheme === 'W+C') {
    ftsSize = k * (a + 1) * N;
    sg = forsBuild(k) + cMsg + cHyper;
    cFts = forsVerify(k);
  } else if (scheme === 'W+C_F+C') {
    ftsSize = (k - 1) * (a + 1) * N;
    sg = sgForsC;
    cFts = forsVerify(k - 1);
  } else {
    // PORS+FP: one tree of t = k·2^a leaves; the signer grinds message hashes
    // until the authentication set of its k leaves has at most mmax nodes.
    const t = k * forsLeaves;
    const cTree = t * (C_PRF + C_Th1) + (t - 1) * C_Th2;
    const sgWith = m => cHyper + cTree + Math.ceil(Math.pow(2, porsLog2Attempts(t, k, m))) * cMsg;
    // mmax grows from (k − 1)·a − ceil(350/n), by 19 at most, until signing
    // costs less than 1.11 times signing with FORS+C.
    mmax = (k - 1) * a - Math.ceil(350 / N);
    for (let i = 0; i < 19 && !(sgWith(mmax) / sgForsC < 1.11); i++) mmax++;
    ftsSize = (k + mmax) * N;
    sg = sgWith(mmax);
    cFts = k * C_Th1 + mmax * C_Th2;
  }

  // randomizer, hypertree authentication path and WOTS+C signatures, their
  // counters, the few-time signature
  const size = N * (1 + h + d * l) + WOTS_C_COUNTER * d + ftsSize;
  // WOTS+C verification costs the same for every message.
  const sv = C_Hmsg + cFts + wotsVerifyC(w, swn, 'WC', false, d) + h * C_Th2;
  return { size, kg: cMerkle, sg, sv, svWorst: sv, swn, mmax };
}

// BGS-CC (docs/model.md, BGS-CC): the few-time signature of ePrint 2026/2502
// in place of FORS

// The BGS-CC schemes and the WOTS variant of their hypertree.
const BGS_SCHEMES = { 'BGS': 'TW', 'W+C_BGS': 'WC' };

// Bytes of the encoder counter.
const BGS_COUNTER = 4;

// Codewords of the constant-sum code: the vectors x with 0 <= x_j <= c_j that
// sum to e (the paper's N), as a BigInt.
function bgsCodeSize(c, e) {
  let counts = [1n];
  for (const cap of c) {
    const next = new Array(counts.length + cap).fill(0n);
    counts.forEach((n, s) => { for (let x = 0; x <= cap; x++) next[s + x] += n; });
    counts = next;
  }
  return e < counts.length ? counts[e] : 0n;
}

// Size and costs of the BGS-CC signature of f = { h, K, L, r, b, u, c, E,
// delta }; h only sets how many blocks the encoder reads. Every hash call of
// the few-time part takes one compression.
function bgsFtsMetrics(f) {
  const { h, K, L, r, b, u, c, E, delta } = f;
  const t = Math.pow(2, L), B = Math.pow(2, b), O = Math.pow(2, u);
  const words = bgsCodeSize(c, E) ** BigInt(r * K);   // codeword choices of one encoding
  const eBits = words > 1n ? (words - 1n).toString(2).length : 0;   // ceil(log2 words)
  const blocks = Math.ceil((32 + h + K * (b + u + r * L) + eBits) / (8 * N));

  // one owner tree: t sources, their guard chains and leaves, the edge chains
  // and the t - 1 nodes
  let edges = 0;
  for (let d = 0; d < L; d++) edges += Math.pow(2, d + 1) * c[d];
  const cOwner = t * (C_PRF + c[L] * C_Th1 + C_Th2) + edges * C_Th1 + (t - 1) * C_Th2;
  // K coordinates of B buckets: O owners in the first layer and t in each of
  // the other r - 1, the O - 1 nodes above the first, then the bucket trees
  // and the K - 1 nodes above the coordinates
  const cGraph = K * B * ((O + (r - 1) * t) * cOwner + (O - 1) * C_Th2) + (K * B - 1) * C_Th2;
  // encoder blocks until a counter passes: one per attempt, the other
  // blocks - 1 for the attempts below the threshold; rounded up exactly
  const num = (1n << BigInt(eBits)) * (2n ** 32n + BigInt(blocks - 1) * BigInt(delta));
  const den = BigInt(delta) * words;
  const cSearch = Number((num + den - 1n) / den);

  let pathSteps = E;
  for (let d = 0; d < L; d++) pathSteps += c[d];
  const cLayer = pathSteps * C_Th1 + (L + 1) * C_Th2;
  return {
    size: BGS_COUNTER + N * K * (b + u + r * (L + 1)),
    sg: cGraph + cSearch,
    sv: blocks + K * ((b + u) * C_Th2 + r * cLayer) + (K - 1) * C_Th2,
  };
}

// What surrounds the few-time signature: R, the d layers of the hypertree and
// the message hashing, with WOTS-TW ('TW') or WOTS+C ('WC') layers. With FORS
// added it is slhMetrics or schemeMetrics('W+C').
function hypertreeMetrics(h, d, w, ots) {
  const hp = h / d;
  const l = wotsL(w, ots);
  const Thl = computeTh(l);
  const leaves = Math.pow(2, hp);
  const cMerkle = leaves * wotsPkC(w, ots) + (leaves - 1) * C_Th2;
  const cMsg = C_Hmsg + C_PRFmsg;
  if (ots === 'WC') {
    const swn = WOTS_C_SWN[w];
    const cVerifyWC = ((w - 1) * l - swn) * C_Th1 + C_Th1c + Thl;
    const sv = C_Hmsg + d * cVerifyWC + h * C_Th2;
    return {
      size: N * (1 + h + d * l) + WOTS_C_COUNTER * d,
      kg: cMerkle,
      sg: cMsg + d * cMerkle + d * wotsCSearch(w, swn) * C_Th1c - cVerifyWC - hp * C_Th2,
      sv, svWorst: sv, swn,
    };
  }
  const cTopSaved = wotsTwMeanSteps(w, 1) * C_Th1 + Thl + hp * C_Th2;
  return {
    size: N * (1 + h + d * l),
    kg: cMerkle,
    sg: cMsg + d * cMerkle - cTopSaved,
    sv: C_Hmsg + wotsTwMeanSteps(w, d) * C_Th1 + d * Thl + h * C_Th2,
    svWorst: C_Hmsg + d * (wotsVerifyWorstSteps(w) * C_Th1 + Thl) + h * C_Th2,
    swn: 0,
  };
}

// Size and costs of BGS-CC under a hypertree, for p = { h, d, w } and the
// few-time configuration p.bgs = { K, L, r, b, u, c, E, delta }: the two parts
// add up.
function bgsMetrics(scheme, p) {
  const ht = hypertreeMetrics(p.h, p.d, p.w, BGS_SCHEMES[scheme]);
  const fts = bgsFtsMetrics({ h: p.h, ...p.bgs });
  return {
    size: ht.size + fts.size, kg: ht.kg, sg: ht.sg + fts.sg,
    sv: ht.sv + fts.sv, svWorst: ht.svWorst + fts.sv, swn: ht.swn, mmax: 0,
  };
}

// FORS and PORS+FP security (docs/model.md, FORS security), summed in log2 to
// avoid underflow.

const _LOG2_E = 1 / Math.LN2;

// ln Γ(z), Lanczos approximation.
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

// log2(1 - e^x)
function _log2OneMinusExp(x) {
  if (x >= 0) return -Infinity;
  return Math.log(-Math.expm1(x)) * _LOG2_E;
}

// log2(2^a + 2^b)
function _log2SumExp(a, b) {
  if (a === -Infinity) return b;
  if (b === -Infinity) return a;
  if (a < b) { const tmp = a; a = b; b = tmp; }
  return a + Math.log1p(Math.pow(2, b - a)) * _LOG2_E;
}

// Beyond this many terms the forgery sum is strided; the summand is smooth on
// that scale, so the sum stays accurate far beyond the displayed precision.
const MAX_SUM_TERMS = 1 << 16;

// -log2 of the forgery probability after 2^q_s_log2 signatures, uncapped.
// log2Forge(r) is log2 of the probability of a forgery on an instance that r
// signatures have used. Only r within `spread` of the mean lambda = q_s / 2^h
// is summed, so the work grows with sqrt(lambda); the custom candidate accepts
// any h.
function forgeryExponent(q_s_log2, h, log2Forge) {
  const q_s = Math.pow(2, q_s_log2);
  const log2_p = -h;
  const p = Math.pow(2, -h);
  const log2_one_minus_p = p < 1e-15 ? -p * _LOG2_E : Math.log1p(-p) * _LOG2_E;
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
    const log2_pf = log2Forge(r);
    const log2_contrib = log2_qhp + log2_pf + log2_stride;
    if (isFinite(log2_contrib)) log2_sigma = _log2SumExp(log2_sigma, log2_contrib);
    if (r > Math.max(lambda, 5) && log2_contrib < -500) break;
  }
  // sigma is a probability; rounding can leave it a hair above 1.
  return Math.max(0, -log2_sigma);
}

// FORS: after r signatures each of the k trees of t = 2^a leaves has revealed
// the leaf a forgery needs with probability 1 − (1 − 1/t)^r.
function forsForgeryExponent(q_s_log2, h, k, a) {
  const t = Math.pow(2, a);
  const ln_one_minus_1_over_t = 1 / t < 1e-15 ? -1 / t : Math.log1p(-1 / t);
  return forgeryExponent(q_s_log2, h, r => k * _log2OneMinusExp(r * ln_one_minus_1_over_t));
}

// PORS+FP: r signatures reveal at most r·k of the t = k·2^a leaves, and a
// forgery needs its k leaves among them.
function porsForgeryExponent(q_s_log2, h, k, a) {
  const t = k * Math.pow(2, a);
  const log2_all = _log2Binom(t, k);
  return forgeryExponent(q_s_log2, h, r => _log2Binom(Math.min(r * k, t), k) - log2_all);
}

// Bits of security: the forgery exponent, capped at 8 * hashbytes by preimage
// search.
function computeSecurityBits(q_s_log2, h, k, a, hashbytes = 16) {
  return Math.min(8 * hashbytes, forsForgeryExponent(q_s_log2, h, k, a));
}

// The stateless schemes are evaluated at 2^40 signatures, unless the budget
// slider of the explorer says otherwise.
const Q_S_LOG2 = 40;

// The forgery exponent of a stateless scheme: PORS+FP has its own, the others
// that of FORS.
function schemeForgeryExponent(scheme, h, k, a, q_s_log2 = Q_S_LOG2) {
  return (scheme === 'W+C_P+FP' ? porsForgeryExponent : forsForgeryExponent)(q_s_log2, h, k, a);
}

// Distance, the report's metric-normalised weighted distance (docs/model.md,
// Distance)

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

// ρ of a BIP340 Schnorr verification (libsecp256k1, 64-byte signature) from
// bip340-vs-sha256; the built-in value stands in when it does not load.
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

