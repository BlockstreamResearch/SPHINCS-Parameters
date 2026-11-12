'use strict';

// ---------- Constants ----------
// SLH-DSA-128s baseline (matches the numbers in the tech report)
const STD = { n: 16, h: 63, d: 7, k: 14, a: 12, w: 16 };

// SLH-DSA-compatible Winternitz choices: lg_w = log2(w) must divide 8 so
// that base_2b message digits stay byte-aligned (lg_w in {1, 2, 4, 8}).
const ALLOWED_W = [2, 4, 16, 256];

// Optional Winternitz extras, gated by a sidebar checkbox 
const OPTIONAL_W = [32, 64, 128];
const UNIVERSE_W = [...ALLOWED_W, ...OPTIONAL_W];

// ---------- Schnorr (BIP340) reference ----------
const SCHNORR_KAPPA_URL =
  'https://raw.githubusercontent.com/mjthatch/bip340-vs-sha256/main/results/kappa.json';
const SCHNORR_FALLBACK = {
  cb64: 1.98,
  impl: 'libsecp256k1',
  commit: null, run: null, machine: null, preliminary: false,
  live: false,
};

// ---------- Cost formulas ----------
// WOTS+ chain components: { len1, len2, len }
// len1 = message chains, len2 = checksum chains, len = len1 + len2
function wotsComponents(n, w) {
  const log2w = Math.log2(w);
  const len1 = Math.ceil(8 * n / log2w);
  const len2 = Math.floor(Math.log2(len1 * (w - 1)) / log2w) + 1;
  return { len1, len2, len: len1 + len2 };
}

// Convenience wrapper kept for any callers that only need total length
function wotsLen(n, w) { return wotsComponents(n, w).len; }

// Worst-case WOTS-TW verification steps per hypertree layer.
//
// WOTS-TW has no constant-sum constraint (unlike WOTS+C), so the
// average is WRONG for worst-case analysis.
//
// Worst case: all len1 message digits = 0 → verifier walks w-1 steps
// on each message chain.  The checksum C = len1*(w-1) is then fixed,
// and its base-w digit sum determines the remaining checksum work.
//
//   worst_steps = len1*(w-1) + len2*(w-1) - digitSum(len1*(w-1), w)
//               = len*(w-1) - digitSum(len1*(w-1), w)
//
// Reference: costs.sage compute_verification_time(), SPX branch.
function wotsVerifyWorstSteps(n, w) {
  const { len1, len2 } = wotsComponents(n, w);
  const C = len1 * (w - 1);
  let ds = 0, rem = C;
  while (rem > 0) { ds += rem % w; rem = Math.floor(rem / w); }
  return len1 * (w - 1) + len2 * (w - 1) - ds;
}

// Average WOTS-TW verification steps over `count` hypertree layers,
// rounded to the nearest integer (same as wotsTwMeanSteps in formulas.js
// and compute_wots_tw_mean_steps in costs.sage).
//
// The len1 message chains average (w-1)/2 steps each, but the len2
// checksum chains do not: the checksum is concentrated around
// len1*(w-1)/2, so its leading digit is almost always 0 or 1 and the
// verifier walks most of that chain. Exactly, with S the sum of the len1
// message digits,
//   E[steps] = (w-1) * (len2 + sum_{j=1}^{len2-1} E[floor(S / w^j)])
// (267.12 for w = 16, where (w-1)*len/2 would give 262). The expectations
// are E[floor(S / w^j)] = sum_{m>=1} P(S >= m*w^j), with the number of
// digit strings of sum <= t counted by inclusion-exclusion:
//   sum_i (-1)^i * C(len1, i) * C(t - i*w + len1, len1).
function binomBig(n, k) {
  if (k < 0n || k > n) return 0n;
  if (k === 0n || k === n) return 1n;
  if (k > n - k) k = n - k;
  let num = 1n, den = 1n;
  for (let i = 0n; i < k; i++) { num *= (n - i); den *= (i + 1n); }
  return num / den;
}

// Per (n, w): the mean steps of one signature as the exact fraction num / W.
const _meanStepsCache = new Map();
function wotsVerifyMeanSteps(n, w, count) {
  const key = n + ',' + w;
  let mean = _meanStepsCache.get(key);
  if (!mean) {
    const { len1, len2 } = wotsComponents(n, w);
    const L1 = BigInt(len1), wB = BigInt(w);
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
    for (let j = 1; j < len2; j++) {
      const step = wB ** BigInt(j);
      for (let m = 1n; m * step <= top; m++) acc += W - countLe(m * step - 1n);
    }
    mean = { num: BigInt(w - 1) * (BigInt(len2) * W + acc), W };
    _meanStepsCache.set(key, mean);
  }
  // count * num / W, rounded to the nearest integer
  return Number((2n * BigInt(count) * mean.num + mean.W) / (2n * mean.W));
}

// Marginal compression-call count for a tweakable hash over n hash-sized
// values, under the cached convention (FIPS 205 SHA-2 layout): the
// PK.seed block is precomputed once per keypair, so each call costs only
// ADRS_c (22 B = 176 bits) + payload (128n bits) + padding (65 bits).
// Matches costs.sage (HASH_CONVENTION=cached, the default):
//   compute_Th(n) = ceil((176 + 128*n + 65) / 512)
function computeTh(n) {
  return Math.ceil((176 + 128 * n + 65) / 512);
}

function metrics(p) {
  const n = STD.n; // 16 bytes (128-bit security)
  const hp = p.h / p.d;
  const { len } = wotsComponents(n, p.w);

  // Compression costs: cached convention, matching costs.sage defaults:
  // PK.seed midstate cached per keypair; a 2-child node hash is
  // ADRS_c (22 B) + 32 B + padding = 497 bits -> 1 compression.
  // Hmsg and PRFmsg for a 32-byte message and an empty context, as the
  // SHRINCS reference implementation executes them: Hmsg is two nested
  // SHA-256 calls of 2 compressions each (its input starts with the
  // randomizer, so nothing is cacheable); PRFmsg is HMAC-SHA-256, 2 + 1
  // compressions with its two key-pad blocks cached.
  const C_PRF = 1;  // PRF generation
  const C_Th1 = 1;  // tweakable hash, 1 value (WOTS chain step / leaf)
  const C_Th2 = 1;  // tweakable hash, 2 values (internal tree node)
  const C_Hmsg = 4; // Message hash
  const C_PRFmsg = 3; // Message PRF

  // Exact compression counts for leaf/root compressions (matches costs.sage).
  // computeTh(n) = ceil((128 + 96 + 128*n + 65) / 512):
  //   Thl = cost to compress len WOTS public values into one XMSS leaf
  //   Thk = cost to compress k  FORS roots into one combined value
  // Previously approximated as len and k respectively, which overstated both
  // by ~25 and ~9 compressions for standard parameters, cascading into
  // KeyGen (+12,800), SigGen (+89,609) and SigVer (+191) errors.
  const Thl = computeTh(len);
  const Thk = computeTh(p.k);

  // 1. Signature Size (Bytes)
  // Rand (1*n) + FORS (k*(a+1)*n) + Hypertree Auth (h*n) + WOTS (d*len*n)
  const size = n * (1 + p.k * (p.a + 1) + p.h + p.d * len);

  // 2. Cost of ONE XMSS Tree Layer (c_merkle)
  const leavesPerTree = Math.pow(2, hp);
  // Leaves: PRF + WOTS chains (w-1)*C_Th1 + leaf compression (Thl)
  const wotsCost = (len * C_PRF) + (len * (p.w - 1) * C_Th1) + Thl;
  // Internal nodes: (2^hp - 1) * C_Th2
  const c_merkle = (leavesPerTree * wotsCost) + ((leavesPerTree - 1) * C_Th2);

  // 3. Key Generation (Build top tree only)
  const kg = c_merkle;

  // 4. Signature Generation (FORS + d * c_merkle)
  const forsLeaves = Math.pow(2, p.a);

  // EXACT FORS COST: PRF + Leaf Hash (C_Th1) + Internal Nodes (C_Th2) + Root compress (Thk)
  const c_fors_fixed = (p.k * forsLeaves * C_PRF) +
    (p.k * forsLeaves * C_Th1) +
    (p.k * (forsLeaves - 1) * C_Th2) +
    Thk;

  const c_msg = C_Hmsg + C_PRFmsg; // Cost to hash message
  const sg = c_fors_fixed + c_msg + (p.d * c_merkle);

  // 5a. Signature Verification — average case
  // Exact expected chain steps for uniformly random digests, summed over
  // the d layers (see wotsVerifyMeanSteps). Used for filter thresholds
  // and distance scoring.
  const c_wots_avg = wotsVerifyMeanSteps(n, p.w, p.d) * C_Th1 + p.d * Thl;
  // FORS path verify: k leaves (C_Th1) + k*a internal nodes (C_Th2) + root (Thk)
  const c_fts = (p.k * C_Th1) + (p.k * p.a * C_Th2) + Thk;
  const sv = C_Hmsg + c_fts + c_wots_avg + (p.h * C_Th2);

  // 5b. Signature Verification — worst case (WOTS-TW)
  // All len1 message digits = 0: verifier walks w-1 steps per message chain.
  // Checksum C = len1*(w-1) is fixed; its base-w digit sum determines checksum work.
  // See wotsVerifyWorstSteps(). Displayed alongside average for comparison.
  const c_wots_worst = (wotsVerifyWorstSteps(n, p.w) * C_Th1) + Thl;
  const sv_worst = C_Hmsg + c_fts + (p.d * c_wots_worst) + (p.h * C_Th2);

  // 6. Density (Compressions per byte)
  // avg:   based on average-case SV (used for filter threshold and distance scoring)
  // worst: based on worst-case SV — upper bound on verifier work per byte transferred
  const cb = sv / size;
  const cb_worst = sv_worst / size;

  return { size, kg, sg, sv, sv_worst, cb, cb_worst };
}

const STD_M = metrics(STD);

// ---------- Sweep ----------
// Canonical grid — must match the report (Sec. 2) and slhdsa-2to40.sage defaults:
//   h in [40, 50], d in [2, 25] with d | h, k in [6, 24], a in [8, 20], w in ALLOWED_W = {2, 4, 16, 256}.
// k >= 6 because with a <= 20 and h <= 50 any k <= 5 falls short of the
// 128-bit security floor at q_s = 2^40, so smaller k never survives anyway.
function sweep() {
  const candidates = [];
  for (let h = 40; h <= 50; h++) {
    for (let d = 2; d <= 25; d++) {
      if (h % d !== 0) continue;
      for (let k = 6; k <= 24; k++) {
        for (let a = 8; a <= 20; a++) {
          for (const w of UNIVERSE_W) {
            const p = { h, d, k, a, w };
            const m = metrics(p);
            // Skip pathological/infinite candidates
            if (!isFinite(m.kg) || !isFinite(m.sg)) continue;
            candidates.push({ ...p, ...m });
          }
        }
      }
    }
  }
  return candidates;
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

// 128-bit security check using the real FORS forgery analysis
function passesSecurity(c) {
  return computeSecurityBits(Q_S_LOG2, c.h, c.k, c.a) >= 128;
}

// Combined initial bounds: security + size strictly less than SLH-DSA-128s
// (the report's Sage script uses MAX_SIZE = 7856, matching the FIPS 205 reference value)
const MAX_SIZE = 7856;
function passesInitial(c) {
  return passesSecurity(c) && c.size < MAX_SIZE;
}

// ---------- Canonical data (data.json) ----------
// The pools are normally loaded from site/data.json, generated by
// export_site_data.sage: SPX from the same sweep CSV as the report, the
// W+C / FORS+C / PORS+FP variants computed by costs.sage. The formulas
// above stay for the custom-candidate panel (SPX model) and as a
// fallback, and are cross-checked against the loaded SPX pool at startup.
function poolFromData(data, scheme) {
  const p = data.pools[scheme];
  const idx = Object.fromEntries(p.fields.map((f, i) => [f, i]));
  // Guard against a stale data.json generated on an older grid: only the
  // swept w universe survives (a freshly exported dataset drops none).
  const rows = p.rows.filter(r => UNIVERSE_W.includes(r[idx.w]));
  if (rows.length !== p.rows.length) {
    console.warn(`pool ${scheme}: dropped ${p.rows.length - rows.length} rows with ` +
      `w outside {${UNIVERSE_W.join(', ')}} — regenerate data.json (stale grid).`);
  }
  return rows.map(r => {
    const c = {
      h: r[idx.h], d: r[idx.d], k: r[idx.k], a: r[idx.a], w: r[idx.w],
      swn: r[idx.swn], mmax: r[idx.mmax],
      size: r[idx.size], kg: r[idx.kg], sg: r[idx.sg],
      sv: r[idx.sv], sv_worst: r[idx.sv_worst],
    };
    c.cb = c.sv / c.size;
    c.cb_worst = c.sv_worst / c.size;
    return c;
  });
}

// Metric accessor honouring the worst-case mode: SigVer and ρ switch to
// their worst-case variants; size/kg/sg are message-independent.
function mkey(k) {
  return state.useWorst && (k === 'sv' || k === 'cb') ? k + '_worst' : k;
}

// ---------- Filter pipeline ----------
const FILTER_STEPS = [
  { key: 'size', metric: 'size', label: 'Size' },
  { key: 'kg', metric: 'kg', label: 'KeyGen' },
  { key: 'sg', metric: 'sg', label: 'SigGen' },
  { key: 'sv', metric: 'sv', label: 'SigVer' },
  { key: 'cb', metric: 'cb', label: 'ρ' },
];

// Returns an array: each element holds the survivors after step i, and which step eliminated each candidate
function runFilters(pool, X) {
  const eliminatedAt = new Map(); // candidate -> step index (or null if survived all)
  pool.forEach(c => eliminatedAt.set(c, null));

  const stepCounts = [{ name: 'Initial pool', count: pool.length }];
  let cur = pool;
  FILTER_STEPS.forEach((step, idx) => {
    const mk = mkey(step.metric);
    const stdVal = STD_M[mk];
    const next = [];
    for (const c of cur) {
      if (c[mk] <= X[step.key] * stdVal) {
        next.push(c);
      } else {
        if (eliminatedAt.get(c) === null) eliminatedAt.set(c, idx);
      }
    }
    cur = next;
    const worstTag = (mk !== step.metric) ? ', worst' : '';
    stepCounts.push({
      name: `${step.label}${worstTag} ≤ ${fmtX(X[step.key])}×`,
      count: cur.length
    });
  });

  return { stepCounts, survivors: cur, eliminatedAt };
}

// ---------- Distance ----------
// Compute per-metric ratio range across the survivor pool so that
// weights have equal leverage regardless of filter tightness.
const METRIC_KEYS = ['size', 'kg', 'sg', 'sv', 'cb'];

function computeRanges(survivors) {
  const ranges = {};
  METRIC_KEYS.forEach(key => {
    const mk = mkey(key);
    const stdVal = STD_M[mk];
    if (!survivors.length) { ranges[key] = { min: 0, max: 1 }; return; }
    const vals = survivors.map(c => c[mk] / stdVal);
    const lo = Math.min(...vals), hi = Math.max(...vals);
    ranges[key] = { min: lo, max: hi === lo ? lo + 1 : hi }; // avoid /0
  });
  return ranges;
}

function weightedDistance(c, W) {
  const sum = W.size + W.kg + W.sg + W.sv + W.cb;
  const p = {
    size: W.size / sum, kg: W.kg / sum, sg: W.sg / sum,
    sv: W.sv / sum, cb: W.cb / sum
  };
  const ranges = state.lastRanges;
  let dist2 = 0;
  METRIC_KEYS.forEach(key => {
    const wKey = key; // same key names in W
    const mk = mkey(key);
    const ratio = c[mk] / STD_M[mk];
    const { min, max } = ranges[key];
    const norm = (ratio - min) / (max - min); // in [0,1] for survivors
    dist2 += p[wKey] * norm * norm;
  });
  return Math.sqrt(dist2);
}

// ---------- State ----------
const DEFAULTS_X = { size: 1.00, kg: 1.00, sg: 1.00, sv: 1.00, cb: 1.00 };
const DEFAULTS_W = { size: 1.0, kg: 1.0, sg: 1.0, sv: 1.0, cb: 1.0 };

const state = {
  candidates: [],
  initialPool: [],
  siteData: null,          // parsed data.json (null in fallback mode)
  schnorr: { ...SCHNORR_FALLBACK },  // BIP340 ρ reference (live after loadSchnorrRef)
  pools: {},               // scheme -> candidate pool
  scheme: 'SPX',
  useWorst: false,         // filter/rank on worst-case SigVer & ρ
  showOptW: false,         // include w = 32, 64, 128 (non-byte-aligned extras)
  xMax: { kg: 20, sg: 20, sv: 20, cb: 20 },
  X: { ...DEFAULTS_X },
  W: { ...DEFAULTS_W },
  // Live filter results (refreshed every update)
  lastEliminatedAt: null,
  lastSurvivors: [],
  lastWinner: null,
  // Layout cache for hit-testing
  scatterLayout: { pad: 12, w: 0, h: 0 },
  // Per-metric ratio ranges across current survivors (for normalisation)
  lastRanges: Object.fromEntries(['size', 'kg', 'sg', 'sv', 'cb'].map(k => [k, { min: 0, max: 1 }])),
};

// Active Winternitz set: the SLH-DSA-compatible core plus any enabled optional extras (the extras exist in the SPX pool only).
function activeWSet() {
  const act = [...ALLOWED_W];
  if (state.showOptW) act.push(...OPTIONAL_W);
  return act.sort((a, b) => a - b);
}

function rebuildInitialPool() {
  const act = activeWSet();
  state.initialPool = (state.pools[state.scheme] || []).filter(c => act.includes(c.w));
}

// Round a ratio up to a 1-2-5 decade; 20x is the floor so the classic slider range never shrinks.
function niceCap(m) {
  if (!isFinite(m) || m <= 20) return 20;
  const e = Math.pow(10, Math.floor(Math.log10(m)));
  for (const f of [1, 2, 5, 10]) if (f * e >= m) return f * e;
  return 10 * e;
}

// X-slider caps: the largest per-metric ratio present in ANY loaded pool
// (average and worst-case variants), so even the extreme candidates —
// e.g. the tiny-signature d = 2 family with keygen ratios in the tens of
// thousands — stay reachable. Never below 20.
function computeXMax() {
  const maxes = { kg: 0, sg: 0, sv: 0, cb: 0 };
  for (const scheme of Object.keys(state.pools)) {
    for (const c of state.pools[scheme]) {
      if (c.kg / STD_M.kg > maxes.kg) maxes.kg = c.kg / STD_M.kg;
      if (c.sg / STD_M.sg > maxes.sg) maxes.sg = c.sg / STD_M.sg;
      maxes.sv = Math.max(maxes.sv, c.sv / STD_M.sv, c.sv_worst / STD_M.sv_worst);
      maxes.cb = Math.max(maxes.cb, c.cb / STD_M.cb, c.cb_worst / STD_M.cb_worst);
    }
  }
  state.xMax = { kg: niceCap(maxes.kg), sg: niceCap(maxes.sg),
                 sv: niceCap(maxes.sv), cb: niceCap(maxes.cb) };
}

function clampXToMax() {
  for (const k of ['kg', 'sg', 'sv', 'cb']) {
    if (state.X[k] > state.xMax[k]) state.X[k] = state.xMax[k];
  }
}

// Tuples swept per w value: (h, d) pairs with d | h times the k and a ranges.
function consideredPerW(grid) {
  const g = grid || { h: [40, 50], d: [2, 25], k: [6, 24], a: [8, 20] };
  let hd = 0;
  for (let h = g.h[0]; h <= g.h[1]; h++)
    for (let d = g.d[0]; d <= g.d[1]; d++) if (h % d === 0) hd++;
  return hd * (g.k[1] - g.k[0] + 1) * (g.a[1] - g.a[0] + 1);
}

// Stable seeded RNG for scatter positions
function mulberry32(seed) {
  let s = seed | 0;
  return () => {
    s = (s + 0x6D2B79F5) | 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------- Rendering ----------

// Log-position mapping for the cost-coefficient sliders: integer track
// positions 0..SLIDER_STEPS <-> X in [min, max], geometrically spaced.
// (~2% per tick — finer than the old 0.1 linear step near X = 1, and it
// reaches the pool's extreme ratios that a linear 0.1..20 track cannot.)
const SLIDER_STEPS = 1000;
function posToX(pos, min, max) {
  return min * Math.pow(max / min, pos / SLIDER_STEPS);
}
function xToPos(x, min, max) {
  const t = Math.log(x / min) / Math.log(max / min);
  return Math.round(SLIDER_STEPS * Math.max(0, Math.min(1, t)));
}
function fmtX(v) {
  // Keep the string short enough for the 92px value inputs: plain
  // integers up to 6 digits, compact exponential beyond.
  if (v < 100) return v.toFixed(2);
  if (v < 1e6) return String(Math.round(v));
  return v.toExponential(1);
}

function renderControls() {
  const filterDefs = [
    { key: 'size', label: 'Size', min: 0.30, max: 1.00, step: 0.01, dp: 2 },
    { key: 'kg', label: 'KeyGen', min: 0.10, max: state.xMax.kg, log: true },
    { key: 'sg', label: 'SigGen', min: 0.10, max: state.xMax.sg, log: true },
    { key: 'sv', label: 'SigVer', min: 0.10, max: state.xMax.sv, log: true },
    { key: 'cb', label: 'ρ', min: 0.10, max: state.xMax.cb, log: true },
  ];
  document.getElementById('filter-controls').innerHTML = filterDefs.map(d => `
<div class="control">
  <label>
    <span class="name">${d.label}</span>
    <input type="number" class="val-input" aria-label="${d.label} bound"
           id="X_${d.key}_val"
           min="${d.min}" max="${d.max}" step="${d.log ? 'any' : d.step}"
           value="${d.log ? fmtX(state.X[d.key]) : state.X[d.key].toFixed(d.dp)}"
           data-coef-input="${d.key}"${d.log ? '' : ` data-dp="${d.dp}"`}>
  </label>
  <input type="range" aria-label="${d.label} bound" min="${d.log ? 0 : d.min}" max="${d.log ? SLIDER_STEPS : d.max}"
         step="${d.log ? 1 : d.step}"
         value="${d.log ? xToPos(state.X[d.key], d.min, d.max) : state.X[d.key]}"
         data-coef="${d.key}"${d.log ? ' data-log="1"' : ''}>
</div>
  `).join('');

  const weightDefs = [
    { key: 'size', label: 'Size', min: 0.10, max: 20.00, step: 0.10, dp: 1 },
    { key: 'kg', label: 'KeyGen', min: 0.10, max: 20.00, step: 0.10, dp: 1 },
    { key: 'sg', label: 'SigGen', min: 0.10, max: 20.00, step: 0.10, dp: 1 },
    { key: 'sv', label: 'SigVer', min: 0.10, max: 20.00, step: 0.10, dp: 1 },
    { key: 'cb', label: 'ρ', min: 0.10, max: 20.00, step: 0.10, dp: 1 },
  ];
  document.getElementById('weight-controls').innerHTML = weightDefs.map(d => `
<div class="control">
  <label>
    <span class="name">${d.label}</span>
    <input type="number" class="val-input" aria-label="${d.label} weight"
           id="W_${d.key}_val"
           min="${d.min}" max="${d.max}" step="${d.step}"
           value="${state.W[d.key].toFixed(d.dp)}"
           data-weight-input="${d.key}" data-dp="${d.dp}">
  </label>
  <input type="range" aria-label="${d.label} weight" min="${d.min}" max="${d.max}" step="${d.step}"
         value="${state.W[d.key]}" data-weight="${d.key}">
</div>
  `).join('');

  // --- Wire bidirectional input <-> slider for both X and W ---
  // Sliders flagged data-log store a 0..SLIDER_STEPS track position; the
  // real range lives on the paired number input's min/max attributes.
  function bindPair(group, store) {
    // Slider -> store + number-input
    document.querySelectorAll(`input[data-${group}]`).forEach(slider => {
      slider.addEventListener('input', e => {
        const key = e.target.dataset[group];
        const numInp = document.querySelector(`input[data-${group}-input="${key}"]`);
        let v;
        if (e.target.dataset.log) {
          v = posToX(parseFloat(e.target.value),
                     parseFloat(numInp.min), parseFloat(numInp.max));
          numInp.value = fmtX(v);
        } else {
          v = parseFloat(e.target.value);
          numInp.value = v.toFixed(parseInt(numInp.dataset.dp, 10));
        }
        store[key] = v;
        requestUpdate();
      });
    });
    // Number input -> store + slider
    document.querySelectorAll(`input[data-${group}-input]`).forEach(inp => {
      inp.addEventListener('input', e => {
        const key = e.target.dataset[`${group}Input`];
        let v = parseFloat(e.target.value);
        if (!isFinite(v)) return;
        const min = parseFloat(e.target.min);
        const max = parseFloat(e.target.max);
        const clamped = Math.max(min, Math.min(max, v));
        store[key] = clamped;
        const slider = document.querySelector(`input[data-${group}="${key}"]`);
        slider.value = slider.dataset.log ? xToPos(clamped, min, max) : clamped;
        requestUpdate();
      });
      // On blur, reformat to canonical precision and re-clamp the displayed value
      inp.addEventListener('blur', e => {
        const key = e.target.dataset[`${group}Input`];
        e.target.value = e.target.dataset.dp
          ? store[key].toFixed(parseInt(e.target.dataset.dp, 10))
          : fmtX(store[key]);
      });
    });
  }

  bindPair('coef', state.X);
  bindPair('weight', state.W);

  document.getElementById('reset-btn').addEventListener('click', () => {
    state.X = { ...DEFAULTS_X };
    state.W = { ...DEFAULTS_W };
    renderControls();
    update();
  });
}

function renderFunnel(stepCounts) {
  const max = stepCounts[0].count || 1;
  const html = stepCounts.map((s, i) => {
    const widthPct = (s.count / max) * 100;
    const prev = i > 0 ? stepCounts[i - 1].count : null;
    const eliminated = prev !== null && s.count === 0 ? 'eliminated' : '';
    return `
  <div class="funnel-row ${eliminated}">
    <div class="label">${s.name}</div>
    <div><div class="bar" style="width: ${widthPct}%;"></div></div>
    <div class="count">${s.count.toLocaleString('en-US')}</div>
  </div>
`;
  }).join('');
  document.getElementById('funnel').innerHTML = html;
}

// Colour scale: blue (low distance) → red (high distance)
function distanceColor(t) {
  // t in [0, 1]; 0 = best (blue), 1 = worst (red)
  // Use HSL: 220° (blue) → 0° (red), going through purple
  t = Math.max(0, Math.min(1, t));
  const hue = 220 - 220 * t;
  return `hsl(${hue}, 70%, 50%)`;
}

const STEP_COLORS = ['#f87171', '#fb923c', '#facc15', '#a3e635', '#22d3ee'];

function renderScatter(eliminatedAt, survivors, winner) {
  const canvas = document.getElementById('scatter');
  // Set internal resolution from CSS size
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth || 800;
  const cssH = 500;
  canvas.width = cssW * dpr;
  canvas.height = cssH * dpr;
  canvas.style.height = cssH + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, cssW, cssH);

  // Background
  ctx.fillStyle = '#fafafa';
  ctx.fillRect(0, 0, cssW, cssH);

  const pad = 12;
  const w = cssW - 2 * pad;
  const h = cssH - 2 * pad;
  // Cache layout for hit-testing
  state.scatterLayout = { pad, w, h, cssW, cssH };

  // Compute distance for survivors to drive colour
  const dists = survivors.map(c => weightedDistance(c, state.W));
  const dmin = dists.length ? Math.min(...dists) : 0;
  const dmax = dists.length ? Math.max(...dists) : 1;
  const drange = (dmax - dmin) || 1;

  // Draw eliminated first (grey, small), then survivors (coloured), then winner
  for (const c of state.initialPool) {
    const step = eliminatedAt.get(c);
    if (step === null) continue; // survived; draw later
    const x = pad + c._sx * w;
    const y = pad + c._sy * h;
    ctx.fillStyle = '#d4d4d0';
    ctx.globalAlpha = 0.45;
    ctx.beginPath();
    ctx.arc(x, y, 1.6, 0, 2 * Math.PI);
    ctx.fill();
  }
  ctx.globalAlpha = 1;

  for (let i = 0; i < survivors.length; i++) {
    const c = survivors[i];
    const x = pad + c._sx * w;
    const y = pad + c._sy * h;
    const t = (dists[i] - dmin) / drange;
    ctx.fillStyle = distanceColor(t);
    ctx.beginPath();
    ctx.arc(x, y, 3.2, 0, 2 * Math.PI);
    ctx.fill();
  }

  // Winner ring
  if (winner) {
    const x = pad + winner._sx * w;
    const y = pad + winner._sy * h;
    ctx.strokeStyle = '#1a1a1a';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(x, y, 8, 0, 2 * Math.PI);
    ctx.stroke();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(x, y, 6, 0, 2 * Math.PI);
    ctx.stroke();
  }

  canvas.setAttribute('aria-label', `Candidate sieve: ${survivors.length.toLocaleString('en-US')} of ` +
    `${state.initialPool.length.toLocaleString('en-US')} candidates within the bounds` +
    (winner ? `, best (${winner.h}, ${winner.d}, ${winner.k}, ${winner.a}, ${winner.w})` : ''));

  // Legend
  const legendHTML = `
<div class="item"><span class="swatch" style="background:#d4d4d0;"></span>filtered out</div>
<div class="item"><span class="swatch" style="background:${distanceColor(0)};"></span>closest</div>
<div class="item"><span class="swatch" style="background:${distanceColor(0.5)};"></span>middle</div>
<div class="item"><span class="swatch" style="background:${distanceColor(1)};"></span>farthest</div>
<div class="item"><span class="swatch" style="background:#1a1a1a;"></span>best</div>
  `;
  document.getElementById('scatter-legend').innerHTML = legendHTML;
}

function ratioClass(r, inverse = false) {
  // r is target/std. inverse=true means lower is better (default for cost metrics)
  if (inverse) {
    if (r <= 0.8) return 'good';
    if (r <= 1.05) return 'warn';
    return 'bad';
  }
  if (r >= 1.2) return 'good';
  if (r >= 0.95) return 'warn';
  return 'bad';
}

// Rows of the comparison tables: each metric next to its SLH-DSA-128s value.
function comparisonRows(c) {
  const schnorr = state.schnorr.cb64;
  const rows = [
    ['Size (B)', c.size, STD_M.size, fmtNum],
    ['KeyGen (C)', c.kg, STD_M.kg, fmtNum],
    ['SigGen (C)', c.sg, STD_M.sg, fmtNum],
    ['SigVer (C)', c.sv, STD_M.sv, fmtNum],
    ['SigVer, worst (C)', c.sv_worst, STD_M.sv_worst, fmtNum],
    ['ρ (C/B)', c.cb, STD_M.cb, fmtRho],
    ['ρ, worst (C/B)', c.cb_worst, STD_M.cb_worst, fmtRho],
    ['ρ ÷ Schnorr', c.cb / schnorr, STD_M.cb / schnorr, fmtRatio],
    ['ρ ÷ Schnorr, worst', c.cb_worst / schnorr, STD_M.cb_worst / schnorr, fmtRatio],
  ];
  return rows.map(([name, value, std, fmtValue]) => {
    const r = value / std;
    return `<tr><td>${name}</td><td>${fmtValue(value)}</td><td>${fmtValue(std)}</td>` +
      `<td class="ratio ${ratioClass(r, true)}">${fmtRatio(r)}</td></tr>`;
  }).join('');
}

function comparisonTable(c, column) {
  return `<table class="metrics">
      <thead><tr><th>Metric</th><th>${column}</th><th><span class="keep-case">SLH-DSA-128s</span></th><th>Ratio</th></tr></thead>
      <tbody>${comparisonRows(c)}</tbody>
    </table>`;
}

function renderWinner(winner) {
  const el = document.getElementById('winner');
  if (!winner) {
    el.innerHTML = '<div class="empty-state">No candidate is within all bounds. Relax one.</div>';
    return;
  }
  const d = weightedDistance(winner, state.W);
  el.innerHTML = `
<div class="winner-grid">
  <div>
    <p class="winner-tuple">(${winner.h}, ${winner.d}, ${winner.k}, ${winner.a}, ${winner.w})</p>
    <p class="winner-distance">Distance <strong>${d.toFixed(4)}</strong> · h′ = ${winner.h / winner.d}</p>
    ${winner.swn ? `<p class="winner-distance">S<sub>wn</sub> = ${winner.swn}${winner.mmax ? ` · m<sub>max</sub> = ${winner.mmax}` : ''}</p>` : ''}
  </div>
  <div>${comparisonTable(winner, 'Winner')}</div>
</div>
  `;
}

// ---------- Main update loop ----------
function update() {
  const { stepCounts, survivors, eliminatedAt } = runFilters(state.initialPool, state.X);
  renderFunnel(stepCounts);
  // Recompute normalisation ranges for this survivor pool
  state.lastRanges = computeRanges(survivors);
  let winner = null;
  if (survivors.length > 0) {
    winner = survivors[0];
    let bestD = weightedDistance(winner, state.W);
    for (let i = 1; i < survivors.length; i++) {
      const d = weightedDistance(survivors[i], state.W);
      if (d < bestD) { bestD = d; winner = survivors[i]; }
    }
  }
  state.lastEliminatedAt = eliminatedAt;
  state.lastSurvivors = survivors;
  state.lastWinner = winner;
  renderScatter(eliminatedAt, survivors, winner);
  renderWinner(winner);
  scheduleHashWrite();
}

// A slider drag fires an input event per step. Recompute and redraw at
// most once per animation frame instead of once per event.
let updateQueued = false;
function requestUpdate() {
  if (updateQueued) return;
  updateQueued = true;
  requestAnimationFrame(() => { updateQueued = false; update(); });
}

// ---------- Hover tooltip ----------
function findNearestCandidate(mx, my) {
  const { pad, w, h } = state.scatterLayout;
  let best = null, bestD = 12 * 12; // 12px hit radius (squared)
  for (const c of state.initialPool) {
    const x = pad + c._sx * w;
    const y = pad + c._sy * h;
    const dx = mx - x, dy = my - y;
    const d2 = dx * dx + dy * dy;
    if (d2 < bestD) { bestD = d2; best = c; }
  }
  return best;
}

function statusFor(c) {
  if (c === state.lastWinner) return { cls: 'winner', text: '★ Best candidate' };
  const elimStep = state.lastEliminatedAt ? state.lastEliminatedAt.get(c) : null;
  if (elimStep === null || elimStep === undefined) {
    return { cls: 'survivor', text: 'Within all bounds' };
  }
  return { cls: 'eliminated', text: `Outside the ${FILTER_STEPS[elimStep].label} bound` };
}

function renderTooltip(c, clientX, clientY) {
  const tt = document.getElementById('tooltip');
  if (!c) { tt.style.display = 'none'; document.getElementById('hover-ring').style.display = 'none'; return; }
  const st = statusFor(c);
  const isSurvivor = st.cls === 'survivor' || st.cls === 'winner';
  const distHTML = isSurvivor
    ? `<div class="tt-distance">Distance <strong>${weightedDistance(c, state.W).toFixed(4)}</strong></div>`
    : '';

  tt.innerHTML = `
<p class="tt-tuple">(${c.h}, ${c.d}, ${c.k}, ${c.a}, ${c.w})${c.swn ? ` <span style="font-size:11px;color:var(--text-soft);">S<sub>wn</sub>=${c.swn}${c.mmax ? `, mmax=${c.mmax}` : ''}</span>` : ''}</p>
<div class="tt-status ${st.cls}">${st.text}</div>
<table>
  <thead><tr><td></td><td>candidate</td><td>SLH-DSA-128s</td><td>ratio</td></tr></thead>
  <tbody>${comparisonRows(c)}</tbody>
</table>
${distHTML}
  `;
  tt.style.display = 'block';

  // Position: prefer to the right of the cursor, flip if off-screen
  const ttRect = tt.getBoundingClientRect();
  const pad = 12;
  let x = clientX + pad;
  let y = clientY + pad;
  if (x + ttRect.width > window.innerWidth - 8) x = clientX - ttRect.width - pad;
  if (y + ttRect.height > window.innerHeight - 8) y = clientY - ttRect.height - pad;
  tt.style.left = Math.max(8, x) + 'px';
  tt.style.top = Math.max(8, y) + 'px';

  // Hover ring (positioned over the scatter)
  const canvas = document.getElementById('scatter');
  const rect = canvas.getBoundingClientRect();
  const { pad: scPad, w, h } = state.scatterLayout;
  const ring = document.getElementById('hover-ring');
  ring.style.left = (rect.left + scPad + c._sx * w) - canvas.parentElement.getBoundingClientRect().left + 'px';
  ring.style.top = (rect.top + scPad + c._sy * h) - canvas.parentElement.getBoundingClientRect().top + 'px';
  ring.style.display = 'block';
}

// ---------- Custom candidate panel ----------
function validateCustom(p) {
  const errors = [];
  const warnings = [];
  const isPosInt = v => Number.isFinite(v) && v > 0 && Math.floor(v) === v;

  if (!isPosInt(p.h)) errors.push('h must be a positive integer.');
  if (!isPosInt(p.d)) errors.push('d must be a positive integer.');
  if (!isPosInt(p.k)) errors.push('k must be a positive integer.');
  if (!isPosInt(p.a)) errors.push('a must be a positive integer.');
  if (!isPosInt(p.w) || p.w < 2) errors.push('w must be an integer ≥ 2.');

  if (errors.length) return { valid: false, errors, warnings };

  if (p.h % p.d !== 0) {
    errors.push(`d must divide h (h/d = ${(p.h / p.d).toFixed(3)}).`);
  }
  if (!UNIVERSE_W.includes(p.w)) {
    errors.push(`w must be one of ${UNIVERSE_W.join(', ')}.`);
  } else if (OPTIONAL_W.includes(p.w)) {
    warnings.push(`w = ${p.w} is exploratory: its digits do not fit whole bytes, as SLH-DSA requires.`);
  }

  if (errors.length) return { valid: false, errors, warnings };

  // Real security check (FORS subset-forgery analysis, q_s = 2^40)
  const secBits = computeSecurityBits(Q_S_LOG2, p.h, p.k, p.a);
  if (secBits < 128) {
    warnings.push(`Below 128-bit security: ${secBits.toFixed(1)} bits at q<sub>s</sub> = 2<sup>40</sup>.`);
  }

  return { valid: true, errors: [], warnings, secBits };
}

function renderCustom() {
  const p = {
    h: parseInt(document.getElementById('cust-h').value, 10),
    d: parseInt(document.getElementById('cust-d').value, 10),
    k: parseInt(document.getElementById('cust-k').value, 10),
    a: parseInt(document.getElementById('cust-a').value, 10),
    w: parseInt(document.getElementById('cust-w').value, 10),
  };

  const v = validateCustom(p);
  const statusEl = document.getElementById('custom-status');
  const resultEl = document.getElementById('custom-result');
  scheduleHashWrite();

  if (!v.valid) {
    statusEl.className = 'custom-status invalid';
    statusEl.innerHTML = `<strong>Invalid.</strong><ul>${v.errors.map(e => `<li>${e}</li>`).join('')}</ul>`;
    resultEl.innerHTML = '';
    return;
  }

  // Compute metrics
  const m = metrics(p);

  // Guard against overflow: 2^(h/d) exceeds double precision for h' ≳ 1024,
  // and the model stops being meaningful long before that.
  if (!isFinite(m.kg) || !isFinite(m.sg)) {
    statusEl.className = 'custom-status invalid';
    statusEl.innerHTML = `<strong>Out of range.</strong> h′ = ${p.h / p.d} is too large for this model; ` +
      `reduce h or increase d.`;
    resultEl.innerHTML = '';
    return;
  }

  // Status banner
  if (v.warnings.length) {
    statusEl.className = 'custom-status warn';
    statusEl.innerHTML = `<strong>Valid, with notes:</strong><ul>${v.warnings.map(w => `<li>${w}</li>`).join('')}</ul>`;
  } else {
    statusEl.className = 'custom-status ok';
    const sameAsStd = p.h === STD.h && p.d === STD.d && p.k === STD.k && p.a === STD.a && p.w === STD.w;
    statusEl.innerHTML = `<strong>Valid.</strong>${sameAsStd ? ' This is SLH-DSA-128s.' : ''}`;
  }

  const hp = p.h / p.d;
  const wotsL = wotsLen(STD.n, p.w);
  const secRaw = forsForgeryExponent(Q_S_LOG2, p.h, p.k, p.a);
  const rawTxt = secRaw > 300 ? '&gt; 300' : secRaw.toFixed(1);
  const secLabel = secRaw >= 128
    ? `<span style="color:var(--good);">128 bits ✓</span> <span style="color:var(--text-mute);font-size:11px;">` +
      `(${rawTxt} bits against FORS forgery, capped by the 2<sup>−128</sup> preimage bound)</span>`
    : `<span style="color:var(--bad);">${secRaw.toFixed(1)} bits</span>`;

  resultEl.innerHTML = `
<div class="winner-grid">
  <div>
    <p class="winner-tuple">(${p.h}, ${p.d}, ${p.k}, ${p.a}, ${p.w})</p>
    <div class="custom-notes">
      <div>Layer height h′ = ${hp}</div>
      <div>WOTS chains: ${wotsL}</div>
      <div>Security at q<sub>s</sub> = 2<sup>40</sup>: ${secLabel}</div>
    </div>
  </div>
  <div>${comparisonTable(m, 'Yours')}</div>
</div>
  `;
}

function attachCustomCandidate() {
  ['cust-h', 'cust-d', 'cust-k', 'cust-a', 'cust-w'].forEach(id => {
    const el = document.getElementById(id);
    el.addEventListener('input', renderCustom);
    el.addEventListener('change', renderCustom);  // <select> (cust-w) safety
  });
  renderCustom();
}

function attachScatterHover() {
  const canvas = document.getElementById('scatter');
  let last = null;
  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const c = findNearestCandidate(mx, my);
    if (c !== last || c) {
      last = c;
      renderTooltip(c, e.clientX, e.clientY);
    }
  });
  canvas.addEventListener('mouseleave', () => {
    last = null;
    renderTooltip(null);
  });
}

// ---------- Setup ----------
async function loadSiteData() {
  try {
    const resp = await fetch('data.json', { cache: 'no-cache' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    return await resp.json();
  } catch (e) {
    console.warn('data.json unavailable (' + e.message + ') — computing the pool in-browser as fallback.');
    return null;
  }
}

// Fetch the BIP340 Schnorr verification-density reference (C/B) from the bip340-vs-sha256 repo
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

// Cross-check the loaded data against the local formulas: the baseline
// plus a sample of pool rows. Any divergence is a bug in one of the two
// implementations — log it loudly.
function selfCheckData(data, pool) {
  const KEYS = ['size', 'kg', 'sg', 'sv', 'sv_worst'];
  let bad = 0;
  const b = data.baseline;
  if (KEYS.some(k => STD_M[k] !== b[k])) {
    bad++; console.error('data.json baseline disagrees with local formulas:', b, STD_M);
  }
  const step = Math.max(1, Math.floor(pool.length / 25));
  for (let i = 0; i < pool.length; i += step) {
    const c = pool[i];
    const m = metrics(c);
    if (KEYS.some(k => m[k] !== c[k])) {
      bad++; console.error('data.json row disagrees with local formulas:', c, m);
    }
  }
  if (bad === 0) console.log('data.json self-check passed (baseline + sampled rows match local formulas).');
  return bad === 0;
}

// ---------- Schemes ----------
const SCHEME_LABELS = { 'SPX': 'SPX', 'W+C': 'W+C', 'W+C_F+C': 'FORS+C', 'W+C_P+FP': 'PORS+FP' };
const SCHEME_IDS = { 'SPX': 'spx', 'W+C': 'wc', 'W+C_F+C': 'fc', 'W+C_P+FP': 'pfp' };
const SCHEME_FROM_ID = Object.fromEntries(Object.entries(SCHEME_IDS).map(([k, v]) => [v, k]));

function renderSchemeButtons() {
  const host = document.getElementById('scheme-controls');
  const schemes = state.siteData ? state.siteData.meta.schemes : ['SPX'];
  host.innerHTML = schemes.map(s =>
    `<button class="${s === state.scheme ? 'active' : ''}" data-scheme="${s}">${SCHEME_LABELS[s]}</button>`).join('');
  host.querySelectorAll('button').forEach(b =>
    b.addEventListener('click', () => activateScheme(b.dataset.scheme)));
  if (!state.siteData) {
    const hint = document.getElementById('scheme-hint');
    hint.textContent = 'Only SPX: data.json did not load.';
    hint.hidden = false;
  }
}

function schnorrNote() {
  const s = state.schnorr;
  const src = s.live
    ? `kappa.json${s.commit ? ` at secp256k1 ${s.commit}` : ''}${s.run ? `, ${s.run}` : ''}` +
      `${s.machine ? `, ${s.machine}` : ''}${s.preliminary ? ', preliminary' : ''}`
    : 'built-in value, the live kappa.json did not load';
  return `<p>Schnorr reference: a BIP340 verification takes ${s.cb64.toFixed(2)} C/B ` +
    `(${s.impl}, one 64-byte signature; ` +
    `<a href="https://github.com/mjthatch/bip340-vs-sha256">bip340-vs-sha256</a>, ${src}). ` +
    `SLH-DSA-128s has ρ = ${fmtRho(STD_M.cb)} C/B, ${fmtRatio(STD_M.cb / s.cb64)} Schnorr ` +
    `(${fmtRatio(STD_M.cb_worst / s.cb64)} worst).</p>`;
}

function renderInfoStrip() {
  const d = state.siteData;
  const pool = state.initialPool;
  const act = activeWSet();
  const wtxt = state.scheme === 'SPX'
    ? `w = {${act.join(', ')}}`
    : `(w, S<sub>wn</sub>) ∈ {(16, 240), (256, 2040)}`;
  const swept = d
    ? (state.scheme === 'SPX' ? consideredPerW(d.meta.grid) * act.length : d.pools[state.scheme].considered)
    : consideredPerW(null) * act.length;
  document.getElementById('initial-info').innerHTML =
    `Scheme <strong>${SCHEME_LABELS[state.scheme]}</strong> · ` +
    `<strong>${swept.toLocaleString('en-US')}</strong> tuples swept · ` +
    `<strong>${pool.length.toLocaleString('en-US')}</strong> pass the initial bounds`;
  const source = d
    ? `<p>Pool: <code>data.json</code>, generated ${d.meta.generated} from commit ${d.meta.commit}. ` +
      `Security from the FORS and PORS+FP subset-forgery analysis in ` +
      `<a href="https://github.com/BlockstreamResearch/SPHINCS-Parameters/blob/main/security.sage">security.sage</a>.</p>`
    : '<p>Pool computed in the browser, because <code>data.json</code> did not load.</p>';
  document.getElementById('about-pool').innerHTML =
    `<p>Initial bounds: at least 128-bit security at q<sub>s</sub> = 2<sup>40</sup>, ` +
    `size below ${fmtNum(STD_M.size)} B, ${wtxt}.</p>` + source + schnorrNote();
}

function activateScheme(scheme) {
  if (!state.pools[scheme] || scheme === state.scheme) return;
  state.scheme = scheme;
  rebuildInitialPool();
  renderSchemeButtons();
  renderInfoStrip();
  update();
}

// ---------- URL state (shareable views) ----------
const HASH_KEYS = ['size', 'kg', 'sg', 'sv', 'cb'];
const CUSTOM_IDS = ['cust-h', 'cust-d', 'cust-k', 'cust-a', 'cust-w'];
const CUSTOM_DEFAULTS = '63,7,14,12,16';

function writeHash() {
  const parts = [];
  if (state.scheme !== 'SPX') parts.push('s=' + SCHEME_IDS[state.scheme]);
  if (HASH_KEYS.some(k => state.X[k] !== DEFAULTS_X[k]))
    parts.push('x=' + HASH_KEYS.map(k => state.X[k]).join(','));
  if (HASH_KEYS.some(k => state.W[k] !== DEFAULTS_W[k]))
    parts.push('w=' + HASH_KEYS.map(k => state.W[k]).join(','));
  if (state.useWorst) parts.push('wc=1');
  if (state.showOptW) parts.push('ow=1');
  const cust = CUSTOM_IDS.map(id => document.getElementById(id).value).join(',');
  if (cust !== CUSTOM_DEFAULTS) parts.push('c=' + cust);
  const url = parts.length
    ? '#' + parts.join('&')
    : location.pathname + location.search;
  // Safari throws once a page exceeds its history-update quota.
  try { history.replaceState(null, '', url); } catch (err) { /* keep the page working */ }
}

// The address bar mirrors the state, but not on every slider step:
// browsers rate-limit history.replaceState (Chromium silently drops
// calls beyond about 200 per 10 s, which left the URL stale after a long
// drag; Safari throws), and every call is a same-document navigation the
// browser has to process in the middle of the drag. One write, shortly
// after the last change, is enough.
const HASH_WRITE_DELAY_MS = 250;
let hashTimer = null;
function scheduleHashWrite() {
  clearTimeout(hashTimer);
  hashTimer = setTimeout(writeHash, HASH_WRITE_DELAY_MS);
}

function applyHash() {
  const raw = location.hash.replace(/^#/, '');
  if (!raw) return;
  const params = {};
  for (const part of raw.split('&')) {
    const eq = part.indexOf('=');
    if (eq > 0) params[part.slice(0, eq)] = decodeURIComponent(part.slice(eq + 1));
  }
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const setVec = (str, store, isX) => {
    const vals = (str || '').split(',').map(parseFloat);
    if (vals.length !== 5 || !vals.every(isFinite)) return;
    // X cost coefficients accept the full pool range (clampXToMax pulls
    // them down to the computed slider caps right after); weights keep 20.
    HASH_KEYS.forEach((k, i) => {
      store[k] = (k === 'size' && isX)
        ? clamp(vals[i], 0.30, 1.00)
        : clamp(vals[i], 0.10, isX ? 1e9 : 20.00);
    });
  };
  if (params.s && SCHEME_FROM_ID[params.s] && state.pools[SCHEME_FROM_ID[params.s]]) {
    state.scheme = SCHEME_FROM_ID[params.s];
  }
  if (params.x) setVec(params.x, state.X, true);
  if (params.w) setVec(params.w, state.W, false);
  if (params.wc === '1') state.useWorst = true;
  if (params.ow === '1') state.showOptW = true;
  if (params.c) {
    const vals = params.c.split(',').map(v => parseInt(v, 10));
    if (vals.length === 5 && vals.every(Number.isFinite)) {
      if (!UNIVERSE_W.includes(vals[4])) vals[4] = 16;
      CUSTOM_IDS.forEach((id, i) => document.getElementById(id).value = vals[i]);
    }
  }
}

// ---------- CSV export ----------
function exportSurvivorsCSV() {
  const header = ['scheme', 'h', 'd', 'k', 'a', 'w', 'swn', 'mmax', 'size_B',
    'keygen_C', 'siggen_C', 'sigver_C', 'sigver_worst_C',
    'rho', 'rho_worst', 'rho_vs_schnorr', 'rho_worst_vs_schnorr', 'schnorr_rho', 'distance'];
  const lines = [header.join(',')];
  for (const c of state.lastSurvivors) {
    lines.push([state.scheme, c.h, c.d, c.k, c.a, c.w, c.swn || 0, c.mmax || 0,
      c.size, c.kg, c.sg, c.sv, c.sv_worst,
      c.cb.toFixed(6), c.cb_worst.toFixed(6),
      (c.cb / state.schnorr.cb64).toFixed(6),
      (c.cb_worst / state.schnorr.cb64).toFixed(6),
      state.schnorr.cb64.toFixed(6),
      weightedDistance(c, state.W).toFixed(6)].join(','));
  }
  const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `survivors_${SCHEME_IDS[state.scheme]}_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function setup() {
  const [data, schnorr] = await Promise.all([loadSiteData(), loadSchnorrRef()]);
  state.siteData = data;
  state.schnorr = schnorr;
  if (data) {
    data.meta.schemes.forEach((s, si) => {
      const pool = poolFromData(data, s);
      const rand = mulberry32(69421 + si);   // stable layout per scheme
      for (const c of pool) { c._sx = rand(); c._sy = rand(); }
      state.pools[s] = pool;
    });
    selfCheckData(data, state.pools['SPX']);
  } else {
    state.candidates = sweep();
    const pool = state.candidates.filter(passesInitial);
    const rand = mulberry32(69421);
    for (const c of pool) { c._sx = rand(); c._sy = rand(); }
    state.pools['SPX'] = pool;
  }
  computeXMax();             // slider caps from the loaded pools
  applyHash();               // may switch scheme, X/W, worst mode, w extras, custom tuple
  clampXToMax();
  rebuildInitialPool();
  renderControls();
  document.getElementById('worst-toggle').checked = state.useWorst;
  document.getElementById('optw-toggle').checked = state.showOptW;
  document.querySelectorAll('[data-std]').forEach(el => { el.innerHTML = fmtNum(STD_M[el.dataset.std]); });
  renderSchemeButtons();
  renderInfoStrip();
  update();
  attachScatterHover();
  attachCustomCandidate();

  document.getElementById('worst-toggle').addEventListener('change', e => {
    state.useWorst = e.target.checked;
    update();
  });
  document.getElementById('optw-toggle').addEventListener('change', e => {
    state.showOptW = e.target.checked;
    rebuildInitialPool();
    renderInfoStrip();
    update();
  });
  document.getElementById('share-btn').addEventListener('click', async e => {
    writeHash();
    const btn = e.target;
    try {
      await navigator.clipboard.writeText(location.href);
      btn.textContent = 'Link copied ✓';
      setTimeout(() => { btn.textContent = 'Copy shareable link'; }, 1500);
    } catch (err) {
      prompt('Copy this link:', location.href);
    }
  });
  document.getElementById('export-btn').addEventListener('click', exportSurvivorsCSV);

  // Re-render the scatter when the canvas CSS size changes
  window.addEventListener('resize', () => {
    if (state.lastEliminatedAt) {
      renderScatter(state.lastEliminatedAt, state.lastSurvivors, state.lastWinner);
    }
  });
}

if (typeof document !== 'undefined') setup();
