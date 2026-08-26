// Shared cost-model layer for the three site pages.
'use strict';

// ---------- Cost-model constants  ----------

const N = 16;

const C_SIZE = 4;

const R_SIZE = 16;

const C_Th1 = 1;

const C_Th1c = 1;

const C_Th2 = 1;

const C_Hmsg = 2;

const C_PRFmsg = 2;

const C_PRF = 1;

const WOTS_C_SWN = { 16: 240, 32: 403, 64: 693, 128: 1206, 256: 2040, 65536: 262140 };

const UXMSS_TARGET_SIZE = 5712;

const SLH = { h: 63, d: 7, k: 14, a: 12, w: 16 };

const HSF_MAX = 255;


// ---------- Helpers ----------

function idxBytes(h) { return Math.max(1, Math.ceil(h / 8)); }

function computeTh(n) { return Math.ceil((176 + 128 * n + 65) / 512); }


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

function binomBig(n, k) {
  if (k < 0n || k > n) return 0n;
  if (k === 0n || k === n) return 1n;
  if (k > n - k) k = n - k;
  let num = 1n, den = 1n;
  for (let i = 0n; i < k; i++) { num *= (n - i); den *= (i + 1n); }
  return num / den;
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
  return l * C_PRF + Math.floor(l * (w - 1) / 2) * C_Th1;
}

function wotsVerifyWorstSteps(w) {
  const l1 = Math.ceil(8 * N / Math.log2(w));
  const l2 = Math.floor(Math.log2(l1 * (w - 1)) / Math.log2(w)) + 1;
  const C = l1 * (w - 1);
  let ds = 0, rem = C;
  while (rem > 0) { ds += rem % w; rem = Math.floor(rem / w); }
  return l1 * (w - 1) + l2 * (w - 1) - ds;
}

function wotsVerifyC(w, swn, ots, worstCase) {
  const l = wotsL(w, ots);
  const Thl = wotsThl(l, ots);
  if (ots === 'WC') return ((w - 1) * l - swn) * C_Th1 + C_Th1c + Thl;
  if (worstCase) return wotsVerifyWorstSteps(w) * C_Th1 + Thl;
  return Math.floor(l * (w - 1) / 2) * C_Th1 + Thl;
}


// ---------- XMSS / XMSS-MT ----------

function treeSizePerLayer(hPrime, w, ots) {
  const l = wotsL(w, ots);
  const ctr = (ots === 'WC') ? C_SIZE : 0;
  return hPrime * N + l * N + ctr;
}

function treeKeygenC(hPrime, w, ots) {
  // 2^h' WOTS keypairs + 2^h' − 1 internal hashes
  const pk = wotsPkC(w, ots);
  const sz = Math.pow(2, hPrime);
  return sz * pk + (sz - 1) * C_Th2;
}

function treeVerifyC(hPrime, w, swn, ots, worstCase) {
  return wotsVerifyC(w, swn, ots, worstCase) + hPrime * C_Th2;
}

function xmssMtSize(h, d, w, ots) {
  const hPrime = h / d;
  return R_SIZE + d * treeSizePerLayer(hPrime, w, ots) + idxBytes(h);
}

function xmssMtKeygenC(h, d, w, ots) {
  // Build only the top tree (others are derived during signing).
  return treeKeygenC(h / d, w, ots);
}

function xmssMtSignBdsC(h, d, w, swn, ots) {
  const hPrime = h / d;
  const pk = wotsPkC(w, ots);
  const cSg = wotsSignC(w, swn, ots);
  return C_Hmsg + C_PRFmsg + cSg + d * (hPrime * pk + hPrime * C_Th2);
}

function xmssMtSignColdC(h, d, w, swn, ots) {
  // State-minimized signer: rebuild d trees of height h' per signature.
  return C_Hmsg + C_PRFmsg + d * (treeKeygenC(h / d, w, ots) + wotsSignC(w, swn, ots))
       - wotsPkC(w, ots);
}

function xmssMtStateBytes(h, d, w, ots) {
  // BDS-style cached-signer state estimate: ~3.5*h' nodes per layer.
  const hPrime = h / d;
  return d * Math.ceil(3.5 * hPrime) * N + (d - 1) * wotsL(w, ots) * N;
}

function xmssMtVerifyC(h, d, w, swn, ots, worstCase) {
  return C_Hmsg + d * treeVerifyC(h / d, w, swn, ots, worstCase);
}


// ---------- UXMSS (SHRINCS left-leaning) ----------

function uxmssIdxBytes(hsf) {
  if (hsf <= 0) return 1;
  return Math.max(1, Math.ceil(Math.log2(hsf + 1) / 8));
}

function findMaxHsf(w, ots, targetSize) {
  const l = wotsL(w, ots);
  const ctr = (ots === 'WC') ? C_SIZE : 0;
  let hsf = 0;
  for (let i = 0; i < 64; i++) {
    const idx = uxmssIdxBytes(hsf);
    const avail = targetSize - 1 - R_SIZE - ctr - l * N - idx;
    const newHsf = Math.max(0, Math.min(Math.floor(avail / N), HSF_MAX));
    if (newHsf === hsf) return hsf;
    hsf = newHsf;
  }
  return hsf;
}

function uxmssSize(q, hsf, w, ots) {
  const l = wotsL(w, ots);
  const ctr = (ots === 'WC') ? C_SIZE : 0;
  return R_SIZE + ctr + l * N + Math.min(q, hsf) * N + uxmssIdxBytes(hsf);
}

function uxmssKeygenC(hsf, w, ots) {
  return (hsf + 1) * wotsPkC(w, ots) + hsf * C_Th2;
}

function uxmssSignC(w, swn, ots) {
  return C_Hmsg + C_PRFmsg + wotsSignC(w, swn, ots);
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
  const cWotsAvg = Math.floor((p.w - 1) * len / 2) * C_Th1 + Thl;
  const sv = C_Hmsg + cFts + p.d * cWotsAvg + p.h * C_Th2;
  const cWotsWorst = wotsVerifyWorstSteps(p.w) * C_Th1 + Thl;
  const svWorst = C_Hmsg + cFts + p.d * cWotsWorst + p.h * C_Th2;

  return { size, kg, sg, sv, svWorst };
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


// ---------- Shared formatters ----------

function fmtBytes(n) { return n.toLocaleString() + ' B'; }

function fmtCompressions(n) {
  if (!isFinite(n)) return '—';
  if (n >= 1e15) return n.toExponential(2);
  if (n >= 1e12) return (n / 1e12).toFixed(2) + 'T';
  if (n >= 1e9)  return (n / 1e9).toFixed(2) + 'G';
  if (n >= 1e6)  return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3)  return (n / 1e3).toFixed(1) + 'K';
  return Math.round(n).toLocaleString();
}

function fmtCpb(n) { return n.toFixed(3); }
