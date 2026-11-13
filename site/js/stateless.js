// The Parameter Explorer: filters the candidate pools of data.json by bounds
// relative to SLH-DSA-128s, ranks what is left by distance, and compares a
// candidate of your own.
'use strict';

// SLH-DSA-compatible Winternitz parameters: log2(w) divides 8, so message
// digits stay byte-aligned.
const ALLOWED_W = [2, 4, 16, 256];

// Exploratory w; a checkbox adds them to the SPX pool.
const OPTIONAL_W = [32, 64, 128];
const UNIVERSE_W = [...ALLOWED_W, ...OPTIONAL_W];

// Explorer rows use data.json's field names and carry ρ.
function metrics(p) {
  const m = slhMetrics(p);
  return {
    size: m.size, kg: m.kg, sg: m.sg, sv: m.sv, sv_worst: m.svWorst,
    cb: m.sv / m.size, cb_worst: m.svWorst / m.size,
  };
}

const STD_M = metrics(SLH);

// The pool of a scheme, from data.json (export_site_data.sage).
function poolFromData(data, scheme) {
  const p = data.pools[scheme];
  const idx = fieldIndex(p);
  // A data.json made for another grid can hold other w.
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

// Field of metric k: worst-case mode switches SigVer and ρ to their worst case.
function mkey(k) {
  return state.useWorst && (k === 'sv' || k === 'cb') ? k + '_worst' : k;
}

const FILTER_STEPS = [
  { key: 'size', metric: 'size', label: 'Size' },
  { key: 'kg', metric: 'kg', label: 'KeyGen' },
  { key: 'sg', metric: 'sg', label: 'SigGen' },
  { key: 'sv', metric: 'sv', label: 'SigVer' },
  { key: 'cb', metric: 'cb', label: 'ρ' },
];

// Applies the bounds X in turn. Returns the count after each step, the
// survivors, and the step that removed each candidate (null if none did).
function runFilters(pool, X) {
  const eliminatedAt = new Map();
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

// Ratios to SLH-DSA-128s, with the worst-case SigVer and ρ in worst-case mode.
function ratiosOf(c) {
  const r = {};
  for (const k of DISTANCE_KEYS) r[k] = c[mkey(k)] / STD_M[mkey(k)];
  return r;
}

function distanceOf(c, W) {
  return weightedDistance(ratiosOf(c), state.lastRanges, W);
}

const DEFAULTS_X = { size: 1.00, kg: 1.00, sg: 1.00, sv: 1.00, cb: 1.00 };
const DEFAULTS_W = { size: 1.0, kg: 1.0, sg: 1.0, sv: 1.0, cb: 1.0 };

const state = {
  initialPool: [],
  siteData: null,          // parsed data.json, null if it did not load
  pools: {},               // scheme -> candidate pool
  scheme: 'SPX',
  useWorst: false,         // bounds and ranking on worst-case SigVer and ρ
  showOptW: false,         // include OPTIONAL_W
  xMax: { kg: 20, sg: 20, sv: 20, cb: 20 },
  X: { ...DEFAULTS_X },
  W: { ...DEFAULTS_W },
  // results of the last update
  lastEliminatedAt: null,
  lastSurvivors: [],
  lastWinner: null,
  // scatter geometry, for hit-testing
  scatterLayout: { pad: 12, w: 0, h: 0 },
  // ratio ranges over the survivors, for the distance
  lastRanges: Object.fromEntries(['size', 'kg', 'sg', 'sv', 'cb'].map(k => [k, { min: 0, max: 1 }])),
};

// Winternitz parameters in the pool: OPTIONAL_W exist in the SPX pool only.
function activeWSet() {
  const act = [...ALLOWED_W];
  if (state.showOptW) act.push(...OPTIONAL_W);
  return act.sort((a, b) => a - b);
}

function rebuildInitialPool() {
  const act = activeWSet();
  state.initialPool = (state.pools[state.scheme] || []).filter(c => act.includes(c.w));
}

// Bound slider caps: the largest ratio of each metric in any pool, average or
// worst case, so every candidate stays reachable (KeyGen ratios of the d = 2
// candidates reach tens of thousands).
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
function consideredPerW(g) {
  let hd = 0;
  for (let h = g.h[0]; h <= g.h[1]; h++)
    for (let d = g.d[0]; d <= g.d[1]; d++) if (h % d === 0) hd++;
  return hd * (g.k[1] - g.k[0] + 1) * (g.a[1] - g.a[0] + 1);
}

// Seeded random numbers, so the dots keep their places between visits.
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
           data-key="${d.key}"${d.log ? '' : ` data-dp="${d.dp}"`}>
  </label>
  <input type="range" aria-label="${d.label} bound" min="${d.log ? 0 : d.min}" max="${d.log ? SLIDER_STEPS : d.max}"
         step="${d.log ? 1 : d.step}"
         value="${d.log ? xToPos(state.X[d.key], d.min, d.max) : state.X[d.key]}"
         data-key="${d.key}"${d.log ? ' data-log="1"' : ''}>
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
           data-key="${d.key}" data-dp="${d.dp}">
  </label>
  <input type="range" aria-label="${d.label} weight" min="${d.min}" max="${d.max}" step="${d.step}"
         value="${state.W[d.key]}" data-key="${d.key}">
</div>
  `).join('');

  bindSliderPairs(document.getElementById('filter-controls'), state.X, requestUpdate);
  bindSliderPairs(document.getElementById('weight-controls'), state.W, requestUpdate);
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

// Colour of a distance scaled to [0, 1]: blue for the closest, through purple
// to red.
function distanceColor(t) {
  t = Math.max(0, Math.min(1, t));
  const hue = 220 - 220 * t;
  return `hsl(${hue}, 70%, 50%)`;
}

const STEP_COLORS = ['#f87171', '#fb923c', '#facc15', '#a3e635', '#22d3ee'];

function renderScatter(eliminatedAt, survivors, winner) {
  const canvas = document.getElementById('scatter');
  // Canvas pixels follow the device pixel ratio.
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth || 800;
  const cssH = 500;
  canvas.width = cssW * dpr;
  canvas.height = cssH * dpr;
  canvas.style.height = cssH + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, cssW, cssH);

  ctx.fillStyle = '#fafafa';
  ctx.fillRect(0, 0, cssW, cssH);

  const pad = 12;
  const w = cssW - 2 * pad;
  const h = cssH - 2 * pad;
  state.scatterLayout = { pad, w, h, cssW, cssH };

  const dists = survivors.map(c => distanceOf(c, state.W));
  const dmin = dists.length ? Math.min(...dists) : 0;
  const dmax = dists.length ? Math.max(...dists) : 1;
  const drange = (dmax - dmin) || 1;

  // Grey dots first, so the coloured ones and the winner stay on top.
  for (const c of state.initialPool) {
    const step = eliminatedAt.get(c);
    if (step === null) continue;
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

  const legendHTML = `
<div class="item"><span class="swatch" style="background:#d4d4d0;"></span>filtered out</div>
<div class="item"><span class="swatch" style="background:${distanceColor(0)};"></span>closest</div>
<div class="item"><span class="swatch" style="background:${distanceColor(0.5)};"></span>middle</div>
<div class="item"><span class="swatch" style="background:${distanceColor(1)};"></span>farthest</div>
<div class="item"><span class="swatch" style="background:#1a1a1a;"></span>best</div>
  `;
  document.getElementById('scatter-legend').innerHTML = legendHTML;
}

// Colour of a ratio to SLH-DSA-128s; lower is better.
function ratioTone(r) {
  if (r <= 0.8) return 'good';
  if (r <= 1.05) return 'warn';
  return 'bad';
}

// Rows of the comparison tables: each metric next to its SLH-DSA-128s value.
function comparisonRows(c) {
  const schnorr = SCHNORR.cb64;
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
      `<td class="ratio ${ratioTone(r)}">${fmtRatio(r)}</td></tr>`;
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
  const d = distanceOf(winner, state.W);
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

// Filters, ranks and redraws after any change of the bounds, weights or pool.
function update() {
  if (!state.siteData) {
    document.getElementById('winner').innerHTML = '<div class="empty-state">No candidate pool.</div>';
    return;
  }
  const { stepCounts, survivors, eliminatedAt } = runFilters(state.initialPool, state.X);
  renderFunnel(stepCounts);
  state.lastRanges = ratioRanges(survivors.map(ratiosOf));
  let winner = null;
  if (survivors.length > 0) {
    winner = survivors[0];
    let bestD = distanceOf(winner, state.W);
    for (let i = 1; i < survivors.length; i++) {
      const d = distanceOf(survivors[i], state.W);
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

const requestUpdate = oncePerFrame(update);

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
    ? `<div class="tt-distance">Distance <strong>${distanceOf(c, state.W).toFixed(4)}</strong></div>`
    : '';

  tt.innerHTML = `
<p class="tt-tuple">(${c.h}, ${c.d}, ${c.k}, ${c.a}, ${c.w})${c.swn ? ` <span class="tt-swn">S<sub>wn</sub>=${c.swn}${c.mmax ? `, mmax=${c.mmax}` : ''}</span>` : ''}</p>
<div class="tt-status ${st.cls}">${st.text}</div>
<table>
  <thead><tr><td></td><td>candidate</td><td>SLH-DSA-128s</td><td>ratio</td></tr></thead>
  <tbody>${comparisonRows(c)}</tbody>
</table>
${distHTML}
  `;
  tt.style.display = 'block';

  // Right of and below the cursor, flipped where that leaves the window.
  const ttRect = tt.getBoundingClientRect();
  const pad = 12;
  let x = clientX + pad;
  let y = clientY + pad;
  if (x + ttRect.width > window.innerWidth - 8) x = clientX - ttRect.width - pad;
  if (y + ttRect.height > window.innerHeight - 8) y = clientY - ttRect.height - pad;
  tt.style.left = Math.max(8, x) + 'px';
  tt.style.top = Math.max(8, y) + 'px';

  const canvas = document.getElementById('scatter');
  const rect = canvas.getBoundingClientRect();
  const { pad: scPad, w, h } = state.scatterLayout;
  const ring = document.getElementById('hover-ring');
  ring.style.left = (rect.left + scPad + c._sx * w) - canvas.parentElement.getBoundingClientRect().left + 'px';
  ring.style.top = (rect.top + scPad + c._sy * h) - canvas.parentElement.getBoundingClientRect().top + 'px';
  ring.style.display = 'block';
}

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

  const m = metrics(p);

  // 2^(h/d) overflows a double for h' above about 1024, and the model stops
  // being meaningful long before that.
  if (!isFinite(m.kg) || !isFinite(m.sg)) {
    statusEl.className = 'custom-status invalid';
    statusEl.innerHTML = `<strong>Out of range.</strong> h′ = ${p.h / p.d} is too large for this model; ` +
      `reduce h or increase d.`;
    resultEl.innerHTML = '';
    return;
  }

  if (v.warnings.length) {
    statusEl.className = 'custom-status warn';
    statusEl.innerHTML = `<strong>Valid, with notes:</strong><ul>${v.warnings.map(w => `<li>${w}</li>`).join('')}</ul>`;
  } else {
    statusEl.className = 'custom-status ok';
    const sameAsStd = p.h === SLH.h && p.d === SLH.d && p.k === SLH.k && p.a === SLH.a && p.w === SLH.w;
    statusEl.innerHTML = `<strong>Valid.</strong>${sameAsStd ? ' This is SLH-DSA-128s.' : ''}`;
  }

  const hp = p.h / p.d;
  const chains = wotsL(p.w, 'TW');
  const secRaw = forsForgeryExponent(Q_S_LOG2, p.h, p.k, p.a);
  const rawTxt = secRaw > 300 ? '&gt; 300' : secRaw.toFixed(1);
  const secLabel = secRaw >= 128
    ? `<span class="sec-ok">128 bits ✓</span> <span class="sec-detail">` +
      `(${rawTxt} bits against FORS forgery, capped by the 2<sup>−128</sup> preimage bound)</span>`
    : `<span class="sec-low">${secRaw.toFixed(1)} bits</span>`;

  resultEl.innerHTML = `
<div class="winner-grid">
  <div>
    <p class="winner-tuple">(${p.h}, ${p.d}, ${p.k}, ${p.a}, ${p.w})</p>
    <div class="custom-notes">
      <div>Layer height h′ = ${hp}</div>
      <div>WOTS chains: ${chains}</div>
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
    el.addEventListener('change', renderCustom);  // the w select
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

// Checks data.json against the model on the baseline and a sample of rows; a
// mismatch is a bug in one of the two.
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

const SCHEME_LABELS = { 'SPX': 'SPX', 'W+C': 'W+C', 'W+C_F+C': 'FORS+C', 'W+C_P+FP': 'PORS+FP' };
const SCHEME_IDS = { 'SPX': 'spx', 'W+C': 'wc', 'W+C_F+C': 'fc', 'W+C_P+FP': 'pfp' };
const SCHEME_FROM_ID = Object.fromEntries(Object.entries(SCHEME_IDS).map(([k, v]) => [v, k]));

function renderSchemeButtons() {
  const host = document.getElementById('scheme-controls');
  const schemes = state.siteData ? state.siteData.meta.schemes : [];
  host.innerHTML = schemes.map(s =>
    `<button class="${s === state.scheme ? 'active' : ''}" data-scheme="${s}">${SCHEME_LABELS[s]}</button>`).join('');
  host.querySelectorAll('button').forEach(b =>
    b.addEventListener('click', () => activateScheme(b.dataset.scheme)));
}

function schnorrNote() {
  const s = SCHNORR;
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
  if (!d) {
    document.getElementById('initial-info').textContent = 'No candidate pool: data.json did not load.';
    document.getElementById('about-pool').innerHTML = schnorrNote();
    return;
  }
  const pool = state.initialPool;
  const act = activeWSet();
  const wtxt = state.scheme === 'SPX'
    ? `w = {${act.join(', ')}}`
    : `(w, S<sub>wn</sub>) ∈ {(16, 240), (256, 2040)}`;
  const swept = state.scheme === 'SPX'
    ? consideredPerW(d.meta.grid) * act.length
    : d.pools[state.scheme].considered;
  document.getElementById('initial-info').innerHTML =
    `Scheme <strong>${SCHEME_LABELS[state.scheme]}</strong> · ` +
    `<strong>${swept.toLocaleString('en-US')}</strong> tuples swept · ` +
    `<strong>${pool.length.toLocaleString('en-US')}</strong> pass the initial bounds`;
  const source = `<p>Pool: <code>data.json</code>, generated ${d.meta.generated} from commit ${d.meta.commit}. ` +
    `Security from the FORS and PORS+FP subset-forgery analysis in ` +
    `<a href="https://github.com/BlockstreamResearch/SPHINCS-Parameters/blob/main/model/security.sage">security.sage</a>.</p>`;
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
  replaceHash(parts);
}

const scheduleHashWrite = hashWriter(writeHash);

function applyHash() {
  const params = readHash();
  const setVec = (str, store, isX) => {
    const vals = (str || '').split(',').map(parseFloat);
    if (vals.length !== 5 || !vals.every(isFinite)) return;
    // Bounds accept the whole pool range here; clampXToMax lowers them to the
    // slider caps next. Weights stay within 20.
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

function exportSurvivorsCSV() {
  const header = ['scheme', 'h', 'd', 'k', 'a', 'w', 'swn', 'mmax', 'size_B',
    'keygen_C', 'siggen_C', 'sigver_C', 'sigver_worst_C',
    'rho', 'rho_worst', 'rho_vs_schnorr', 'rho_worst_vs_schnorr', 'schnorr_rho', 'distance'];
  const lines = [header.join(',')];
  for (const c of state.lastSurvivors) {
    lines.push([state.scheme, c.h, c.d, c.k, c.a, c.w, c.swn || 0, c.mmax || 0,
      c.size, c.kg, c.sg, c.sv, c.sv_worst,
      c.cb.toFixed(6), c.cb_worst.toFixed(6),
      (c.cb / SCHNORR.cb64).toFixed(6),
      (c.cb_worst / SCHNORR.cb64).toFixed(6),
      SCHNORR.cb64.toFixed(6),
      distanceOf(c, state.W).toFixed(6)].join(','));
  }
  downloadCSV(`survivors_${SCHEME_IDS[state.scheme]}`, lines);
}

async function setup() {
  const [data, schnorr] = await Promise.all([loadSiteData(), loadSchnorrRef()]);
  state.siteData = data;
  SCHNORR = schnorr;
  if (data) {
    data.meta.schemes.forEach((s, si) => {
      const pool = poolFromData(data, s);
      const rand = mulberry32(69421 + si);   // stable layout per scheme
      for (const c of pool) { c._sx = rand(); c._sy = rand(); }
      state.pools[s] = pool;
    });
    selfCheckData(data, state.pools['SPX']);
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
  document.getElementById('reset-btn').addEventListener('click', () => {
    state.X = { ...DEFAULTS_X };
    state.W = { ...DEFAULTS_W };
    renderControls();
    update();
  });
  bindShareButton(writeHash);
  document.getElementById('export-btn').addEventListener('click', exportSurvivorsCSV);

  // The canvas follows its width.
  window.addEventListener('resize', () => {
    if (state.lastEliminatedAt) {
      renderScatter(state.lastEliminatedAt, state.lastSurvivors, state.lastWinner);
    }
  });
}

// The tests load this file under node, without a document.
if (typeof document !== 'undefined') setup();
