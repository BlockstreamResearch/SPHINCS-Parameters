// Helpers shared by the three site pages: number formats, popovers, sliders,
// the address bar, data.json and the glossary.
'use strict';

// Number formats

// Compressions and bytes: exact up to six digits, compact above, with the exact value on hover. Returns HTML.
function fmtNum(n) {
  if (!isFinite(n)) return '—';
  n = Math.round(n);
  const exact = n.toLocaleString('en-US');
  if (n < 1e6) return exact;
  for (const [unit, size] of [['M', 1e6], ['G', 1e9], ['T', 1e12], ['P', 1e15]]) {
    const v = (n / size).toPrecision(3);
    if (Number(v) < 1000) return `<span title="${exact}">${v}${unit}</span>`;
  }
  return `<span title="${exact}">${n.toExponential(2)}</span>`;
}

// Ratios to a reference value, to three significant digits.
function fmtRatio(r) {
  if (r >= 100) return Math.round(r).toLocaleString('en-US') + '×';
  return r.toPrecision(3) + '×';
}

// ρ, in compressions per signature byte.
function fmtRho(r) {
  return r.toFixed(4);
}

function fmtPow2(e) {
  return `2<sup>${e}</sup>`;
}

// Popovers: <button class="info" popovertarget="ID" aria-label="About …">i</button> opens
// <div class="pop" id="ID" popover>…</div>. The browser opens and closes the popover;
// this code only places it next to its button.

function infoButton(id, label) {
  return `<button type="button" class="info" popovertarget="${id}" aria-label="${label}">i</button>`;
}

(function () {
  if (typeof document === 'undefined') return;   // under node, in the tests
  if (!('popover' in HTMLElement.prototype)) return;  // older browsers show the content inline
  let opener = null;
  document.addEventListener('click', e => {
    const b = e.target.closest && e.target.closest('[popovertarget]');
    if (b) opener = b;
  }, true);

  function place(pop) {
    const btn = opener && opener.isConnected && opener.getAttribute('popovertarget') === pop.id
      ? opener : document.querySelector(`[popovertarget="${pop.id}"]`);
    if (!btn) return;
    const r = btn.getBoundingClientRect(), gap = 6, edge = 8;
    const left = Math.max(edge, Math.min(r.left, innerWidth - pop.offsetWidth - edge));
    let top = r.bottom + gap;
    if (top + pop.offsetHeight > innerHeight - edge && r.top - gap - pop.offsetHeight >= edge) {
      top = r.top - gap - pop.offsetHeight;
    }
    pop.style.left = `${left}px`;
    pop.style.top = `${Math.max(edge, top)}px`;
  }

  // toggle does not bubble, so listen in the capture phase.
  document.addEventListener('toggle', e => {
    if (e.newState === 'open' && e.target.classList.contains('pop')) place(e.target);
  }, true);
  const placeOpen = () => document.querySelectorAll('.pop:popover-open').forEach(place);
  addEventListener('resize', placeOpen);
  addEventListener('scroll', placeOpen, true);
})();

// Sliders

function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}

// A log-scale slider holds a track position 0..SLIDER_STEPS that maps
// geometrically onto min..max.
const SLIDER_STEPS = 1000;

function posToX(pos, min, max) {
  return min * Math.pow(max / min, pos / SLIDER_STEPS);
}

function xToPos(x, min, max) {
  const t = Math.log(x / min) / Math.log(max / min);
  return Math.round(SLIDER_STEPS * clamp(t, 0, 1));
}

// Short enough for the number inputs: two decimals below 100, integers below
// a million, exponential above.
function fmtX(v) {
  if (v < 100) return v.toFixed(2);
  if (v < 1e6) return String(Math.round(v));
  return v.toExponential(1);
}

// Slider caps: the ratio rounded up to 1, 2 or 5 times a power of ten, at least 20.
function niceCap(m) {
  if (!isFinite(m) || m <= 20) return 20;
  const e = Math.pow(10, Math.floor(Math.log10(m)));
  for (const f of [1, 2, 5, 10]) if (f * e >= m) return f * e;
  return 10 * e;
}

// Keeps store[key] in step with each range input in host and the number input
// with the same data-key. A range with data-log is a log-scale slider over the
// number input's min..max; a number input with data-dp shows that many decimals.
function bindSliderPairs(host, store, onChange) {
  for (const slider of host.querySelectorAll('input[type="range"][data-key]')) {
    const key = slider.dataset.key;
    const num = host.querySelector(`input[type="number"][data-key="${key}"]`);
    const show = v => {
      num.value = num.dataset.dp ? v.toFixed(parseInt(num.dataset.dp, 10)) : fmtX(v);
    };
    slider.addEventListener('input', () => {
      const v = slider.dataset.log
        ? posToX(parseFloat(slider.value), parseFloat(num.min), parseFloat(num.max))
        : parseFloat(slider.value);
      store[key] = v;
      show(v);
      onChange();
    });
    num.addEventListener('input', () => {
      const v = parseFloat(num.value);
      if (!isFinite(v)) return;
      const min = parseFloat(num.min), max = parseFloat(num.max);
      store[key] = clamp(v, min, max);
      slider.value = slider.dataset.log ? xToPos(store[key], min, max) : store[key];
      onChange();
    });
    num.addEventListener('blur', () => show(store[key]));
  }
}

// A slider drag fires an input event per step: run fn at most once per frame.
function oncePerFrame(fn) {
  let queued = false;
  return () => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => { queued = false; fn(); });
  };
}

// Address bar

// The #key=value&... parameters.
function readHash() {
  const params = {};
  for (const part of location.hash.replace(/^#/, '').split('&')) {
    const eq = part.indexOf('=');
    if (eq > 0) params[part.slice(0, eq)] = decodeURIComponent(part.slice(eq + 1));
  }
  return params;
}

function replaceHash(parts) {
  const url = parts.length ? '#' + parts.join('&') : location.pathname + location.search;
  // Safari throws once a page exceeds its history-update quota.
  try { history.replaceState(null, '', url); } catch (err) { /* keep the page working */ }
}

// Browsers rate-limit history.replaceState (Chromium drops calls beyond about
// 200 per 10 s), so the address bar is written once, shortly after the last
// change, rather than on every slider step.
const HASH_WRITE_DELAY_MS = 250;

function hashWriter(write) {
  let timer = null;
  return () => {
    clearTimeout(timer);
    timer = setTimeout(write, HASH_WRITE_DELAY_MS);
  };
}

function bindShareButton(writeHash) {
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
}

// Data

async function loadSiteData() {
  try {
    const resp = await fetch('data.json', { cache: 'no-cache' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    return await resp.json();
  } catch (e) {
    console.warn('data.json unavailable (' + e.message + ')');
    return null;
  }
}

// Column of each field in a data.json table.
function fieldIndex(table) {
  return Object.fromEntries(table.fields.map((f, i) => [f, i]));
}

function downloadCSV(name, lines) {
  const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${name}_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// Glossary

if (typeof document !== 'undefined') document.body.insertAdjacentHTML('beforeend', `
<div class="pop pop-wide" id="glossary" popover>
  <h3>Glossary</h3>
  <dl>
    <dt>C</dt>
    <dd>One SHA-256 compression. Costs count compressions; the PK.seed block is compressed once per key and reused.</dd>
    <dt>B</dt>
    <dd>Byte.</dd>
    <dt>KeyGen, SigGen, SigVer</dt>
    <dd>Compressions to generate a key pair, to sign a message and to verify a signature. SigVer is the average unless marked worst.</dd>
    <dt>ρ</dt>
    <dd>SigVer per signature byte, in C/B.</dd>
    <dt>ρ ÷ Schnorr</dt>
    <dd>ρ divided by the ρ of a BIP340 Schnorr verification (libsecp256k1, 64-byte signature).</dd>
    <dt>SLH-DSA-128s</dt>
    <dd>The FIPS 205 parameter set (h, d, k, a, w) = (63, 7, 14, 12, 16). Ratios (×) compare against it.</dd>
    <dt>h, d, k, a, w</dt>
    <dd>Hypertree height, number of layers, FORS trees, FORS tree height, Winternitz parameter. h′ = h/d is the height of one layer.</dd>
    <dt>q<sub>s</sub></dt>
    <dd>The number of signatures per key that security is computed for: 2<sup>40</sup> for the stateless schemes.</dd>
    <dt>WOTS, WOTS+C</dt>
    <dd>Winternitz one-time signatures. WOTS (as in SLH-DSA) has checksum chains; WOTS+C replaces them with a counter that the signer grinds until the message digits have a fixed sum, so verification always costs the same.</dd>
    <dt>XMSS, XMSS-MT, UXMSS</dt>
    <dd>Stateful schemes: one balanced Merkle tree (BXMSS in SHRINCS), d layers of such trees, and the unbalanced SHRINCS tree, whose signatures grow by one node per signature.</dd>
    <dt>Cached, cold</dt>
    <dd>A cached signer keeps tree state between signatures (a BDS state for XMSS, a leaf cache for UXMSS); a cold signer keeps none and rebuilds its trees for every signature.</dd>
  </dl>
</div>`);
