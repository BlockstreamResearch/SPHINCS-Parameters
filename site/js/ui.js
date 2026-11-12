// Number formats, popovers and the glossary.
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

// Glossary

document.body.insertAdjacentHTML('beforeend', `
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
