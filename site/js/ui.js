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
    const from = r.left + pop.offsetWidth > innerWidth - edge ? r.right - pop.offsetWidth : r.left;
    const left = Math.max(edge, Math.min(from, innerWidth - pop.offsetWidth - edge));
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
    <dd>One SHA-256 compression call.</dd>
    <dt>B</dt>
    <dd>Byte.</dd>
    <dt>KeyGen, SigGen, SigVer</dt>
    <dd>The number of C that the function requires.</dd>
    <dt>ρ</dt>
    <dd>The number of C per signature byte (SigVer).</dd>
    <dt>ρ ÷ Schnorr</dt>
    <dd>ρ divided by per-byte BIP340 Schnorr verification cost.</dd>
    <dt>SLH-DSA-128s</dt>
    <dd>The FIPS 205 parameter set. Ratios compare against it.</dd>
    <dt>h</dt>
    <dd>Hypertree height.</dd>
    <dt>d</dt>
    <dd>The number of layers.</dd>
    <dt>k</dt>
    <dd>The number of FORS trees.</dd>
    <dt>a</dt>
    <dd>FORS tree height.</dd>
    <dt>w</dt>
    <dd>Winternitz parameter.</dd>
    <dt>h′ = h/d</dt>
    <dd>Height of one hypertree layer.</dd>
    <dt>q<sub>s</sub></dt>
    <dd>Signature budget.</dd>
    <dt>Cached / Cold</dt>
    <dd>Signing mode.</dd>
  </dl>
</div>`);
