// The pinned parameters page: the stateless parameters of the report's
// candidate 1 and the stateful XMSS and UXMSS cards.
'use strict';

// Explorer links that point here (#s=…&x=…&w=…&wc=…&c=…) belong to
// stateless.html. Under node, where the tests run, there is no location.
if (typeof location !== 'undefined' && location.hash &&
    /(^#|[#&])(s|x|w|wc|c)=/.test(location.hash)) {
  location.replace('stateless.html' + location.hash);
}

const PINNED = { h: 45, d: 5, k: 10, a: 13, w: 16 };   // the report's candidate 1
const XMSS_W = 64;      // the stateful cards use WOTS+C with w = 64
const XMSS_H_MAX = 20;

// A SHRINCS stateless signature is the SLH-DSA signature behind the one-byte
// indicator: 5,777 B for the pinned parameters.
function shrincsStatelessSize(p) { return slhMetrics(p).size + IND_SIZE; }

function row(name, value) {
  return `<tr><td>${name}</td><td>${value}</td></tr>`;
}

function renderStateless() {
  const m = slhMetrics(PINNED);
  const size = shrincsStatelessSize(PINNED);
  const cb = m.sv / size, cbW = m.svWorst / size;
  document.getElementById('stateless-table').innerHTML = [
    row('Max signatures', fmtPow2(40)),
    row('Size (B)', fmtNum(size)),
    row('KeyGen (C)', fmtNum(m.kg)),
    row('SigGen (C)', fmtNum(m.sg)),
    row('SigVer (C)', fmtNum(m.sv)),
    row('SigVer, worst (C)', fmtNum(m.svWorst)),
    row('ρ (C/B)', fmtRho(cb)),
    row('ρ, worst (C/B)', fmtRho(cbW)),
    row('ρ ÷ Schnorr, worst', fmtRatio(cbW / SCHNORR.cb64)),
  ].join('');
}

function renderXmss() {
  const h = state.xmssH;
  const swn = WOTS_C_SWN[XMSS_W];
  const size = xmssMtSize(h, 1, XMSS_W, 'WC');
  const kg = xmssMtKeygenC(h, 1, XMSS_W, 'WC');
  const sg = xmssMtSignBdsC(h, 1, XMSS_W, swn, 'WC');
  const sgCold = xmssMtSignColdC(h, 1, XMSS_W, swn, 'WC');
  const st = xmssMtStateBytes(h, 1, XMSS_W, 'WC');
  const sv = xmssMtVerifyC(h, 1, XMSS_W, swn, 'WC');
  const cb = sv / size;
  document.getElementById('xmss-tuple').textContent = `WOTS+C, w = ${XMSS_W}, h = ${h}`;
  document.getElementById('xmss-table').innerHTML = [
    row('Max signatures', fmtPow2(h)),
    row('Size (B)', fmtNum(size)),
    row('KeyGen (C)', fmtNum(kg)),
    row('SigGen, cached (C)', fmtNum(sg)),
    row('SigGen, cold (C)', fmtNum(sgCold)),
    row('State (B)', fmtNum(st)),
    row('SigVer (C)', fmtNum(sv)),
    row('ρ (C/B)', fmtRho(cb)),
    row('ρ ÷ Schnorr', fmtRatio(cb / SCHNORR.cb64)),
  ].join('');
  const link = document.getElementById('xmss-link');
  link.href = `stateful.html#cand=xmssmt-WC-${XMSS_W}-${h}-1,uxmss-WC-${XMSS_W}`;
}

function renderUxmss() {
  const swn = WOTS_C_SWN[XMSS_W];
  const hsf = findMaxHsf(XMSS_W, 'WC', UXMSS_TARGET_SIZE);
  const sz1 = uxmssSize(1, hsf, XMSS_W, 'WC');
  const szMax = uxmssSize(hsf, hsf, XMSS_W, 'WC');
  const kg = uxmssKeygenC(hsf, XMSS_W, 'WC');
  const sg1 = uxmssSignC(1, hsf, XMSS_W, swn, 'WC');
  const sgLast = uxmssSignC(hsf + 1, hsf, XMSS_W, swn, 'WC');
  const sgCold = uxmssSignColdC(hsf, XMSS_W, swn, 'WC');
  const sv1 = uxmssVerifyC(1, hsf, XMSS_W, swn, 'WC');
  const svMax = uxmssVerifyC(hsf, hsf, XMSS_W, swn, 'WC');
  const cb1 = sv1 / sz1, cbMax = svMax / szMax;
  document.getElementById('uxmss-table').innerHTML = [
    row('Max signatures', fmtNum(hsf + 1)),
    row('Size (B)', `${fmtNum(sz1)} → ${fmtNum(szMax)}`),
    row('KeyGen (C)', fmtNum(kg)),
    row('SigGen, cached (C)', `${fmtNum(sg1)} → ${fmtNum(sgLast)}`),
    row('SigGen, cold (C)', fmtNum(sgCold)),
    row('State (B)', fmtNum(uxmssStateBytes(hsf))),
    row('SigVer (C)', `${fmtNum(sv1)} → ${fmtNum(svMax)}`),
    row('ρ (C/B)', `${fmtRho(cb1)} → ${fmtRho(cbMax)}`),
    row('ρ ÷ Schnorr', `${fmtRatio(cb1 / SCHNORR.cb64)} → ${fmtRatio(cbMax / SCHNORR.cb64)}`),
  ].join('');
}

const state = { xmssH: 20 };

async function setup() {
  SCHNORR = await loadSchnorrRef();
  renderStateless();
  renderXmss();
  renderUxmss();

  const slider = document.getElementById('xmss-h');
  const num = document.getElementById('xmss-h-val');
  slider.addEventListener('input', () => {
    state.xmssH = parseInt(slider.value, 10);
    num.value = state.xmssH;
    renderXmss();
  });
  num.addEventListener('input', () => {
    const v = parseInt(num.value, 10);
    if (!Number.isInteger(v)) return;
    state.xmssH = Math.max(2, Math.min(XMSS_H_MAX, v));
    slider.value = state.xmssH;
    renderXmss();
  });
  num.addEventListener('blur', () => { num.value = state.xmssH; });
}

// The tests load this file under node, without a document.
if (typeof document !== 'undefined') setup();
