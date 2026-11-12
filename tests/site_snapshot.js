#!/usr/bin/env node
// Checks that the site pages still show the numbers recorded in tests/site_snapshot.json.
//
// Each page is opened in Chromium for a fixed list of share links. The script
// reads the result tables, info lines, popovers and inputs, and compares their numbers
// at the precision shown.
//
//   node tests/site_snapshot.js           compare; exit 1 if a number changed
//   node tests/site_snapshot.js --update  record what the pages show now
'use strict';
const fs = require('fs');
const http = require('http');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'site_snapshot.json');

// Share links to open; '' is the page's default view.
const STATES = {
  'index.html': [''],
  'stateless.html': [
    '',
    '#s=wc',
    '#s=fc',
    '#wc=1',
    '#ow=1&c=45,5,10,13,128',
    '#c=14,7,14,12,16',
    '#x=0.74,2,2,0.8,1&w=5,1,1,2,1',
  ],
  'stateful.html': [
    '',
    '#m=cold',
    '#b=0.5,20,20,2,20,20&w=5,1,1,2,1&sort=size.asc',
    '#b=1,20,20,1.5,20,30&w=5,1,1,2,1',
    '#cand=uxmss-WC-64,xmssmt-WC-64-20-1',
  ],
};

const REGIONS = {
  'index.html': ['#stateless-table', '#xmss-table', '#uxmss-table', '.tuple'],
  'stateless.html': ['#initial-info', '#funnel', '#winner', '#custom-status', '#custom-result'],
  'stateful.html': ['#compare-table', '#sweep-info', '#sweep-table'],
};
const MAX_ROWS = 25;

// Reading a page

function readPage({ regions, maxRows }) {
  const shown = el => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  // Visible text with spaces around elements ("554<span>0.00×</span>" reads as two numbers)
  // and "^" before superscripts (2<sup>40</sup> reads as 2^40).
  const textOf = (root, skipTables, hiddenToo = false) => {
    let s = '';
    (function walk(node) {
      for (const n of node.childNodes) {
        if (n.nodeType === Node.TEXT_NODE) {
          s += n.nodeValue;
        } else if (n.nodeType === Node.ELEMENT_NODE && (hiddenToo || shown(n)) && !n.matches('script, style') &&
                   !(skipTables && n.tagName === 'TABLE')) {
          s += n.tagName === 'SUP' ? ' ^' : ' ';
          walk(n);
          s += ' ';
        }
      }
    })(root);
    return s.replace(/\b\d{4}-\d{2}-\d{2}\b/g, '<date>').replace(/\bcommit [\w.-]+/g, 'commit <id>')
      .replace(/\s+/g, ' ').trim();
  };

  const out = {};
  const found = [];
  for (const sel of regions) {
    const els = Array.from(document.querySelectorAll(sel)).filter(shown);
    if (els.length) found.push(sel);
    els.forEach((el, i) => {
      const name = els.length > 1 ? `${sel}[${i}]` : sel;
      const text = el.tagName === 'TABLE' ? '' : textOf(el, true);
      if (text) out[name] = text;
      const tables = el.tagName === 'TABLE' ? [el] : Array.from(el.querySelectorAll('table'));
      let r = 0;
      for (const tr of tables.flatMap(t => Array.from(t.tBodies).flatMap(b => Array.from(b.rows)))) {
        if (r === maxRows) break;
        if (!shown(tr)) continue;
        const cells = Array.from(tr.cells).filter(shown).map(c => textOf(c, false));
        if (cells.some(c => /\d/.test(c))) out[`${name} row ${r++}`] = cells;
      }
    });
  }
  // Popovers stay hidden until opened.
  for (const el of document.querySelectorAll('[popover][id]')) {
    const text = textOf(el, false, true);
    if (/\d/.test(text)) out[`popover #${el.id}`] = text;
  }
  // Inputs carry the state a share link restores, so hidden ones count too.
  for (const el of document.querySelectorAll('input[id], select[id]')) {
    if (el.type === 'range') continue;  // mirrors the number box next to it
    out[`input #${el.id}`] = el.type === 'checkbox' ? (el.checked ? 'on' : 'off') : el.value;
  }
  return { values: out, found };
}

// Comparing numbers

const SUPERSCRIPT = Object.fromEntries(Array.from('⁰¹²³⁴⁵⁶⁷⁸⁹⁻', (c, i) => [c, '0123456789-'[i]]));
const SCALE = { '': 1, K: 1e3, M: 1e6, G: 1e9, T: 1e12 };
const NUMBER = /(?:^|[^\p{L}\d.])(-?)(\d{1,3}(?:[,\u00a0\u202f]\d{3})+(?![\d,])|\d+)(\.\d+)?(?:e([+-]?\d+))?([KMGT]?)(?![\p{L}\d])/gu;

// The numbers in a displayed string, each with the size of its last shown digit.
function numbers(text) {
  const t = text
    .replace(/[⁰¹²³⁴⁵⁶⁷⁸⁹⁻]+/g, s => '^' + Array.from(s, c => SUPERSCRIPT[c]).join(''))
    .replace(/\u2212/g, '-');
  return Array.from(t.matchAll(NUMBER), ([, sign, int, frac = '', exp, suffix]) => {
    const scale = SCALE[suffix] * 10 ** Number(exp || 0);
    return {
      text: sign + int + frac + (exp ? 'e' + exp : '') + suffix,
      value: (sign ? -1 : 1) * Number(int.replace(/\D/g, '') + frac) * scale,
      step: (frac ? 10 ** (1 - frac.length) : 1) * scale,
    };
  });
}

// Two displays agree if the ranges they round from overlap.
function sameNumbers(a, b) {
  return a.length === b.length && a.every((x, i) => {
    const y = b[i];
    return Math.abs(x.value - y.value) < (x.step + y.step) / 2 - 1e-9 * Math.max(x.step, y.step);
  });
}

// Long entries are shown as the numbers that changed: "0.2791 → 0.2793".
function describe(was, now) {
  const full = `was ${JSON.stringify(was)}\n         now ${JSON.stringify(now)}`;
  const x = numbers([].concat(was).join(' ')), y = numbers([].concat(now).join(' '));
  if (full.length < 300 || x.length !== y.length) return full;
  return x.flatMap((n, i) => sameNumbers([n], [y[i]]) ? [] : [`${n.text} → ${y[i].text}`]).join(', ');
}

// 'same', 'reworded' (same numbers, other text) or 'changed'.
function compare(key, was, now) {
  if (JSON.stringify(was) === JSON.stringify(now)) return 'same';
  const a = [].concat(was), b = [].concat(now);
  if (a.length !== b.length) return 'changed';
  let result = 'reworded';
  a.forEach((cell, i) => {
    const x = numbers(cell), y = numbers(b[i]);
    const textOnly = !x.length && !y.length;
    if (textOnly ? key.startsWith('input ') && cell !== b[i] : !sameNumbers(x, y)) result = 'changed';
  });
  return result;
}

// Running the pages

function serve() {
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json',
                  '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png' };
  const server = http.createServer((req, res) => {
    const file = path.join(ROOT, decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
    if (!file.startsWith(ROOT + path.sep)) return res.writeHead(403).end();
    fs.readFile(file, (err, body) => {
      if (err) return res.writeHead(404).end();
      res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' }).end(body);
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function openPage(browser, origin, url) {
  // Fixed locale: the pages format numbers with toLocaleString().
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 }, locale: 'en-US', timezoneId: 'UTC',
  });
  // Offline: other hosts (the live Schnorr reference) fail and the pages use their built-in values.
  await context.route('**/*', route =>
    route.request().url().startsWith(origin) ? route.continue() : route.abort());
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(origin + url, { waitUntil: 'networkidle' });
  return { context, page, errors };
}

// Read until two reads 250 ms apart agree; the pages render in animation frames and timers.
async function readSettled(page, regions) {
  let last = '';
  for (let i = 0; i < 60; i++) {
    const now = JSON.stringify(await page.evaluate(readPage, { regions, maxRows: MAX_ROWS }));
    if (now === last) return JSON.parse(now);
    last = now;
    await page.waitForTimeout(250);
  }
  throw new Error(`${page.url()} kept changing for 15 s`);
}

// One line per entry keeps diffs of the snapshot readable.
function format(snapshot) {
  const states = Object.entries(snapshot).map(([state, values]) =>
    ` ${JSON.stringify(state)}: {\n` +
    Object.entries(values).map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(',\n') +
    '\n }');
  return '{\n' + states.join(',\n') + '\n}\n';
}

async function main() {
  const update = process.argv.slice(2).includes('--update');

  let chromium;
  try {
    ({ chromium } = require('playwright'));
  } catch {
    console.error('Playwright is missing. Install it once with: npm install && npx playwright install chromium');
    process.exit(2);
  }
  if (!fs.existsSync(path.join(ROOT, 'site', 'data.json'))) {
    console.error('site/data.json is missing. Run `make check-local` (or `make generate`) first.');
    process.exit(2);
  }

  const server = await serve();
  const origin = `http://127.0.0.1:${server.address().port}/site/`;
  const browser = await chromium.launch();
  const current = {};
  const problems = [];
  try {
    for (const [file, hashes] of Object.entries(STATES)) {
      const found = new Set();
      for (const hash of hashes) {
        const state = file + hash;
        const { context, page, errors } = await openPage(browser, origin, state);
        const read = await readSettled(page, REGIONS[file]);
        current[state] = read.values;
        read.found.forEach(sel => found.add(sel));
        for (const e of errors) problems.push(`${state}: page error: ${e}`);
        await context.close();
      }
      for (const sel of REGIONS[file]) {
        if (!found.has(sel)) problems.push(`${file}: no share link shows anything at ${sel}`);
      }
    }
  } finally {
    await browser.close();
    server.close();
  }

  for (const p of problems) console.log(p);
  const count = Object.values(current).reduce((n, v) => n + Object.keys(v).length, 0);
  if (update) {
    if (problems.length) {
      console.log('Not recorded: fix the problems above first.');
      process.exit(1);
    }
    fs.writeFileSync(SNAPSHOT, format(current));
    console.log(`Recorded ${count} entries from ${Object.keys(current).length} page states in tests/site_snapshot.json.`);
    return;
  }

  const recorded = fs.existsSync(SNAPSHOT) ? JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8')) : {};
  let changed = 0, reworded = 0;
  for (const state of new Set([...Object.keys(recorded), ...Object.keys(current)])) {
    const was = recorded[state] || {}, now = current[state] || {};
    for (const key of new Set([...Object.keys(was), ...Object.keys(now)])) {
      if (!(key in now)) {
        changed++;
        console.log(`missing  ${state}  ${key}\n         was ${JSON.stringify(was[key])}`);
      } else if (!(key in was)) {
        console.log(`new      ${state}  ${key}\n         now ${JSON.stringify(now[key])}`);
      } else {
        const result = compare(key, was[key], now[key]);
        if (result === 'reworded') reworded++;
        if (result !== 'changed') continue;
        changed++;
        console.log(`changed  ${state}  ${key}\n         ${describe(was[key], now[key])}`);
      }
    }
  }
  if (reworded) console.log(`${reworded} entries show the same numbers in other words.`);
  if (changed || problems.length) {
    console.log(`${changed} entries changed. If that is intended: make site-snapshot UPDATE=1`);
    process.exit(1);
  }
  console.log(`Site snapshot matches: ${count} entries from ${Object.keys(current).length} page states.`);
}

main().catch(e => {
  console.error(e.message);
  process.exit(2);
});
