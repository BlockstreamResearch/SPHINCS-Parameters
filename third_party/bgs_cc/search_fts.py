#!/usr/bin/env python3
"""Searches the BGS-CC parameter sets for the explorer and writes q40_fts.csv.

    python3 third_party/bgs_cc/search_fts.py <bgs-cc checkout> [--jobs N]

It needs numpy and a checkout of bgs-cc (https://github.com/nekomelisa/bgs-cc), whose
bench/params.py and bench/search.py give the coverage bound, the code family and the solved
threshold. The region is that of the bgs-cc search: codes c = (first, middle x (L - 1), last)
with capacities 0 to 4 and L up to 8, then the neighbours of the codes that matter; K up to 8,
r up to 64, u up to 12, b up to 16, h from 20 to 72; delta the largest threshold, of three set
bits, that keeps the bound at 2^-128.002.

What differs from bgs-cc's own frontier is what is kept:

1. Per code, every (K, r, u, b, h) with such a delta, below the size bound under the smallest
   hypertree and within the signing cap. Of the sets with the same height and size, those that
   another matches or beats in both signing and verification are dropped: under any hypertree
   that other candidate is at least as good in every metric of the explorer. Signing and
   verification count as equal within 1%.
2. Over all codes, the candidates the explorer could show: each set under each hypertree of
   its height (tests/model.py, bgs_hypertrees). Within a scheme and a w, a candidate stays if
   no other beats it in size, KeyGen, SigGen and rho, with the average or the worst-case
   verification; SigGen and rho count as equal within --grain. A smaller size with a smaller
   rho is also a smaller SigVer, so SigVer needs no pass of its own.

q40_fts.csv holds the sets of the candidates of step 2, each with its hypertrees as d/w per
scheme; q40_fts.json says what was searched. The sets of step 1 stay beside them in
q40_fts_store.npz (not in git), with the codes already done, so a run that stops can be
started again, and step 2 can be repeated with --frontier-only. The tables of the codes are
cached in <checkout>/bench/results/q40_cache.sqlite, as by bgs-cc. About 13,000 codes take
two to three hours on eight cores.
"""
import argparse
import csv
import json
import math
import multiprocessing
import os
import sqlite3
import subprocess
import sys
import time

for _name in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'VECLIB_MAXIMUM_THREADS'):
    os.environ.setdefault(_name, '1')    # one thread per worker: the workers are the parallelism

import numpy as np  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, 'tests'))
import model as M  # noqa: E402

Q_S_LOG2 = M.PARAMETERS['bgs_cc']['q_s_log2']
LAMBDA = M.PARAMETERS['security_bits']
MAX_SIZE = M.PARAMETERS['stateless']['grid']['max_size']
GRAIN = 0.01    # step 1: signing and verification closer than this count as equal
# R, the authentication path and two layers of 16 chains: the smallest hypertree of the grid
MIN_HYPERTREE = lambda h: M.N * (1 + h + 2 * 16)   # noqa: E731

P = SR = None   # bgs-cc's bench/params.py and bench/search.py


def load_bgs_cc(path):
    global P, SR
    bench = os.path.join(path, 'bench')
    if not os.path.exists(os.path.join(bench, 'search.py')):
        raise SystemExit(f'{path} is not a checkout of bgs-cc: bench/search.py is missing')
    sys.path.insert(0, bench)
    import params
    import search
    P, SR = params, search


def buckets(x, grain=GRAIN):
    """Steps of `grain` on a log scale, as bgs-cc compares signing and verification."""
    return np.floor(np.log(x) / math.log1p(grain)).astype(np.int64)


def staircase(h, size, sign, verify):
    """Indices of the sets to keep: within each (h, size), those that no other matches or
    beats in both the signing and the verification bucket."""
    if not len(h):
        return np.zeros(0, np.int64)
    sb, vb = buckets(sign), buckets(verify)
    group = h.astype(np.int64) * 2**20 + size.astype(np.int64)
    order = np.lexsort((verify, sign, vb, sb, group))
    g, s = group[order], sb[order]
    first = np.ones(len(order), bool)            # the lowest verification of each signing bucket
    first[1:] = (g[1:] != g[:-1]) | (s[1:] != s[:-1])
    order, g = order[first], g[first]
    v = vb[order]
    gid = np.cumsum(np.r_[True, g[1:] != g[:-1]])
    # a running minimum that starts again in each group: later groups sit lower
    adj = v - gid * (int(v.max() - v.min()) + 2)
    run = np.minimum.accumulate(adj)
    return order[np.r_[True, adj[1:] < run[:-1]]]


def code_sets(task):
    """Step 1 for one code. Returns (c, E, the table if new, ints, floats, counts): the ints
    are (K, r, u, b, h, delta), the floats (size, signing, verification, cover bits), the
    counts the (K, r, u, b, h) looked at and those with a delta and within the bounds."""
    c, E, blob, (sign_cap, kmax) = task
    n, m_cut = M.N, P.M_CUT
    L = len(c) - 1
    f = np.frombuffer(blob).reshape(m_cut + 1, m_cut + 1) if blob else SR.f_table(c, E, m_cut)
    C = SR.curves(f, L, m_cut)
    W, tail = SR.outer(Q_S_LOG2)
    N, t = P.code_size(list(c), E), 2**L
    J = t * (c[L] + 3) + sum(2**(d + 1) * c[d] for d in range(L)) - 1
    per_layer = E + sum(c[:L]) + L + 1           # verification calls of a layer, eq. (19)
    rr, uu = np.arange(SR.R_MAX + 1)[:, None], np.arange(SR.U_MAX + 1)[None, :]
    G0 = (2.0**uu + (rr - 1) * t) * J + 2.0**uu  # one bucket of one coordinate, eq. (15), plus 1
    out_i, out_f, counts = [], [], [0, 0]
    heights = np.arange(SR.X_LO, 73)
    cells = (SR.R_MAX - 1) * (SR.U_MAX + 1) * len(heights)       # (r, u, h) per K and b

    def emit(K, r, u, b, h, delta, tau, raw, ell_n, eta):
        ok = (h >= heights[0]) & (h <= heights[-1])
        r, u, b, h, delta, tau, raw = (a[ok] for a in (r, u, b, h, delta, tau, raw))
        size = 4 + n * K * (b + u + r * (L + 1))                                   # eq. (17)
        blocks = -(-(32 + h + K * (b + u + r * L) + ell_n[r]) // (8 * n))
        sign = K * 2.0**b * G0[r, u] - 1 + 1 / tau + (blocks - 1) / eta[r]         # eq. (18)
        ok = (size + MIN_HYPERTREE(h) < MAX_SIZE) & (sign <= sign_cap)
        counts[1] += int(ok.sum())
        if not ok.any():
            return
        r, u, b, h, delta, tau, raw, size, blocks, sign = (
            a[ok] for a in (r, u, b, h, delta, tau, raw, size, blocks, sign))
        verify = blocks + K * (b + u + r * per_layer) + K - 1                      # eq. (19)
        keep = staircase(h, size, sign, verify)
        out_i.append(np.stack([np.full(len(r), K), r, u, b, h, delta], axis=1)[keep])
        out_f.append(np.stack([size, sign, verify, -np.log2(tau * raw)], axis=1)[keep])

    def code_bits(K):
        """Per r: ceil(log2 N^(r K)), and eta, the share of the codeword choices in 2^that."""
        powers = [N ** (r * K) for r in range(SR.R_MAX + 1)]
        bits = [(x - 1).bit_length() for x in powers]
        return np.array(bits), np.array([x / 2**e for x, e in zip(powers, bits)])

    bs = np.arange(SR.B_MAX + 1)
    with np.errstate(divide='ignore', over='ignore', invalid='ignore'):
        # K = 1: the bound sees h and b only as h + b
        ell_n, eta = code_bits(1)
        raw = C @ W.T + tail
        delta, tau = SR.solve_delta(raw, eta[:, None, None], LAMBDA, Q_S_LOG2, P.RELIABILITY_BITS)
        delta[:2] = 0                            # r >= 2
        r, u, x = np.nonzero(delta)
        for b in bs:
            counts[0] += cells
            emit(1, r, u, np.full(len(r), b), x - b, delta[r, u, x], tau[r, u, x], raw[r, u, x],
                 ell_n, eta)
        # K > 1: the buckets thin each coordinate, eq. (27); the K coordinates share the address
        for K in range(2, kmax + 1):
            ell_n, eta = code_bits(K)
            for b in bs:
                if K * 2.0**b * G0[2, 0] > sign_cap:
                    break
                counts[0] += cells
                raw = (C @ SR.pmf_matrix(2**int(b)).T)**K @ W[heights].T + tail[heights]
                delta, tau = SR.solve_delta(raw, eta[:, None, None], LAMBDA, Q_S_LOG2,
                                            P.RELIABILITY_BITS)
                delta[:2] = 0
                r, u, hi = np.nonzero(delta)
                emit(K, r, u, np.full(len(r), b), heights[hi], delta[r, u, hi], tau[r, u, hi],
                     raw[r, u, hi], ell_n, eta)

    new = None if blob else f.tobytes()
    if not out_i:
        return c, E, new, np.zeros((0, 6), np.int64), np.zeros((0, 4)), counts
    I, F = np.concatenate(out_i), np.concatenate(out_f)
    keep = staircase(I[:, 4], F[:, 0], F[:, 1], F[:, 2])       # across K
    return c, E, new, I[keep], F[keep], counts


class Store:
    """The sets of step 1, with the codes they belong to, the codes already done, the counts
    of what was looked at, and the options: those the sets depend on, which a later run has
    to repeat, and those of the code family, which it may widen."""

    def __init__(self, path, options):
        self.path, self.options, self.family = path, options, {}
        self.codes, self.done, self.counts = [], set(), [0, 0]
        self.I, self.F, self.owner = np.zeros((0, 6), np.int64), np.zeros((0, 4)), np.zeros(0, np.int64)
        self.new, self.pending = [], 0
        if os.path.exists(path):
            with np.load(path) as z:
                saved = json.loads(str(z['options']))
                if options is None:
                    self.options = saved
                elif saved != options:
                    raise SystemExit(f'{path} was made with {saved}, this run asks for {options}.\n'
                                     'Use the same options, or another --store.')
                self.I, self.F, self.owner = z['I'], z['F'], z['owner']
                self.codes = [(tuple(c), E) for c, E in json.loads(str(z['codes']))]
                self.done = {(tuple(c), E) for c, E in json.loads(str(z['done']))}
                self.counts = json.loads(str(z['counts']))
                self.family = json.loads(str(z['family']))
        elif options is None:
            raise SystemExit(f'{path} does not exist: run the search first')

    def add(self, c, E, I, F, counts):
        self.done.add((c, E))
        self.counts = [a + b for a, b in zip(self.counts, counts)]
        if len(I):
            self.codes.append((c, E))
            self.new.append((len(self.codes) - 1, I, F))
            self.pending += len(I)
            if self.pending > 2_000_000:         # bounds the memory
                self.prune()

    def prune(self):
        if self.new:
            self.I = np.concatenate([self.I] + [I for _, I, _ in self.new])
            self.F = np.concatenate([self.F] + [F for _, _, F in self.new])
            self.owner = np.concatenate([self.owner] + [np.full(len(I), k) for k, I, _ in self.new])
            self.new, self.pending = [], 0
            keep = staircase(self.I[:, 4], self.F[:, 0], self.F[:, 1], self.F[:, 2])
            self.I, self.F, self.owner = self.I[keep], self.F[keep], self.owner[keep]

    def save(self):
        self.prune()
        tmp = self.path + '.tmp.npz'
        np.savez_compressed(tmp, I=self.I, F=self.F, owner=self.owner,
                            codes=json.dumps(self.codes), done=json.dumps(sorted(self.done)),
                            counts=json.dumps(self.counts), options=json.dumps(self.options),
                            family=json.dumps(self.family))
        os.replace(tmp, self.path)


def frontier(store, grain):
    """Step 2. Returns the indices of the sets that some hypertree of the grid turns into a
    candidate nothing beats, and those candidates per scheme as (set, d, w). Candidates are
    compared within a scheme and a w, so each w keeps all of its own."""
    h, size, sign, verify = store.I[:, 4], store.F[:, 0], store.F[:, 1], store.F[:, 2]
    rows_at = {int(x): np.flatnonzero(h == x) for x in np.unique(h)}
    keep, candidates = np.zeros(len(h), bool), {}
    step1, SR.GRAIN = SR.GRAIN, grain            # SR.pareto compares in steps of SR.GRAIN
    try:
        for scheme in M.BGS_SCHEMES:
            found = set()
            for w in M.bgs_w(scheme):
                trees = [(t, M.hypertree_metrics(*t)) for t in M.bgs_hypertrees(scheme, rows_at)
                         if t[2] == w]
                # with the average verification, then with the worst case where it differs
                worst = any(m['sv'] != m['sv_worst'] for _, m in trees)
                for sv in ('sv', 'sv_worst') if worst else ('sv',):
                    parts = []
                    for (hh, d, _, _), m in trees:
                        rows = rows_at[hh]
                        total = size[rows] + m['size']
                        rows, total = rows[total < MAX_SIZE], total[total < MAX_SIZE]
                        if not len(rows):
                            continue
                        sg, rho = sign[rows] + m['sg'], (verify[rows] + m[sv]) / total
                        # of a (SigGen, rho) cell, SR.pareto takes the smallest only
                        cell = buckets(sg, grain) * 2**20 + buckets(rho, grain) + 2**19
                        order = np.lexsort((total, cell))
                        pick = order[np.r_[True, cell[order][1:] != cell[order][:-1]]]
                        parts.append((rows[pick], np.full(len(pick), d), total[pick], sg[pick],
                                      np.full(len(pick), float(m['kg'])), rho[pick]))
                    if not parts:
                        continue
                    rows, d, total, sg, kg, rho = (np.concatenate(x) for x in zip(*parts))
                    best = SR.pareto(total, sg, rho, kg)
                    keep[rows[best]] = True
                    found.update((int(row), int(dd), w) for row, dd in zip(rows[best], d[best]))
            candidates[scheme] = sorted(found)
    finally:
        SR.GRAIN = step1
    return np.flatnonzero(keep), candidates


def write_csv(store, rows, candidates, path):
    """The sets `rows` of the store, sorted, each with its hypertrees per scheme. Checks
    every set against the explorer's model on the way."""
    trees = {scheme: {} for scheme in candidates}
    for scheme, found in candidates.items():
        for row, d, w in found:
            trees[scheme].setdefault(row, []).append((w, d))
    out = []
    for i in rows:
        K, r, u, b, h, delta = (int(x) for x in store.I[i])
        c, E = store.codes[store.owner[i]]
        size, sign, verify, bits = (float(x) for x in store.F[i])
        m = M.bgs_fts_metrics(h, K, len(c) - 1, r, b, u, list(c), E, delta)
        assert m['size'] == size and m['sv'] == verify and abs(m['sg'] - sign) <= 1, (store.I[i], c, E)
        out.append((h, K, len(c) - 1, r, b, u, c, E, delta, round(bits, 3))
                   + tuple(' '.join(f'{d}/{w}' for w, d in sorted(trees[scheme].get(i, ())))
                           for scheme in candidates))
    with open(path, 'w', newline='') as fh:
        writer = csv.writer(fh, lineterminator='\n')
        writer.writerow(['h', 'K', 'L', 'r', 'b', 'u', 'c', 'E', 'delta', 'cover_bits']
                        + list(candidates))
        for h, K, L, r, b, u, c, E, delta, bits, *per_scheme in sorted(out):
            writer.writerow([h, K, L, r, b, u, ' '.join(map(str, c)), E, delta, bits] + per_scheme)


def checkout_commit(path):
    try:
        return subprocess.run(['git', '-C', path, 'rev-parse', 'HEAD'], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('bgs_cc', help='a checkout of bgs-cc')
    ap.add_argument('--jobs', type=int, default=os.cpu_count())
    ap.add_argument('--sign-cap', type=float, default=27,
                    help='log2 of the compressions a few-time signature may take to sign')
    ap.add_argument('--lmax', type=int, default=8)
    ap.add_argument('--cmax', type=int, default=4)
    ap.add_argument('--kmax', type=int, default=8)
    ap.add_argument('--refine', type=int, default=1,
                    help='rounds of neighbours of the codes that matter')
    ap.add_argument('--max-code-seconds', type=float, default=60,
                    help='skip codes whose table takes longer')
    ap.add_argument('--grain', type=float, default=GRAIN,
                    help='step 2: SigGen and rho closer than this count as equal')
    ap.add_argument('--codes', type=int,
                    help='stop each round after this many codes, cheapest first (a trial run)')
    ap.add_argument('--frontier-only', action='store_true', help='repeat step 2 from the stored sets')
    ap.add_argument('--store', default=os.path.join(HERE, f'q{Q_S_LOG2}_fts_store.npz'),
                    help='the sets of step 1')
    ap.add_argument('--out', default=os.path.join(HERE, f'q{Q_S_LOG2}_fts.csv'))
    args = ap.parse_args()

    load_bgs_cc(args.bgs_cc)
    results = os.path.join(args.bgs_cc, 'bench', 'results')
    os.makedirs(results, exist_ok=True)
    region = {'sign_cap': args.sign_cap, 'kmax': args.kmax, 'max_size': MAX_SIZE,
              'q_s_log2': Q_S_LOG2, 'security_bits': LAMBDA}
    store = Store(args.store, None if args.frontier_only else region)
    start, skipped, rounds = time.time(), 0, 0

    def step2(label):
        if not len(store.I):
            raise SystemExit('no set is within the bounds')
        rows, candidates = frontier(store, args.grain)
        print(f'  {label}: {len(rows):,} sets in the candidates nothing beats '
              f'({", ".join(f"{s} {len(x):,}" for s, x in candidates.items())}), '
              f'{time.time() - start:.0f} s', flush=True)
        return rows, candidates

    if args.frontier_only:
        rows, candidates = step2('stored sets')
    else:
        db = sqlite3.connect(os.path.join(results, f'q{Q_S_LOG2}_cache.sqlite'))
        db.execute('CREATE TABLE IF NOT EXISTS f (key TEXT PRIMARY KEY, data BLOB)')
        cached = dict(db.execute('SELECT key, data FROM f'))

        def cache_key(c, E):
            return f"{','.join(map(str, c))}|{E}|{P.M_CUT}"

        def tasks(codes):                        # runs in a thread of the pool
            for c, E in codes:
                yield c, E, cached.get(cache_key(c, E)), (2.0**args.sign_cap, args.kmax)

        store.family = {'lmax': args.lmax, 'cmax': args.cmax, 'refine': args.refine,
                        'max_code_seconds': args.max_code_seconds}
        todo = set(SR.family(args.lmax, args.cmax))
        # spawn on every system: the workers load bgs-cc themselves
        with multiprocessing.get_context('spawn').Pool(args.jobs, load_bgs_cc, (args.bgs_cc,)) as pool:
            for rnd in range(args.refine + 1):
                costs = {code: SR.usable(*code, args.max_code_seconds) for code in todo}
                skipped += sum(1 for code, cost in costs.items()
                               if cost is None and P.code_size(list(code[0]), code[1]) > 1)
                codes = sorted((code for code, cost in costs.items() if cost is not None),
                               key=lambda code: (costs[code], code))
                if args.codes:
                    codes = codes[:args.codes]
                codes = [code for code in codes if code not in store.done]
                if rnd and not codes:
                    break
                if codes:
                    new = [code for code in codes if cache_key(*code) not in cached]
                    print(f'round {rnd}: {len(codes):,} codes, {len(new):,} tables to compute (about '
                          f'{sum(costs[code] for code in new) / 3600:.1f} core hours on an Apple M2)',
                          flush=True)
                    saved = time.time()
                    for n, (c, E, blob, I, F, counts) in enumerate(
                            pool.imap_unordered(code_sets, tasks(codes)), 1):
                        if blob:
                            db.execute('INSERT OR REPLACE INTO f VALUES (?, ?)', (cache_key(c, E), blob))
                            cached[cache_key(c, E)] = blob
                        store.add(c, E, I, F, counts)
                        if n == len(codes) or (n % 50 == 0 and time.time() - saved > 300):
                            db.commit()
                            store.save()
                            saved = time.time()
                            print(f'  {n:,}/{len(codes):,} codes, {len(store.I):,} sets kept, '
                                  f'{time.time() - start:.0f} s', flush=True)
                store.save()
                rounds = rnd
                rows, candidates = step2(f'after round {rnd}')
                todo = {nb for k in set(store.owner[rows].tolist())
                        for nb in SR.neighbours(*store.codes[k])}

    write_csv(store, rows, candidates, args.out)
    summary = {
        'codes': len(store.done),
        'parameter_sets': store.counts[0],       # (code, K, r, u, b, h) looked at
        'within_bounds': store.counts[1],        # of them: a delta exists, size and signing fit
        'stored': len(store.I),                  # left by step 1
        'sets': len(rows),
        'candidates': {scheme: len(found) for scheme, found in candidates.items()},
        'region': dict(store.options, **store.family, r_max=SR.R_MAX, u_max=SR.U_MAX,
                       b_max=SR.B_MAX, h=[SR.X_LO, 72], m_cut=P.M_CUT),
        'grain': [GRAIN, args.grain],
        'margin_bits': SR.MARGIN,
        'bgs_cc_commit': checkout_commit(args.bgs_cc),
    }
    with open(os.path.splitext(args.out)[0] + '.json', 'w') as fh:
        json.dump(summary, fh, indent=1)
        fh.write('\n')
    if not args.frontier_only:
        print(f'{len(store.done):,} codes searched in {rounds + 1} rounds, {skipped} skipped as '
              f'too slow, {len(store.I):,} sets stored in {store.path}')
    print(f'wrote {len(rows):,} sets to {args.out}')


if __name__ == '__main__':
    main()
