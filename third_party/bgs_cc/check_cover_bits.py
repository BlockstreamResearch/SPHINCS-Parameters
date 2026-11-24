#!/usr/bin/env python3
"""Evaluates the coverage bound of every parameter set of q40_fts.csv again and
compares it with the file's cover_bits. The local table of each code is the
exact one of tests/model.py; the sums after it are those of its bgs_cover_bits,
with numpy, and each table serves all the sets of its code.

    python3 third_party/bgs_cc/check_cover_bits.py [jobs [codes]]

Needs numpy. The largest codes take a minute each; `codes` stops after that
many, smallest first. A set with more than 150 bits is only checked to have
them: the tail bound used here stops near 2^-170, below the search's own.
"""
import os
import sys
import time
from math import exp, lgamma, log, log1p, log2
from multiprocessing import Pool

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, 'tests'))
import model as M  # noqa: E402

M_CUT = 24                                     # as the search: the local table is exact up to here
Q_S = 2**M.PARAMETERS['bgs_cc']['q_s_log2']
TARGET = M.PARAMETERS['security_bits']
ROUNDING = 6e-4                                # the file rounds to 0.001
SPARE = 150                                    # bits from which the values are not compared


def binom(n_max, p):
    """rows[n][j] = Pr[Bin(n, p) = j]."""
    rows = np.zeros((n_max + 1, n_max + 1))
    rows[0, 0] = 1.0
    for n in range(1, n_max + 1):
        rows[n, 0] = rows[n - 1, 0] * (1 - p)
        rows[n, 1:] = rows[n - 1, 1:] * (1 - p) + rows[n - 1, :-1] * p
    return rows


def log_choose(q):
    return sum(log(Q_S - i) for i in range(q)) - lgamma(q + 1)


def cover_bits(cfg, f):
    """M.bgs_cover_bits for one set, given the local table f of its code."""
    h, K, L, r, b, u, c, E, delta = (cfg[k] for k in M.BGS_FTS_FIELDS)
    x = h + b if K == 1 else h

    def log_tail(q):
        return min(0.0, log_choose(q + 1) - x * (q + 1) * log(2))

    q_max = 8
    while q_max < 160 and log_tail(q_max) > -170 * log(2):
        q_max += 1
    own, first = binom(q_max, 1 / 2**L), binom(q_max, 1 / 2**u)
    a = own.copy()
    a[:, 0] = 0.0
    top = min(M_CUT, q_max)
    a[1:top + 1, 1:top + 1] *= f[1:top + 1, 1:top + 1]
    cover = np.zeros(q_max + 1)
    for q in range(1, q_max + 1):
        step = np.zeros((q + 1, q + 1))
        for j in range(1, q + 1):
            step[j] = np.convolve(a[j, :j + 1], own[q - j, :q - j + 1])
        vec = np.ones(q + 1)
        vec[0] = 0.0
        for _ in range(r):
            vec = step @ vec
        cover[q] = first[q, :q + 1] @ vec
    if K > 1:
        cover = (binom(q_max, 1 / 2**b) @ cover) ** K
    pmf = np.array([0.0] + [exp(log_choose(q) - x * q * log(2) + (Q_S - q) * log1p(-2.0**-x))
                            for q in range(1, q_max + 1)])
    total = exp(log_tail(q_max)) + pmf @ cover
    words = M.bgs_code_size(c, E)**(r * K)
    accept = (delta / 2**32) * words / 2**((words - 1).bit_length())
    return -log2(accept * total)


def one_code(group):
    (c, E), sets = group
    f = np.array(M._bgs_local(list(c), E, M_CUT))
    return [(cfg, cover_bits(cfg, f)) for cfg in sets]


def main():
    jobs = int(sys.argv[1]) if len(sys.argv) > 1 else os.cpu_count()
    groups = {}
    for cfg in M.bgs_fts_rows():
        groups.setdefault((tuple(cfg['c']), cfg['E']), []).append(cfg)
    # cheapest tables first: a table costs about (codewords) * 2^(L + 1)
    codes = sorted(groups.items(), key=lambda g: M.bgs_code_size(g[0][0], g[0][1]) * 2**len(g[0][0]))
    if len(sys.argv) > 2:
        codes = codes[:int(sys.argv[2])]
    start, done, worst, lowest, bad = time.time(), 0, 0.0, float('inf'), 0
    with Pool(jobs) as pool:
        for n, results in enumerate(pool.imap(one_code, codes), 1):
            for cfg, bits in results:
                done += 1
                lowest = min(lowest, bits)
                if cfg['bits'] < SPARE:
                    worst = max(worst, abs(bits - cfg['bits']))
                if bits < min(cfg['bits'], SPARE) - ROUNDING or (
                        cfg['bits'] < SPARE and abs(bits - cfg['bits']) > ROUNDING):
                    bad += 1
                    print('DIFFERS', {k: cfg[k] for k in M.BGS_FTS_FIELDS}, 'file', cfg['bits'], 'here', bits)
            if n % 50 == 0 or n == len(codes):
                print(f'{n}/{len(codes)} codes, {done} sets, {time.time() - start:.0f} s', flush=True)
    print(f'{done} sets: lowest {lowest:.4f} bits, largest difference to the file {worst:.5f} bits, '
          f'{bad} below the file or off by more than {ROUNDING}')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
