# BGS-CC candidates

BGS-CC is the few-time signature of Ren and Yu, "Shorter Hash-Based Signatures via Guarded Sharing
in a DAG Model" ([ePrint 2026/2502](https://eprint.iacr.org/2026/2502)). `q40_fts.csv` holds its
parameter sets for 2^40 signatures at 128 bits with n = 16, and for each set the hypertrees under
which the explorer shows it (`docs/model.md`, BGS-CC).

| Column | Meaning |
|---|---|
| h | hypertree height: the instance is one of 2^h |
| K | coordinates |
| L | height of a tree, t = 2^L leaves |
| r | layers |
| b | B = 2^b buckets per coordinate |
| u | O = 2^u trees in the first layer |
| c | chain capacities c_0 to c_L, separated by spaces |
| E | the sum of the chain depths |
| delta | threshold of the 32-bit rejection value |
| cover_bits | -log2 of the coverage bound at 2^40 signatures, as the search computed it |
| BGS, W+C_BGS | the hypertrees of the set's candidates in that scheme, as d/w, separated by spaces |

`q40_fts.json` says what was searched: the codes, the parameter sets looked at, the sets within
the bounds, the candidates kept and the region.

## Source

**Interim.** The sets are those of [bgs-cc](https://github.com/nekomelisa/bgs-cc), commit 1fa4397:
the distinct (h, K, L, r, b, u, c, E, delta) of its `bench/results/q40_frontier.csv`, the frontier
that `bench/frontier.py` found under its own hypertrees (WOTS+ with w = 4, 8 or 16, signing within
2^25 hash calls). Step 2 of `search_fts.py` chose their hypertrees. A full run of `search_fts.py`
replaces both files.

`search_fts.py <bgs-cc checkout>` searches the same region with the coverage bound of bgs-cc
(`bench/params.py`, `bench/search.py`) and keeps what the explorer needs:

1. Per code, every (K, r, u, b, h) with a usable delta, below the size bound and within the
   signing cap of 2^27 compressions. Of the sets with the same height and size, it drops those
   that another matches or beats in both signing and verification, within 1%.
2. Each set under each hypertree of its height. For each scheme and each w, a candidate stays if
   no other beats it in size, KeyGen, SigGen and rho, with the average or the worst-case
   verification, where SigGen and rho within 1% count as equal.

So each w has its own frontier, and the two steps together can be off by about 2% in SigGen and
rho. The sets of step 1 stay in `q40_fts_store.npz` (not in git), and `--frontier-only` repeats
step 2 from them.

## What the numbers rest on

- The region: codes c = (first, middle x (L - 1), last) with capacities up to 4 and L up to 8,
  then the neighbours of the codes on the frontier; K up to 8, r up to 64, u up to 12, b up to 16,
  h from 20 to 72. Sets outside it were not considered.
- `cover_bits` is a float evaluation with a margin of 0.002 bits: delta is the largest value, of at
  most three set bits, that keeps the bound at 2^-128.002. The rigorous checker of bgs-cc
  (`bench/params.py`, directed rounding) accepts the sets it was run on, a sample.
- `tests/model.py` evaluates the bound again, written from the paper: it reproduces the 128-bit
  rows of the paper's Table 6, `check_cover_bits.py` runs it over all sets (numpy), and
  `tests/test_model.py` over a sample.
- The bound is the coverage model of the paper, a preprint.
