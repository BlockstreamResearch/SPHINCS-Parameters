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

`search_fts.py <bgs-cc checkout>` made both files on 24 November 2026. It takes the coverage bound,
the code family and the solved threshold from [bgs-cc](https://github.com/nekomelisa/bgs-cc)
(`bench/params.py`, `bench/search.py`, commit 1fa4397) and keeps what the explorer needs:

1. Per code, every (K, r, u, b, h) with a usable delta, below the size bound and within the
   signing cap of 2^27 compressions. Of the sets with the same height and size, it drops those
   that another matches or beats in both signing and verification, within 1%.
2. Each set under each hypertree of its height. For each scheme and each w, a candidate stays if
   no other beats it in size, KeyGen, SigGen and rho, with the average or the worst-case
   verification, where SigGen and rho within 1% count as equal.

So each w has its own frontier, and the two steps together can be off by about 2% in SigGen and
rho. The run went through 14,086 codes and 53.7 billion (code, K, r, u, b, h); 7.4 billion of them
have a usable delta within the bounds. Step 1 left 121,410 sets, step 2 the 19,400 of the file,
with 91,468 candidates for BGS and 63,923 for W+C_BGS.

The sets of step 1 stay in `q40_fts_store.npz` (not in git). `--frontier-only` repeats step 2
from them, and a further run of the script searches one more round of codes.

`--budget Q` searches for 2^Q signatures, a stop of the explorer's budget slider, and writes
`q<Q>_fts.csv` and `.json`. The range of h moves with the budget, and the tables of the codes,
which do not depend on it, are reused. The explorer shows BGS-CC at a budget once its file is here.

## What the numbers rest on

- The region: K up to 8, r up to 64, u up to 12, b up to 16, h from 20 to 72. Sets outside it were
  not considered, and some sets of the file sit on its edges.
- **The codes come from a local search that has not converged.** The run covers the family
  c = (first, middle x (L - 1), last) with capacities up to 4 and L up to 8, and one round of
  neighbours: the codes one step in one capacity away from a code on the frontier. 785 of the 931
  codes of the file come from that round. 7,201 neighbours of the file's codes are not searched
  yet (`not_searched` in the JSON), and 129 codes were left out because their table is estimated
  to take over a minute (`too_slow`). In a trial with 603 of the unsearched ones, those around
  the smallest candidates, a third of the candidates then came from the new codes: the smallest
  W+C_BGS candidate within the report's bounds went from 4,160 B to 4,112 B, the smallest BGS
  one stayed at 4,644 B.
- `cover_bits` is a float evaluation with a margin of 0.002 bits: delta is the largest value, of at
  most three set bits, that keeps the bound at 2^-128.002. The rigorous checker of bgs-cc
  (`bench/params.py`, directed rounding) was run on 40 sets: six behind the smallest candidates,
  the eight lowest in cover bits among the small codes, six with K > 1 and 20 spread over the
  file. It accepts all of them, within 0.0005 bits of the file.
- `tests/model.py` evaluates the bound again, written from the paper: it reproduces the 128-bit
  rows of the paper's Table 6, and `tests/test_model.py` repeats it for a sample of the file.
  `check_cover_bits.py` runs it over all sets (numpy, about 50 minutes on two cores). On
  24 November 2026 every one of the 19,400 sets was within 0.0005 bits of its `cover_bits`, the
  rounding of the file, and the lowest at 128.0020 bits.
- The bound is the coverage model of the paper, a preprint.
