# SPHINCS-Parameters

This repository holds the model, the parameter searches and the report behind the parameters of SHRINCS. It computes the size, costs and security of SLH-DSA and
the variants W+C, W+C_F+C and W+C_P+FP, searches their parameters, and compares stateful schemes.

- Site: [Explorer](https://blockstreamresearch.github.io/SPHINCS-Parameters/site/);
- Report: [report.pdf](https://blockstreamresearch.github.io/SPHINCS-Parameters/site/report.pdf), from [document/](document/);
- Background: [Searching for SHRINCS parameters](https://blog.blockstream.com/searching-for-shrincs-parameters/).

## Quick start

Without Sage, with Python 3.12 and Node 22 as in CI:

    make check-local

This writes the sweep CSVs and `site/data.json` from `tests/model.py`, a Python port of the model, and runs the tests.

With SageMath 10.4, pandas and seaborn (`sage -pip install pandas seaborn`):

    make generate PYTHON="sage -python"

This runs the steps of CI's generate job, then the tests, in a few minutes:

1. `make sweeps`: `scripts/slhdsa-2to40.sage` evaluates the grid of `parameters.json` with the model in `model/` and writes `analysis/all_size_capped_candidates.csv` and `analysis/all_unbound_candidates.csv`.
2. `make derived`: `analysis/min_mult_search.py` and `analysis/extremes_summary.py` write the derived tables next to them.
3. `make data`: `scripts/export_site_data.sage` writes `site/data.json` from the capped CSV, its own sweeps of the optional w and the variants, and `model/stateful.sage`.
4. `make figures`: the other `analysis/` scripts draw the report's figures into `document/content/images/`.
5. `make test`: `tests/run.py`.

To open the pages, serve the repository (the pages fetch `site/data.json`), for example with `python3 -m http.server`, and go to http://localhost:8000/site/.

## Layout

- `parameters.json`: the search grids, the S_wn table, the UXMSS bounds, the security target and the SLH-DSA-128s baseline.
- `model/`: the model in Sage. `costs.sage` covers SLH-DSA and its variants, `security.sage` FORS and PORS+FP, `stateful.sage` XMSS, XMSS-MT and UXMSS.
- `scripts/`: the parameter sweep and the export of `site/data.json`.
- `analysis/`: the derived tables and the report's figures.
- `site/`: the three pages. `index.html` shows the pinned parameters. `stateless.html` explores the pools of SPX, W+C, FORS+C and PORS+FP and compares a candidate of your own, of any of these schemes. `stateful.html` compares XMSS, XMSS-MT and UXMSS with SLH-DSA-128s. `site/js/model.js` computes the same model in the browser, and `site/js/octopus_pmf.js` ports `third_party/octopus_pmf.py` for PORS+FP candidates.
- `document/`: the report in LaTeX. CI builds it and publishes it with the site; a tag also attaches it, `site/data.json` and the sweep CSVs to a release.
- `tests/`: `model.py`, the tests by area (`python3 tests/run.py [model] [generated] [site] [sage]`), the fixtures and the site snapshot.
- `third_party/octopus_pmf.py`: the size distribution of the Octopus authentication set, for PORS+FP (MIT, from [PORS-FP](https://github.com/MehdiAbri/PORS-FP)).
- `reference/`: the parameter search script of the [SPHINCS+ specification](https://sphincs.org/data/sphincs+-specification.pdf), updated for SageMath 9.

## Changing the model or the pages

- `tests/fixtures.json` pins values of the model. `make fixtures` lists those that differ from the code; after an intended change, `make fixtures WRITE=1` updates them.
- Before pushing a change to `site/`, run `make site-snapshot`, which compares the numbers the pages show with `tests/site_snapshot.json`. It needs `site/data.json` from either make target above and, once, `npm install && npx playwright install chromium`. After an intended change, `make site-snapshot UPDATE=1` records the new numbers.
- Run `make check-local` before pushing.
