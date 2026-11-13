# SPHINCS-Parameters
Scripts for exploring SPHINCS+ parameter tradeoffs, computing security levels, signature sizes, and signing/verification costs.
- [model/security.sage](model/security.sage) computes the security level for FORS and PORS+FP parameter sets
- [reference/original-sphincs-parameter-search.sage](reference/original-sphincs-parameter-search.sage) script from https://sphincs.org/data/sphincs+-specification.pdf (updated for SageMath 9.0)
- [model/costs.sage](model/costs.sage) computes signature sizes and signing/verification times for SPHINCS+ variants
- [model/stateful.sage](model/stateful.sage) evaluates stateful alternatives (XMSS, XMSS-MT, SHRINCS/UXMSS) against the SLH-DSA-128s baseline
- [parameters.json](parameters.json) holds the search grids and fixed parameters that the Sage scripts, the tests and `site/data.json` share
- [third_party/octopus_pmf.py](third_party/octopus_pmf.py) computes the PMF of the Octopus authentication set size (MIT license, from https://github.com/MehdiAbri/PORS-FP)
- [scripts/slhdsa-2to40.sage](scripts/slhdsa-2to40.sage) sweeps SLH-DSA parameter tuples and filters them by security level and signature size
- [scripts/export_site_data.sage](scripts/export_site_data.sage) exports `site/data.json`, the dataset both site pages load
- [analysis/](analysis/) scripts for the derived tables and the report figures
- [tests/](tests/) regression suite, run `python3 tests/test_regression.py`
- [document/](document/) LaTeX source for the accompanying technical report
- [site/](site/) interactive pages hosted on GitHub Pages: the SHRINCS pinned-parameters main page ([index.html](site/index.html)), stateless parameter search over all report schemes (SPX / W+C / FORS+C / PORS+FP) with worst-case mode, shareable URL state and CSV export ([stateless.html](site/stateless.html)), and stateful scheme comparison ([stateful.html](site/stateful.html)); the cost and security model shared by the three pages lives in [js/model.js](site/js/model.js). The report PDF is not tracked in git: CI compiles [document/](document/) and deploys it as `site/report.pdf` (also attached to releases on tags)

Contributing: run `make check-local` before pushing.