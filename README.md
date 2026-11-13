# SPHINCS-Parameters
Scripts for exploring SPHINCS+ parameter tradeoffs, computing security levels, signature sizes, and signing/verification costs.
- [security.sage](security.sage) computes the security level for FORS and PORS+FP parameter sets
- [original-sphincs-parameter-search.sage](original-sphincs-parameter-search.sage) script from https://sphincs.org/data/sphincs+-specification.pdf (updated for SageMath 9.0)
- [costs.sage](costs.sage) computes signature sizes and signing/verification times for SPHINCS+ variants
- [stateful.sage](stateful.sage) evaluates stateful alternatives (XMSS, XMSS-MT, SHRINCS/UXMSS) against the SLH-DSA-128s baseline
- [parameters.json](parameters.json) holds the search grids and fixed parameters that the Sage scripts, the tests and `site/data.json` share
- [octopus_pmf.py](octopus_pmf.py) computes the PMF of the Octopus authentication set size (MIT license, from https://github.com/MehdiAbri/PORS-FP)
- [slhdsa-2to40.sage](slhdsa-2to40.sage) sweeps SLH-DSA parameter tuples and filters them by security level and signature size
- [export_site_data.sage](export_site_data.sage) exports `site/data.json`, the dataset both site pages load
- [utils/](utils/) helper scripts for searching and visualising the parameter space
- [tests/](tests/) regression suite, run `python3 tests/test_regression.py`
- [document/](document/) LaTeX source for the accompanying technical report
- [site/](site/) interactive pages hosted on GitHub Pages: the SHRINCS pinned-parameters main page ([index.html](site/index.html)), stateless parameter search over all report schemes (SPX / W+C / FORS+C / PORS+FP) with worst-case mode, shareable URL state and CSV export ([stateless.html](site/stateless.html)), and stateful scheme comparison ([stateful.html](site/stateful.html)); the cost and security model shared by the three pages lives in [js/model.js](site/js/model.js). The report PDF is not tracked in git: CI compiles [document/](document/) and deploys it as `site/report.pdf` (also attached to releases on tags)

Contributing: run `make check-local` before pushing.