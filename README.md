# SPHINCS-Parameters
Scripts for exploring SPHINCS+ parameter tradeoffs, computing security levels, signature sizes, and signing/verification costs.
- [security.sage](security.sage) computes the security level for FORS and PORS+FP parameter sets
- [original-sphincs-parameter-search.sage](original-sphincs-parameter-search.sage) script from https://sphincs.org/data/sphincs+-specification.pdf (updated for SageMath 9.0)
- [costs.sage](costs.sage) computes signature sizes and signing/verification times for SPHINCS+ variants
- [octopus_pmf.py](octopus_pmf.py) computes the PMF of the Octopus authentication set size (MIT license, from https://github.com/MehdiAbri/PORS-FP)
- [slhdsa-2to40.sage](slhdsa-2to40.sage) sweeps SLH-DSA parameter tuples and filters them by security level and signature size
- [run_experiments.py](run_experiments.py) runs the full parameter sweep and writes results to CSV
- [utils/](utils/) helper scripts for searching and visualising the parameter space
- [document/](document/) LaTeX source for the accompanying technical report
- [site/](site/) interactive parameter explorer hosted on GitHub Pages, including the compiled [report.pdf](site/report.pdf)