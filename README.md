# SPHINCS-Parameters

Scripts for exploring SPHINCS+ parameter tradeoffs, computing security levels, signature sizes, and signing/verification costs.

- [security.sage](security.sage) computes the security level for FORS and PORS+FP parameter sets
- [original-sphincs-parameter-search.sage](original-sphincs-parameter-search.sage) script from https://sphincs.org/data/sphincs+-specification.pdf (updated for SageMath 9.0)
- [costs.sage](costs.sage) computes signature sizes and signing/verification times for SPHINCS+ variants
- [octopus_pmf.py](octopus_pmf.py) computes the PMF of the Octopus authentication set size (MIT license, from https://github.com/MehdiAbri/PORS-FP)
