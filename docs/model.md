# Cost and security model

Sizes are in bytes and costs in SHA-256 compressions (C). The hash output is n = 16 bytes.
The pages compute the model in `site/js/model.js`, the Sage scripts in `costs.sage`,
`stateful.sage` and `security.sage`, and `tests/model.py` ports it to check both.

## Hash calls

Hashing follows the FIPS 205 SHA-2 instantiation as the SHRINCS reference implementation runs it:
the block that holds PK.seed is compressed once per key and its state reused, so each call pays
only for the rest of its input. A tweakable hash over m values of n bytes takes

    Th(m) = ceil((176 + 128·m + 65) / 512)

compressions: a 22-byte compressed address, the values, and the SHA-256 padding (one bit and a
64-bit length). A chain step, a chain step with the WOTS+C counter, a tree node and a PRF call each
fit in one block, so `C_Th1 = C_Th1c = C_Th2 = C_PRF = 1`. Compressing the l chain ends of a WOTS
key into a leaf takes Th(l), and the k FORS roots Th(k).

For a 32-byte message and an empty context:

- H_msg is two nested SHA-256 calls of 2 compressions each. Its input starts with the randomizer R,
  so no state can be reused: `C_Hmsg = 4`.
- PRF_msg is HMAC-SHA-256, two SHA-256 calls of 3 and 2 compressions. Their first blocks, the fixed
  key pads, are reused like the PK.seed block: `C_PRFmsg = 3`.

## WOTS

A WOTS key has l1 = ceil(8n / log2 w) message chains. WOTS-TW, the variant in SLH-DSA, adds
l2 = floor(log_w(l1·(w − 1))) + 1 checksum chains (FIPS 205); WOTS+C has none and grinds a counter
instead. With l chains, a public key costs

    pk = l·PRF + l·(w − 1)·Th1 + Th(l)

### WOTS-TW verification

A message digit m costs the verifier w − 1 − m chain steps, so the message chains average
(w − 1)/2 steps each. The checksum chains do not: the checksum C = l1·(w − 1) − S, with S the sum
of the message digits, is concentrated around l1·(w − 1)/2, so its leading base-w digit is almost
always 0 or 1 and the verifier walks most of that chain. With digit_sum(x) = x − (w − 1)·Σ_{j≥1}
floor(x / w^j), and C distributed like S (map every digit m to w − 1 − m),

    E[steps] = l1·(w − 1)/2 + l2·(w − 1) − E[digit_sum(C)]
             = (w − 1)·(l2 + Σ_{j=1}^{l2−1} E[floor(S / w^j)])

where E[floor(S / w^j)] = Σ_{m≥1} P(S ≥ m·w^j), and the number of digit strings with sum at most t
is Σ_i (−1)^i·C(l1, i)·C(t − i·w + l1, l1). The code evaluates this with exact integers and rounds
the total for all d layers of a signature once, to the nearest integer. For w = 16 the mean is
267.12 steps rather than the 262 of (w − 1)·l/2; for w = 256 it is 2415.03 rather than 2295.

The verifier walks the most when every message digit is 0. The checksum is then l1·(w − 1), so

    worst = l1·(w − 1) + l2·(w − 1) − digit_sum(l1·(w − 1))

Any other message saves at least as many steps on the message chains as it can cost on the
checksum chains.

The signer walks the part of each chain the verifier does not: l PRF calls and
l·(w − 1) − E[steps] chain steps.

### WOTS+C

The signer grinds a counter until the l = l1 digits of the digest sum to S_wn, which makes
verification cost the same for every message. Of the w^l digit strings,

    ν = Σ_{j=0}^{l} (−1)^j·C(l, j)·C(S_wn + l − j·w − 1, l − 1)

have that sum, so signing takes ceil(w^l / ν) attempts of `C_Th1c` on average, then l PRF calls and
S_wn chain steps. Verification takes l·(w − 1) − S_wn chain steps, one `C_Th1c` and Th(l).

SHRINCS stores the counter in 2 bytes: 2^16 counters miss the target sum with probability below
2^−126 for every w ≤ 256. w = 65536 needs about 137,000 attempts on average and keeps a 4-byte
counter.

## SLH-DSA

For (h, d, k, a, w), the hypertree has d layers of trees of height h′ = h/d.

    size   = n·(1 + k·(a + 1) + h + d·l)
    tree   = 2^h′·pk + (2^h′ − 1)·Th2
    KeyGen = tree
    SigGen = FORS + H_msg + PRF_msg + d·tree
    FORS   = k·2^a·(PRF + Th1) + k·(2^a − 1)·Th2 + Th(k)
    SigVer = H_msg + k·Th1 + k·a·Th2 + Th(k) + d WOTS-TW verifications + h·Th2

The size counts the randomizer, k FORS leaves with a authentication nodes each, the h nodes of the
hypertree authentication path and d WOTS signatures: 7,856 B for SLH-DSA-128s, (63, 7, 14, 12, 16).
KeyGen builds the top tree; a signature rebuilds one tree per layer. SigVer takes the mean of
[WOTS-TW verification](#wots-tw-verification), SigVer worst its worst case in every layer. A SHRINCS
stateless signature adds a one-byte indicator.

## FORS security

The stateless schemes are evaluated at q_s = 2^40 signatures. Each signature uses one of 2^h FORS
instances, so the number r of signatures that land on a given instance follows Binomial(q_s, 2^−h).
After r signatures each of the k trees of t = 2^a leaves has revealed up to r leaves, and a forger
needs the leaf it must open revealed in every tree:

    P(forgery | r) = (1 − (1 − 1/t)^r)^k
    P(forgery)     = Σ_r C(q_s, r)·2^(−h·r)·(1 − 2^−h)^(q_s − r)·P(forgery | r)
    security       = −log2(max(2^(−8n), P(forgery)))

so 128 bits at most. Unlike the SPHINCS+ parameter script, this uses the exact forgery factor
instead of the bound (r/t)^k, and the maximum of the two attacks instead of their sum, since a
query cannot serve both. `security.sage` also covers PORS+FP.

The page sums in log2 to avoid underflow. Only r within 30·sqrt(λ + 1) + 30 of the mean
λ = q_s / 2^h is summed: further out the binomial weight is below e^−450 of its peak. That keeps
the work at O(sqrt(λ)); when even that exceeds 2^16 terms, the sum takes every s-th term and
weights it by s. For the parameter grid λ ≤ 1, and every term from r = 1 is summed.

## Stateful schemes

Every stateful scheme uses the SHRINCS stateful signature layout, so sizes compare like for like:

    indicator (1 B) | R (16 B) | leaf index | per layer: [counter] + l·n chain values + h′·n auth path

The leaf index takes max(1, ceil(h / 8)) bytes in XMSS and XMSS-MT. In UXMSS it takes
ceil(min(depth, 64) / 8) bytes for a leaf at that depth: SHRINCS sizes the field by the depth of
the signing leaf.

### XMSS and XMSS-MT

d layers of trees of height h′ = h/d give 2^h signatures; XMSS is d = 1.

    KeyGen = 2^h′·pk + (2^h′ − 1)·Th2      the top tree
    SigVer = H_msg + d·(WOTS verification + h′·Th2)

A cached signer keeps a BDS traversal state for every layer (Buchmann, Dahmen and Schneider,
"Merkle Tree Traversal Revisited", PQCrypto 2008) and the WOTS signatures of the upper layers, so
it computes one WOTS signature and one BDS update per layer. K is 2 for even h′ and 3 for odd, the
smallest K ≥ 2 with h′ − K even. An update takes at most (h′ − K)/2 + 1 leaf computations and
floor(3·(h′ − K − 1)/2) + 1 node hashes; the long-run average is about one leaf computation lower.

    SigGen, cached = H_msg + PRF_msg + WOTS signature + d·(leaves·pk + hashes·Th2)
    State          = d·(h′ + floor(h′/2) + 2^K − K − 1 + (h′ − K) + (h′ − K − 1))·n + (d − 1)·l·n

The state counts what the SHRINCS signer caches hold: the authentication path, the keep nodes,
the retained nodes, one completed node per treehash instance and their stack of partial results,
plus the upper-layer WOTS signatures.

A cold signer keeps no state and rebuilds the d trees for every signature. In the top tree it needs
only the authentication path, so it skips the signing leaf and the h′ nodes on its path to the root:

    SigGen, cold = H_msg + PRF_msg + d·(tree + WOTS signature) − pk − h′·Th2

### UXMSS

The SHRINCS unbalanced tree has a spine of height hsf with hsf + 1 leaves. The q-th signature
(q = 1 is the first) carries min(q, hsf) authentication nodes, so each signature is one node longer
than the one before. hsf is the largest value up to 255 for which the last signature stays below
5,712 B, the size of the report's candidate 2, (45, 5, 8, 16, 16).

    size(q) = 1 + 16 + index + counter + l·n + min(q, hsf)·n
    KeyGen  = (hsf + 1)·pk + hsf·Th2
    SigVer  = H_msg + WOTS verification + min(q, hsf)·Th2
    State   = (hsf + 1)·n

A cached signer keeps the hsf + 1 leaf public keys. Every authentication node is one of them,
except the sibling of the signing leaf on the spine, which it recombines from the cached leaves
below it with hsf − q node hashes (none for the last two signatures):

    SigGen, cached = H_msg + PRF_msg + WOTS signature + (hsf − min(q, hsf))·Th2

A cold signer first rebuilds the hsf other leaves. Its first signature, the most expensive, takes
SigGen, cached for q = 1, plus hsf·pk.

## Distance

The explorer and the stateful page rank the candidates within the bounds by the report's
metric-normalised weighted distance (Section 3, Metric-Normalized Weighted Distance). For each
metric i (size, KeyGen, SigGen, SigVer and ρ), X_i is the candidate's ratio to SLH-DSA-128s,
rescaled over the candidates within the bounds, and W_i is its weight:

    X̂_i = (X_i − min_i) / (max_i − min_i)      max_i = min_i + 1 if all X_i are equal
    d   = sqrt(Σ_i p_i·X̂_i²),                   p_i = W_i / Σ_j W_j

Because every X̂_i spans [0, 1], a weight sets its metric's share of the distance however loose the
bounds are. The explorer's worst-case mode uses the worst-case SigVer and ρ; on the stateful page
SigGen follows the signer mode.

## Schnorr reference

ρ ÷ Schnorr divides ρ by the compressions per byte of a BIP340 Schnorr verification with
libsecp256k1 for a 64-byte signature, read from `results/kappa.json` of
[bip340-vs-sha256](https://github.com/mjthatch/bip340-vs-sha256) when a page loads. If that fails,
the pages use 1.98 C/B.
