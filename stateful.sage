"""
Stateful hash-based signature scheme search: XMSS, XMSS-MT, and SHRINCS/UXMSS.

Analyzes three stateful hash-based signature constructions across two
signature-count targets: 2^20 and 2^40.

1. XMSS: Standard balanced single-layer Merkle tree (height h, 2^h signatures)
   - One layer; auth-path always h nodes (fixed per OTS/w/h combination).
   - Keygen builds 2^h WOTS keypairs (infeasible for h=40, fine for h=20).
   - BDS amortised signing: O(h) WOTS PK computations per signature.

2. XMSS-MT: Multi-tree hypertree (total height h, d layers of height h'=h/d)
   - The practical stateful solution for both 2^20 and 2^40 signatures.
   - Keygen builds only the top-layer tree (2^h' WOTS keypairs, manageable).
   - Signing (cold): rebuild d trees of height h' per signature.
   - Signing (BDS): O(d*h') amortised WOTS PK computations per signature.
   - No FORS/FTS needed: state prevents replay attacks.
   - Signature size grows with d (more layers → more XMSS layer sigs).

3. SHRINCS/UXMSS: Left-leaning unbalanced Merkle tree (SHRINCS stateful)
   - Tree of height hsf with hsf+1 leaves; capacity = hsf + 1 signature.
   - The signature with index i in 1..hsf+1 carries min(i, hsf) auth nodes.
   - Signature size grows linearly with the index (XMSS-MT: constant).
   - Target is strictly isolated to 2^40 signatures, hardcoded to use (5,712 bytes) as the reference bound.
   - hsf is additionally capped at 255.

OTS variants:
  WOTS-classic  Original Winternitz OTS; no tweaks; l = l1 + l2 chains.
                Collision resistance required. No domain separation in chains.
                PK compression uses plain SHA-256 (1 fewer block than WOTS-TW).
  WOTS-TW       SPHINCS+-style tweakable-hash OTS; l = l1 + l2 chains.
                Only second-preimage resistance required.
  WOTS+C        Counter-based OTS; no checksum; l = l1 + grinding counter.
                Verification cost fixed: (w-1)*l - S_wn steps (deterministic).

w values: 16, 32, 64, 128, 256.
  w= 16: l1=32  WOTS-TW/classic l=35  WOTS+C S_wn=240
  w= 32: l1=26  WOTS-TW/classic l=28  WOTS+C S_wn=403
  w= 64: l1=22  WOTS-TW/classic l=24  WOTS+C S_wn=693
  w=128: l1=19  WOTS-TW/classic l=21  WOTS+C S_wn=1206
  w=256: l1=16  WOTS-TW/classic l=18  WOTS+C S_wn=2040

  Note: l1 = ceil(8n / log2(w)) per FIPS 205. For w=16 and w=256 the
  division is exact; the others need the round-up (w=32: 26 chains for
  130 >= 128 bits, w=64: 22 for 132, w=128: 19 for 133) to cover the
  full 128-bit message digest.

SHA-256 compression model: inherited from costs.sage, governed by the
HASH_CONVENTION env var ('cached' default: PK.seed midstate cached, C_Th2=1,
Thl_tw(l) = ceil((241+128*l)/512); 'uncached' original: C_Th2=2,
Thl_tw(l) = ceil((289+128*l)/512)). Always: C_Th1=1 C_Th1c=1 C_PRF=1
C_Hmsg=2 C_PRFmsg=2; Thl_classic(l) = ceil((65+128*l)/512) (plain SHA-256).

Usage:
  sage stateful.sage                     # Tables for both 2^20 and 2^40
  sage stateful.sage --csv               # CSV to stdout
  sage stateful.sage --output FILE.csv   # Write CSV to file (also shows tables)
  sage stateful.sage --xmss-only         # Single-layer XMSS table only
  sage stateful.sage --xmssmt-only       # XMSS-MT table only
  sage stateful.sage --uxmss-only        # UXMSS table only
  sage stateful.sage --detail            # Per-q UXMSS size progression
  sage stateful.sage --help              # This message
"""

import os, sys, csv as _csv
from math import log, ceil


_saved_argv = sys.argv
sys.argv = ['stateful.sage']
_dir = os.path.dirname(os.path.abspath(__file__))
os.environ['COSTS_SAGE_NO_MAIN'] = '1'   # functions only — suppress costs.sage CLI output
load(os.path.join(_dir, "costs.sage"))
sys.argv = _saved_argv


def _parse_args(argv):
    do_csv = xmss_only = xmssmt_only = uxmss_only = show_detail = False
    output_file = None
    ref_overrides = {}      # {20: N, 40: N}
    i = 1
    while i < len(argv):
        a = argv[i]
        if   a == "--csv":          do_csv = True; i += 1
        elif a == "--xmss-only":    xmss_only = True; i += 1
        elif a == "--xmssmt-only":  xmssmt_only = True; i += 1
        elif a == "--uxmss-only":   uxmss_only = True; i += 1
        elif a == "--detail":       show_detail = True; i += 1
        elif a == "--output" and i + 1 < len(argv):
            output_file = argv[i + 1]; i += 2
        elif a == "--ref-size20" and i + 1 < len(argv):
            ref_overrides[20] = int(argv[i + 1]); i += 2
        elif a == "--ref-size40" and i + 1 < len(argv):
            ref_overrides[40] = int(argv[i + 1]); i += 2
        elif a == "--help":
            print(__doc__); sys.exit(0)
        else:
            print("Unknown argument: {}".format(a), file=sys.stderr); sys.exit(2)
    return do_csv, xmss_only, xmssmt_only, uxmss_only, show_detail, output_file, ref_overrides

(DO_CSV, XMSS_ONLY, XMSSMT_ONLY,
 UXMSS_ONLY, SHOW_DETAIL,
 OUTPUT_FILE, REF_OVERRIDES) = _parse_args(sys.argv)

N          = hashbytes       # 16 bytes = 128-bit hash output
C_SIZE     = counter_size    # 4 bytes (WOTS+C grinding counter)
R_SIZE     = randomness_size # 16 bytes = n (message randomness, from costs.sage)
TARGET_SEC = 128             # Minimum security level (bits)


def idx_bytes(h):
    """Minimum bytes required to encode a leaf index in a tree of total height h.

    h=20 → 3 B (covers 2^20 leaves), h=40 → 5 B (covers 2^40 leaves).
    A hardcoded 4-byte field would under-size signatures for h>32.
    """
    return max(1, int(ceil(h / 8)))

# Targets
H_VALS       = [20, 40]      # h=20 -> 2^20 sigs, h=40 -> 2^40 sigs for standard trees
UXMSS_H_VALS = [40]          # UXMSS restricted to 2^40 target based on SLH-DSA reference

# OTS type identifiers
OTS_CLASSIC = "classic"
OTS_TW      = "tw"
OTS_WC      = "wc"

# WOTS+C target digit sums S_wn = floor(l1*(w-1)/2), where l1 = ceil(8n/log2(w))
# w=16:  l1=32, S_wn = 32*15/2 = 240
# w=32:  l1=26, S_wn = 26*31/2 = 403
# w=64:  l1=22, S_wn = 22*63/2 = 693
# w=128: l1=19, S_wn = floor(19*127/2) = 1206  (odd product; ν(1206) = ν(1207))
# w=256: l1=16, S_wn = 16*255/2 = 2040
WOTS_C_PAIRS = [(16, 240), (32, 403), (64, 693), (128, 1206), (256, 2040)]
WOTS_W_VALS  = [16, 32, 64, 128, 256]

PARAM_SETS = (
    [(OTS_WC,      w, swn) for w, swn in WOTS_C_PAIRS] +
    [(OTS_TW,      w, 0)   for w in WOTS_W_VALS] +
    [(OTS_CLASSIC, w, 0)   for w in WOTS_W_VALS]
)

def get_d_vals(h):
    """Return XMSS-MT layer counts to sweep for a given total height h."""
    return [d for d in range(2, h + 1) if h % d == 0]


def ots_label(ots_type, w, swn):
    if ots_type == OTS_WC:      return "WOTS+C(w={:3d},S={:4d})".format(w, swn)
    if ots_type == OTS_TW:      return "WOTS-TW(w={:3d})".format(w)
    return "WOTS-classic(w={:3d})".format(w)


def wots_l(w, ots_type):
    """Total Winternitz chain count l, per FIPS 205 §11.

    l1 = ceil(8n / log2(w)) — message chains
    l2 = floor(log2(l1*(w-1)) / log2(w)) + 1 — checksum chains (WOTS-TW/classic only)
    """
    l1 = int(ceil(N * 8 / log(w, 2)))
    if ots_type == OTS_WC:
        return int(l1)
    l2 = int(floor(log(l1 * (w - 1), 2) / log(w, 2))) + 1
    return int(l1 + l2)


def wots_Thl(l, ots_type):
    """Compressions to compress l chain endpoints into the WOTS public key."""
    if ots_type == OTS_CLASSIC:
        return int(ceil((128 * l + 65) / 512))   # plain SHA-256
    return int(compute_Th(l))                    # ceil((289+128*l)/512)


def wots_pk_C(w, ots_type):
    l   = wots_l(w, ots_type)
    Thl = wots_Thl(l, ots_type)
    return l * C_PRF + l * (w - 1) * C_Th1 + Thl


def wots_sign_C(w, swn, ots_type):
    l   = wots_l(w, ots_type)
    if ots_type == OTS_WC:
        Thl    = wots_Thl(l, ots_type)
        nu     = compute_nu(l, swn, w)
        search = int(ceil(F(w)**l / F(nu)))
        return search * C_Th1c + l * C_PRF + swn * C_Th1 + Thl
    return l * C_PRF + l * (w - 1) // 2 * C_Th1


def wots_verify_worst_steps(w, ots_type):
    l1 = int(ceil(N * 8 / log(w, 2)))
    l2 = int(floor(log(l1 * (w - 1), 2) / log(w, 2))) + 1
    C = l1 * (w - 1)
    ds = 0
    rem = C
    while rem > 0:
        ds += rem % w
        rem = rem // w
    return l1 * (w - 1) + l2 * (w - 1) - ds


def wots_verify_C(w, swn, ots_type, worst_case=False):
    l   = wots_l(w, ots_type)
    Thl = wots_Thl(l, ots_type)
    
    if ots_type == OTS_WC:
        return ((w - 1) * l - swn) * C_Th1 + C_Th1c + Thl
    
    if worst_case:
        steps = wots_verify_worst_steps(w, ots_type)
        return steps * C_Th1 + Thl
        
    return l * (w - 1) // 2 * C_Th1 + Thl

def tree_size_per_layer(h_prime, w, ots_type):
    l   = wots_l(w, ots_type)
    ctr = C_SIZE if ots_type == OTS_WC else 0
    return h_prime * N + l * N + ctr


def tree_keygen_C(h_prime, w, ots_type):
    pk = wots_pk_C(w, ots_type)
    sz = F(2)**h_prime
    return sz * pk + (sz - 1) * C_Th2


def tree_sign_amortised_C(h_prime, w, swn, ots_type):
    pk   = wots_pk_C(w, ots_type)
    c_sg = wots_sign_C(w, swn, ots_type)
    return C_Hmsg + C_PRFmsg + c_sg + h_prime * pk + h_prime * C_Th2


def tree_verify_C(h_prime, w, swn, ots_type, worst_case=False):
    return wots_verify_C(w, swn, ots_type, worst_case) + h_prime * C_Th2


def xmss_size_h(h, w, ots_type):
    l   = wots_l(w, ots_type)
    ctr = C_SIZE if ots_type == OTS_WC else 0
    return R_SIZE + ctr + l * N + h * N + idx_bytes(h)


def xmss_keygen_C_h(h, w, ots_type):
    return float(tree_keygen_C(h, w, ots_type))


def xmss_sign_C_h(h, w, swn, ots_type):
    return float(tree_sign_amortised_C(h, w, swn, ots_type))


def xmss_verify_C_h(h, w, swn, ots_type, worst_case=False):
    return float(C_Hmsg + tree_verify_C(h, w, swn, ots_type, worst_case))


def compute_xmss_rows(h):
    rows = []
    for ots_type, w, swn in PARAM_SETS:
        rows.append(dict(
            scheme   = "XMSS",
            h=h, q_s_log2=h, d=1, h_prime=h,
            label    = ots_label(ots_type, w, swn),
            ots_type = ots_type, w=w, swn=swn,
            l        = wots_l(w, ots_type),
            size     = xmss_size_h(h, w, ots_type),
            keygen_C = xmss_keygen_C_h(h, w, ots_type),
            sign_C   = xmss_sign_C_h(h, w, swn, ots_type),
            sign_cold_C = xmssmt_sign_cold_C_h(h, 1, w, swn, ots_type),
            state_bytes = xmssmt_state_bytes(h, 1, w, ots_type),
            verify_avg_C   = xmss_verify_C_h(h, w, swn, ots_type, worst_case=False),
            verify_worst_C = xmss_verify_C_h(h, w, swn, ots_type, worst_case=True),
        ))
    return rows


def xmssmt_size_h(h, d, w, ots_type):
    h_prime = h // d
    return R_SIZE + d * tree_size_per_layer(h_prime, w, ots_type) + idx_bytes(h)


def xmssmt_keygen_C_h(h, d, w, ots_type):
    h_prime = h // d
    return float(tree_keygen_C(h_prime, w, ots_type))


def xmssmt_sign_cold_C_h(h, d, w, swn, ots_type):
    h_prime = h // d
    return float(C_Hmsg + C_PRFmsg +
                 d * (float(tree_keygen_C(h_prime, w, ots_type)) +
                      wots_sign_C(w, swn, ots_type)))


def xmssmt_sign_bds_C_h(h, d, w, swn, ots_type):
    h_prime = h // d
    pk      = wots_pk_C(w, ots_type)
    c_sg    = wots_sign_C(w, swn, ots_type)
    
    return float(C_Hmsg + C_PRFmsg + c_sg + d * (h_prime * pk + h_prime * C_Th2))


def xmssmt_verify_C_h(h, d, w, swn, ots_type, worst_case=False):
    h_prime = h // d
    return float(C_Hmsg + d * tree_verify_C(h_prime, w, swn, ots_type, worst_case))


def compute_xmssmt_rows(h):
    rows = []
    for ots_type, w, swn in PARAM_SETS:
        for d in get_d_vals(h):
            h_prime = h // d
            rows.append(dict(
                scheme   = "XMSS-MT",
                h=h, q_s_log2=h, d=d, h_prime=h_prime,
                label    = ots_label(ots_type, w, swn),
                ots_type = ots_type, w=w, swn=swn,
                l        = wots_l(w, ots_type),
                size     = xmssmt_size_h(h, d, w, ots_type),
                keygen_C = xmssmt_keygen_C_h(h, d, w, ots_type),
                sign_C   = xmssmt_sign_bds_C_h(h, d, w, swn, ots_type),
                sign_cold_C = xmssmt_sign_cold_C_h(h, d, w, swn, ots_type),
                state_bytes = xmssmt_state_bytes(h, d, w, ots_type),
                verify_avg_C   = xmssmt_verify_C_h(h, d, w, swn, ots_type, worst_case=False),
                verify_worst_C = xmssmt_verify_C_h(h, d, w, swn, ots_type, worst_case=True),
            ))
    return rows

def _uxmss_idx_bytes(hsf):
    """UXMSS supports hsf+1 signatures; index only needs to distinguish those."""
    if hsf <= 0:
        return 1
    return max(1, int(ceil(log(hsf + 1, 2) / 8)))


HSF_MAX = 255   # FXMSS encodes the node height as a single byte

def find_max_hsf(w, ots_type, target_size):
    """Largest hsf with the max UXMSS signature strictly < target_size,
    capped at HSF_MAX = 255.

    Because idx_bytes depends on hsf, we use a small fixed-point loop.
    """
    l   = wots_l(w, ots_type)
    ctr = C_SIZE if ots_type == OTS_WC else 0
    hsf = 0
    # Iterate until the index-byte assumption is self-consistent.
    for _ in range(64):
        idx = _uxmss_idx_bytes(hsf)
        avail = target_size - 1 - R_SIZE - ctr - l * N - idx
        new_hsf = max(0, min(int(avail // N), HSF_MAX))
        if new_hsf == hsf:
            return hsf
        hsf = new_hsf
    return hsf


def uxmss_size(q, hsf, w, ots_type):
    l   = wots_l(w, ots_type)
    ctr = C_SIZE if ots_type == OTS_WC else 0
    return R_SIZE + ctr + l * N + min(q, hsf) * N + _uxmss_idx_bytes(hsf)


def uxmss_keygen_C(hsf, w, ots_type):
    return float((hsf + 1) * wots_pk_C(w, ots_type) + hsf * C_Th2)


def uxmss_sign_C(q, hsf, w, swn, ots_type):
    """Cached signer: the full tree is kept as state, auth nodes are lookups."""
    return float(C_Hmsg + C_PRFmsg + wots_sign_C(w, swn, ots_type))


def uxmss_sign_cold_C(hsf, w, swn, ots_type):
    """State-minimal signer: rebuild all leaves to derive the auth path, then sign."""
    return float(C_Hmsg + C_PRFmsg + wots_sign_C(w, swn, ots_type)
                 + uxmss_keygen_C(hsf, w, ots_type))


def uxmss_state_bytes(hsf):
    """Cached-signer state: all hsf+1 leaf hashes"""
    return int((hsf + 1) * N)


def xmssmt_state_bytes(h, d, w, ots_type):
    """BDS-style cached-signer state estimate: ~3.5*h' nodes per layer plus the cached
    upper-layer WOTS signatures. See Buchmann-Dahmen-Schneider,
    'Merkle Tree Traversal Revisited'."""
    h_prime = h // d
    l = wots_l(w, ots_type)
    return int(d * ceil(3.5 * h_prime) * N + (d - 1) * l * N)

def uxmss_verify_C(q, hsf, w, swn, ots_type, worst_case=False):
    return float(C_Hmsg + wots_verify_C(w, swn, ots_type, worst_case) + min(q, hsf) * C_Th2)


def compute_uxmss_rows(target_size, q_s_log2):
    rows = []
    for ots_type, w, swn in PARAM_SETS:
        hsf  = find_max_hsf(w, ots_type, target_size)
        nsig = hsf + 1
        rows.append(dict(
            scheme       = "UXMSS",
            q_s_log2     = q_s_log2,
            ref_size     = target_size,
            label        = ots_label(ots_type, w, swn),
            ots_type     = ots_type, w=w, swn=swn,
            l            = wots_l(w, ots_type),
            hsf          = hsf, nsig=nsig,
            sz_q1        = uxmss_size(1,   hsf, w, ots_type),
            sz_max       = uxmss_size(hsf, hsf, w, ots_type),
            keygen_C     = uxmss_keygen_C(hsf, w, ots_type),
            sign_q1_C    = uxmss_sign_C(1,   hsf, w, swn, ots_type),
            sign_cold_C  = uxmss_sign_cold_C(hsf, w, swn, ots_type),
            state_bytes  = uxmss_state_bytes(hsf),
            verify_max_avg_C   = uxmss_verify_C(hsf, hsf, w, swn, ots_type, worst_case=False),
            verify_max_worst_C = uxmss_verify_C(hsf, hsf, w, swn, ots_type, worst_case=True),
        ))
    return rows


# Unified CSV header covering all three schemes
_CSV_HEADER = [
    "scheme", "q_s_log2", "h_total", "d", "h_prime",
    "ots_type", "w", "swn", "l",
    "size_bytes",
    "keygen_C", "sign_bds_C", "sign_cold_C", "state_bytes",
    "verify_avg_C", "verify_worst_C",
    "ref_size", "hsf", "num_sigs",
    "sz_q1", "sz_max", "sign_q1_C", "verify_max_avg_C", "verify_max_worst_C",
]


def _fmt_f(v):
    """Format float for CSV (empty string for NaN)."""
    import math
    if isinstance(v, float) and math.isnan(v):
        return ""
    return "{:.6e}".format(float(v))


def _xmss_csv_row(r):
    return [r['scheme'], r['q_s_log2'], r['h'], r['d'], r['h_prime'],
            r['ots_type'], r['w'], r['swn'], r['l'],
            r['size'],
            _fmt_f(r['keygen_C']), _fmt_f(r['sign_C']),
            _fmt_f(r['sign_cold_C']), r['state_bytes'],
            _fmt_f(r['verify_avg_C']), _fmt_f(r['verify_worst_C']),
            "", "", "", "", "", "", "", ""]


def _xmssmt_csv_row(r):
    return [r['scheme'], r['q_s_log2'], r['h'], r['d'], r['h_prime'],
            r['ots_type'], r['w'], r['swn'], r['l'],
            r['size'],
            _fmt_f(r['keygen_C']), _fmt_f(r['sign_C']),
            _fmt_f(r['sign_cold_C']), r['state_bytes'],
            _fmt_f(r['verify_avg_C']), _fmt_f(r['verify_worst_C']),
            "", "", "", "", "", "", "", ""]


def _uxmss_csv_row(r):
    return [r['scheme'], r['q_s_log2'], "", "", "",
            r['ots_type'], r['w'], r['swn'], r['l'],
            "",
            _fmt_f(r['keygen_C']), "", _fmt_f(r['sign_cold_C']), r['state_bytes'], "", "",
            r['ref_size'], r['hsf'], r['nsig'],
            r['sz_q1'], r['sz_max'],
            _fmt_f(r['sign_q1_C']), _fmt_f(r['verify_max_avg_C']), _fmt_f(r['verify_max_worst_C'])]


def write_csv(dest, xmss_by_h, xmssmt_by_h, uxmss_by_h):
    """
    Write all results to dest (file object or sys.stdout).
    Groups: XMSS h=20, XMSS h=40, XMSS-MT h=20, XMSS-MT h=40, UXMSS 2^40.
    """
    writer = _csv.writer(dest)
    writer.writerow(_CSV_HEADER)
    total = 0
    for h in H_VALS:
        for r in xmss_by_h.get(h, []):
            writer.writerow(_xmss_csv_row(r)); total += 1
    for h in H_VALS:
        for r in xmssmt_by_h.get(h, []):
            writer.writerow(_xmssmt_csv_row(r)); total += 1
    for h in UXMSS_H_VALS:
        for r in uxmss_by_h.get(h, []):
            writer.writerow(_uxmss_csv_row(r)); total += 1
    return total


def save_csv_file(path, xmss_by_h, xmssmt_by_h, uxmss_by_h):
    """Save all results to a CSV file and report row count."""
    with open(path, 'w', newline='') as f:
        n = write_csv(f, xmss_by_h, xmssmt_by_h, uxmss_by_h)
    print("Saved {} data rows to {!r}".format(n, path), file=sys.stderr)


def fmt_c(n):
    """Format a compression count with K/M/G/T suffixes."""
    import math
    if isinstance(n, float) and math.isnan(n):
        return "—"
    n = float(n)
    if n >= 1e15: return "{:.2e}".format(n)
    if n >= 1e12: return "{:.2f}T".format(n / 1e12)
    if n >= 1e9:  return "{:.2f}G".format(n / 1e9)
    if n >= 1e6:  return "{:.2f}M".format(n / 1e6)
    if n >= 1e3:  return "{:.1f}K".format(n / 1e3)
    return "{:d}".format(int(n))


def _row(vals, cols):
    return " ".join("{:{a}{w}}".format(str(v), a=a, w=w)
                    for v, (_, w, a) in zip(vals, cols))


def _hdr(cols):
    return " ".join("{:{a}{w}}".format(h, a=a, w=w) for h, w, a in cols)


def _sep_line(cols, char="-"):
    return char * (sum(c[1] for c in cols) + len(cols) - 1)


def print_xmss_table(rows_by_h):
    cols = [("q_s", 4, ">"), ("OTS Variant", 26, "<"), ("l", 3, ">"),
            ("Size(B)", 7, ">"), ("Keygen(C)", 11, ">"),
            ("Sign-BDS(C)", 11, ">"), ("Vfy-avg(C)", 10, ">"), ("Vfy-wrst(C)", 11, ">")]
    W = sum(c[1] for c in cols) + len(cols) - 1
    print()
    print("="*W)
    print(" XMSS — Single-Layer Balanced Tree ".center(W, "="))
    print(" OTS: WOTS-classic / WOTS-TW / WOTS+C  |  w ∈ {16,32,64,128,256} ".center(W, "="))
    print(" Auth path = h nodes (fixed per sig); Sign-BDS = amortised ".center(W, "="))
    print("="*W)
    print(_hdr(cols)); print(_sep_line(cols))
    for h in H_VALS:
        for r in rows_by_h.get(h, []):
            infeas = r['keygen_C'] > 1e11
            kg = fmt_c(r['keygen_C']) + ("*" if infeas else " ")
            print(_row(["2^{}".format(h), r['label'], r['l'], r['size'],
                        kg, fmt_c(r['sign_C']), 
                        fmt_c(r['verify_avg_C']), fmt_c(r['verify_worst_C'])], cols))
        print()
    print(_sep_line(cols))
    print("* Keygen for h=40 requires 2^40 ≈ 1.1·10^12 WOTS keypairs — infeasible.")
    print("  h=20 keygen ≈ 2^20 ≈ 1M WOTS keys — feasible (~seconds on modern CPU).")
    print()


def print_xmssmt_table(rows_by_h):
    cols = [("q_s", 4, ">"), ("OTS Variant", 26, "<"), ("d", 2, ">"),
            ("h'", 3, ">"), ("l", 3, ">"), ("Size(B)", 7, ">"),
            ("Keygen(C)", 10, ">"), ("Sign-BDS(C)", 11, ">"),
            ("Sign-cold(C)", 12, ">"), ("Vfy-avg(C)", 10, ">"), ("Vfy-wrst(C)", 11, ">")]
    W = sum(c[1] for c in cols) + len(cols) - 1
    print()
    print("="*W)
    print(" XMSS-MT — Multi-Tree Hypertree (no FORS needed; stateful) ".center(W, "="))
    print(" OTS: WOTS-classic / WOTS-TW / WOTS+C  |  w ∈ {16,32,64,128,256} ".center(W, "="))
    print(" Keygen builds top tree only (2^h' keys); Sign-BDS amortised ".center(W, "="))
    print("="*W)
    print(_hdr(cols)); print(_sep_line(cols))
    cur_label = None
    for h in H_VALS:
        for r in rows_by_h.get(h, []):
            tag = "2^{}".format(h)
            new_label = (h, r['label'])
            if new_label != cur_label:
                if cur_label is not None:
                    print()
                cur_label = new_label
            print(_row([tag, r['label'], r['d'], r['h_prime'], r['l'], r['size'],
                        fmt_c(r['keygen_C']), fmt_c(r['sign_C']), fmt_c(r['sign_cold_C']), 
                        fmt_c(r['verify_avg_C']), fmt_c(r['verify_worst_C'])], cols))
    print()
    print(_sep_line(cols))
    print("Sign-cold: rebuild d trees per sig (worst-case). BDS: amortised O(d·h') PK evals.")
    print()


def print_uxmss_table(rows_by_h, refs):
    cols = [("OTS Variant", 26, "<"), ("l", 3, ">"),
            ("Ref(B)", 6, ">"), ("hsf", 5, ">"), ("Sigs", 7, ">"),
            ("Sz(q=1)", 8, ">"), ("Sz(max)", 8, ">"),
            ("Keygen(C)", 10, ">"), ("Sign(q=1)", 9, ">"), 
            ("VfyAvg(mx)", 10, ">"), ("VfyWrst(mx)", 11, ">")]
    W = sum(c[1] for c in cols) + len(cols) - 1
    print()
    print("="*W)
    print(" SHRINCS/UXMSS — Left-leaning Stateful Tree ".center(W, "="))
    print(" OTS: WOTS-classic / WOTS-TW / WOTS+C  |  w ∈ {16,32,64,128,256} ".center(W, "="))
    print(" max stateful sig must be strictly < Ref ".center(W, "="))
    print("="*W)
    print(_hdr(cols)); print(_sep_line(cols))
    for h in UXMSS_H_VALS:
        ref = refs.get(h)
        ref_size = ref['size'] if ref else "—"
        for r in rows_by_h.get(h, []):
            print(_row([r['label'], r['l'], ref_size,
                        r['hsf'], r['nsig'], r['sz_q1'], r['sz_max'],
                        fmt_c(r['keygen_C']), fmt_c(r['sign_q1_C']),
                        fmt_c(r['verify_max_avg_C']), fmt_c(r['verify_max_worst_C'])], cols))
        print()
    print(_sep_line(cols))
    print("Ref: SPX reference computed per target (see footer for parameters).")
    print("hsf = max auth-path nodes; Sigs = hsf+1; Sz(max) must be < Ref.")
    print()


def print_uxmss_detail(uxmss_by_h):
    for h in UXMSS_H_VALS:
        print("\n  --- UXMSS Per-Signature Progression (Bounded by Ref Size for 2^{} target) ---".format(h))
        for r in uxmss_by_h.get(h, []):
            hsf = r['hsf']
            w, swn, ots_type = r['w'], r['swn'], r['ots_type']
            if hsf <= 0: continue
            print("\n  {} (l={}, hsf={}, {} sigs)".format(
                r['label'], r['l'], hsf, hsf + 1))
            print("  {:>6}  {:>8}  {:>12}  {:>12}  {:>12}".format(
                "q", "Size(B)", "Sign(C)", "Vfy-avg(C)", "Vfy-wrst(C)"))
            print("  " + "-" * 56)
            qpts = sorted(set(filter(lambda q: 1 <= q <= hsf + 1,
                 [1, 2, 5, 10, hsf // 4, hsf // 2, 3 * hsf // 4,
                 max(1, hsf - 1), hsf, hsf + 1])))
            for q in qpts:
                sz = uxmss_size(q, hsf, w, ots_type)
                sc = uxmss_sign_C(q, hsf, w, swn, ots_type)
                vc_avg = uxmss_verify_C(q, hsf, w, swn, ots_type, worst_case=False)
                vc_wrst = uxmss_verify_C(q, hsf, w, swn, ots_type, worst_case=True)
                flag = " ← max" if q == hsf else (" ← last" if q == hsf + 1 else "")
                print("  {:>6}  {:>8}  {:>12}  {:>12}  {:>12}{}".format(
                    q, sz, fmt_c(sc), fmt_c(vc_avg), fmt_c(vc_wrst), flag))
    print()


# The env flag lets other scripts (export_site_data.sage) load this file for
# its functions without triggering the CLI tables (sage's load() executes in
# the caller's namespace, where __name__ is '__main__').
if __name__ == "__main__" and not os.environ.get("STATEFUL_SAGE_NO_MAIN"):
    refs = {}
    for h in UXMSS_H_VALS:
        print("Applying Candidate 2 as hardcoded reference (5,712 B) for target 2^{}.".format(h),
              file=sys.stderr)
        refs[h] = dict(h=45, d=5, k=8, a=16, w=16, size=5712, security=128.0)

    xmss_by_h   = {h: compute_xmss_rows(h)             for h in H_VALS}
    xmssmt_by_h = {h: compute_xmssmt_rows(h)             for h in H_VALS}
    uxmss_by_h  = {h: compute_uxmss_rows(refs[h]['size'] if refs[h] else 9999, h)
                   for h in UXMSS_H_VALS}

    if DO_CSV:
        write_csv(sys.stdout, xmss_by_h, xmssmt_by_h, uxmss_by_h)

    if OUTPUT_FILE:
        save_csv_file(OUTPUT_FILE, xmss_by_h, xmssmt_by_h, uxmss_by_h)

    if not DO_CSV:
        if not XMSSMT_ONLY and not UXMSS_ONLY:
            print_xmss_table(xmss_by_h)
        if not XMSS_ONLY and not UXMSS_ONLY:
            print_xmssmt_table(xmssmt_by_h)
        if not XMSS_ONLY and not XMSSMT_ONLY:
            print_uxmss_table(uxmss_by_h, refs)
        if SHOW_DETAIL and not XMSS_ONLY and not XMSSMT_ONLY:
            print_uxmss_detail(uxmss_by_h)

        print("=" * 72)
        print(" Reference configurations ".center(72, "="))
        print("=" * 72)
        for h_target in UXMSS_H_VALS:
            r = refs.get(h_target)
            if r and r.get('security') is not None:
                print("  target=2^{target}: SPX h={h},d={d},k={k},a={a},w={w}  "
                      "({security:.1f}-bit)  {size} B".format(target=h_target, **r))
        print()