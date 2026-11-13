"""
XMSS and XMSS-MT for 2^20 and 2^40 signatures and UXMSS, the SHRINCS stateful
tree, with WOTS-TW and WOTS+C: sizes in bytes, costs in SHA-256 compressions and
signer state. docs/model.md has the model, parameters.json the w set, S_wn and
the UXMSS bounds. export_site_data.sage loads this file for site/data.json.

  sage stateful.sage [--xmss-only | --xmssmt-only | --uxmss-only] [--detail]
  sage stateful.sage --csv                (the CSV instead of the tables)
  sage stateful.sage --output FILE.csv    (the tables, and the CSV in FILE.csv)
"""
import csv
import math
import os
import sys

_DOC = __doc__   # loading costs.sage replaces __doc__
os.environ['COSTS_SAGE_NO_MAIN'] = '1'   # its functions, without its CLI
load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "costs.sage"))


def _parse_args(argv):
    do_csv = xmss_only = xmssmt_only = uxmss_only = show_detail = False
    output_file = None
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
        elif a == "--help":
            print(_DOC); sys.exit(0)
        else:
            print("Unknown argument: {}".format(a), file=sys.stderr); sys.exit(2)
    return do_csv, xmss_only, xmssmt_only, uxmss_only, show_detail, output_file


N        = hashbytes
R_SIZE   = randomness_size
IND_SIZE = 1   # SHRINCS indicator byte: the leaf height on the stateful path

H_VALS       = [20, 40]   # XMSS and XMSS-MT for 2^20 and 2^40 signatures
UXMSS_H_VALS = [40]       # the UXMSS bound is the size of a 2^40 stateless signature

OTS_TW = "tw"
OTS_WC = "wc"

WOTS_W_VALS  = PARAMETERS['stateful']['w']
WOTS_C_PAIRS = [(w, SWN[w]) for w in WOTS_W_VALS]

PARAM_SETS = (
    [(OTS_WC, w, swn) for w, swn in WOTS_C_PAIRS] +
    [(OTS_TW, w, 0)   for w in WOTS_W_VALS]
)

HSF_MAX = PARAMETERS['stateful']['hsf_max']


def ots_label(ots_type, w, swn):
    if ots_type == OTS_WC:      return "WOTS+C(w={:3d},S={:4d})".format(w, swn)
    return "WOTS-TW(w={:3d})".format(w)


def counter_bytes(w):
    """Bytes of the WOTS+C counter: 2 as in SHRINCS, 4 for w = 65536
    (docs/model.md, WOTS+C)."""
    return 2 if w <= 256 else 4


def idx_bytes(h):
    """Bytes of the leaf index in XMSS and XMSS-MT of total height h."""
    return max(1, int(ceil(h / 8)))


# WOTS

def wots_l(w, ots_type):
    """Number of WOTS chains: l1 for WOTS+C, l1 + l2 for WOTS-TW."""
    l1, l2 = wots_lengths(w)
    return int(l1) if ots_type == OTS_WC else int(l1 + l2)


def wots_pk_C(w, ots_type):
    """Compressions to compute one WOTS public key."""
    l = wots_l(w, ots_type)
    return l * C_PRF + l * (w - 1) * C_Th1 + compute_Th(l)


def wots_tw_verify_steps(w, count=1):
    """Mean chain steps to verify count WOTS-TW signatures, rounded once."""
    l1, l2 = wots_lengths(w)
    return int(compute_wots_tw_mean_steps(l1, l2, w, count))


def wots_tw_sign_steps(w):
    """Mean chain steps to produce one WOTS-TW signature: the part of each
    chain the verifier does not walk."""
    return wots_l(w, OTS_TW) * (w - 1) - wots_tw_verify_steps(w)


def wots_sign_C(w, swn, ots_type):
    """Mean compressions to produce one WOTS signature."""
    l = wots_l(w, ots_type)
    if ots_type == OTS_WC:
        nu     = compute_nu(l, swn, w)
        search = int((w**l + nu - 1) // nu)
        return search * C_Th1c + l * C_PRF + swn * C_Th1
    return l * C_PRF + wots_tw_sign_steps(w) * C_Th1


def wots_verify_C(w, swn, ots_type, worst_case=False, count=1):
    """Compressions to verify count WOTS signatures: the chain steps, the
    public-key compression and, for WOTS+C, the counter hash."""
    l   = wots_l(w, ots_type)
    Thl = compute_Th(l)

    if ots_type == OTS_WC:
        return count * (((w - 1) * l - swn) * C_Th1 + C_Th1c + Thl)

    if worst_case:
        l1, l2 = wots_lengths(w)
        return count * (compute_wots_tw_worst_steps(l1, l2, w) * C_Th1 + Thl)

    return wots_tw_verify_steps(w, count) * C_Th1 + count * Thl


# XMSS and XMSS-MT: d layers of trees of height h' = h/d, XMSS is d = 1.
# BDS bounds and state: docs/model.md, XMSS and XMSS-MT.

def bds_k(h_prime):
    """Smallest BDS parameter K for a tree of height h_prime."""
    if h_prime < 2:
        return h_prime
    return 2 if h_prime % 2 == 0 else 3


def bds_leaves(h_prime):
    """Leaf computations per BDS update, at most."""
    return (h_prime - bds_k(h_prime)) // 2 + 1


def bds_hashes(h_prime):
    """Node hashes per BDS update, at most."""
    return (3 * max(0, h_prime - bds_k(h_prime) - 1)) // 2 + 1


def bds_state_nodes(h_prime):
    """Nodes a BDS signer stores, at most: authentication path, keep, retain,
    and the treehash instances with their stacks."""
    k = bds_k(h_prime)
    return (h_prime + h_prime // 2 + (2**k - k - 1)
            + max(0, h_prime - k) + max(0, h_prime - k - 1))


def tree_size_per_layer(h_prime, w, ots_type):
    l   = wots_l(w, ots_type)
    ctr = counter_bytes(w) if ots_type == OTS_WC else 0
    return h_prime * N + l * N + ctr


def tree_keygen_C(h_prime, w, ots_type):
    pk = wots_pk_C(w, ots_type)
    sz = 2**h_prime
    return sz * pk + (sz - 1) * C_Th2


def tree_verify_C(h_prime, w, swn, ots_type, worst_case=False, count=1):
    return (wots_verify_C(w, swn, ots_type, worst_case, count)
            + count * h_prime * C_Th2)


def xmssmt_size_h(h, d, w, ots_type):
    h_prime = h // d
    return (IND_SIZE + R_SIZE + idx_bytes(h)
            + d * tree_size_per_layer(h_prime, w, ots_type))


def xmssmt_keygen_C_h(h, d, w, ots_type):
    h_prime = h // d
    return int(tree_keygen_C(h_prime, w, ots_type))


def xmssmt_sign_bds_C_h(h, d, w, swn, ots_type):
    """Cached signer: one BDS update per layer and signature, at most."""
    h_prime = h // d
    pk      = wots_pk_C(w, ots_type)
    c_sg    = wots_sign_C(w, swn, ots_type)

    return float(C_Hmsg + C_PRFmsg + c_sg
                 + d * (bds_leaves(h_prime) * pk + bds_hashes(h_prime) * C_Th2))


def xmssmt_sign_cold_C_h(h, d, w, swn, ots_type):
    """Cold signer: rebuilds the d trees for every signature. In the top tree
    it needs only the authentication path, so it skips the signing leaf and
    the h' nodes above it."""
    h_prime = h // d
    return int(C_Hmsg + C_PRFmsg +
               d * (int(tree_keygen_C(h_prime, w, ots_type)) +
                    wots_sign_C(w, swn, ots_type))
               - wots_pk_C(w, ots_type) - h_prime * C_Th2)


def xmssmt_state_bytes(h, d, w, ots_type):
    """Cached-signer state: the BDS state of every layer and the WOTS
    signatures of the upper layers."""
    h_prime = h // d
    l = wots_l(w, ots_type)
    return int(d * bds_state_nodes(h_prime) * N + (d - 1) * l * N)


def xmssmt_verify_C_h(h, d, w, swn, ots_type, worst_case=False):
    h_prime = h // d
    return float(C_Hmsg + tree_verify_C(h_prime, w, swn, ots_type, worst_case, d))


def compute_tree_rows(scheme, h, d_values):
    rows = []
    for ots_type, w, swn in PARAM_SETS:
        for d in d_values:
            rows.append(dict(
                scheme   = scheme,
                h=h, q_s_log2=h, d=d, h_prime=h // d,
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


# UXMSS: a spine of height hsf with hsf + 1 leaves (docs/model.md, UXMSS)

def _uxmss_idx_bytes(depth):
    """Bytes of the leaf index, ceil(min(depth, 64) / 8): SHRINCS sizes the
    field by the depth of the signing leaf, although an unbalanced-tree
    index is only ever 0 or 1."""
    return max(1, (min(int(depth), 64) + 7) // 8)


def uxmss_size(q, hsf, w, ots_type):
    """Size of the q-th UXMSS signature (q = 1 is the first)."""
    l     = wots_l(w, ots_type)
    ctr   = counter_bytes(w) if ots_type == OTS_WC else 0
    depth = min(q, hsf)
    return IND_SIZE + R_SIZE + _uxmss_idx_bytes(depth) + ctr + l * N + depth * N


def find_max_hsf(w, ots_type, target_size):
    """Largest hsf up to HSF_MAX whose last signature is below target_size."""
    for hsf in range(HSF_MAX, 0, -1):
        if uxmss_size(hsf, hsf, w, ots_type) < target_size:
            return hsf
    return 0


def uxmss_keygen_C(hsf, w, ots_type):
    return float((hsf + 1) * wots_pk_C(w, ots_type) + hsf * C_Th2)


def uxmss_sign_C(q, hsf, w, swn, ots_type):
    """Cached signer, q-th signature. It keeps the hsf + 1 leaf public keys;
    the spine sibling of the signing leaf takes hsf - q node hashes."""
    return float(C_Hmsg + C_PRFmsg + wots_sign_C(w, swn, ots_type)
                 + (hsf - min(q, hsf)) * C_Th2)


def uxmss_sign_cold_C(hsf, w, swn, ots_type):
    """Cold signer, first signature (the most expensive): the hsf other
    leaves, then as the cached signer."""
    return float(uxmss_sign_C(1, hsf, w, swn, ots_type)
                 + hsf * wots_pk_C(w, ots_type))


def uxmss_state_bytes(hsf):
    """Cached-signer state: the hsf + 1 leaf public keys."""
    return int((hsf + 1) * N)


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


# CSV

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
    """A float for the CSV, empty for NaN."""
    if isinstance(v, float) and math.isnan(v):
        return ""
    return "{:.6e}".format(float(v))


def _tree_csv_row(r):
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
    """Writes the rows to dest (a file or sys.stdout) and returns their number."""
    writer = csv.writer(dest)
    writer.writerow(_CSV_HEADER)
    total = 0
    for by_h in (xmss_by_h, xmssmt_by_h):
        for h in H_VALS:
            for r in by_h.get(h, []):
                writer.writerow(_tree_csv_row(r)); total += 1
    for h in UXMSS_H_VALS:
        for r in uxmss_by_h.get(h, []):
            writer.writerow(_uxmss_csv_row(r)); total += 1
    return total


def save_csv_file(path, xmss_by_h, xmssmt_by_h, uxmss_by_h):
    with open(path, 'w', newline='') as f:
        n = write_csv(f, xmss_by_h, xmssmt_by_h, uxmss_by_h)
    print("Saved {} data rows to {!r}".format(n, path), file=sys.stderr)


# Tables

def fmt_c(n):
    """A compression count with a K, M, G or T suffix."""
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


OTS_LINE = " OTS: WOTS-TW / WOTS+C  |  w ∈ {{{}}} ".format(",".join(str(w) for w in WOTS_W_VALS))


def print_xmss_table(rows_by_h):
    cols = [("q_s", 4, ">"), ("OTS Variant", 26, "<"), ("l", 3, ">"),
            ("Size(B)", 7, ">"), ("Keygen(C)", 11, ">"),
            ("Sign-BDS(C)", 11, ">"), ("Vfy-avg(C)", 10, ">"), ("Vfy-wrst(C)", 11, ">")]
    W = sum(c[1] for c in cols) + len(cols) - 1
    print()
    print("="*W)
    print(" XMSS — Single-Layer Balanced Tree ".center(W, "="))
    print(OTS_LINE.center(W, "="))
    print(" Auth path = h nodes (fixed per sig); Sign-BDS = bound per sig ".center(W, "="))
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
    print(OTS_LINE.center(W, "="))
    print(" Keygen builds top tree only (2^h' keys); Sign-BDS = bound per sig ".center(W, "="))
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
    print("Sign-cold: rebuild d trees per sig (worst-case). BDS: at most d·((h'-K)/2 + 1) PK evals per sig.")
    print()


def print_uxmss_table(rows_by_h, ref_size):
    cols = [("OTS Variant", 26, "<"), ("l", 3, ">"),
            ("Ref(B)", 6, ">"), ("hsf", 5, ">"), ("Sigs", 7, ">"),
            ("Sz(q=1)", 8, ">"), ("Sz(max)", 8, ">"),
            ("Keygen(C)", 10, ">"), ("Sign(q=1)", 9, ">"),
            ("VfyAvg(mx)", 10, ">"), ("VfyWrst(mx)", 11, ">")]
    W = sum(c[1] for c in cols) + len(cols) - 1
    print()
    print("="*W)
    print(" SHRINCS/UXMSS — Left-leaning Stateful Tree ".center(W, "="))
    print(OTS_LINE.center(W, "="))
    print(" max stateful sig must be strictly < Ref ".center(W, "="))
    print("="*W)
    print(_hdr(cols)); print(_sep_line(cols))
    for h in UXMSS_H_VALS:
        for r in rows_by_h.get(h, []):
            print(_row([r['label'], r['l'], ref_size,
                        r['hsf'], r['nsig'], r['sz_q1'], r['sz_max'],
                        fmt_c(r['keygen_C']), fmt_c(r['sign_q1_C']),
                        fmt_c(r['verify_max_avg_C']), fmt_c(r['verify_max_worst_C'])], cols))
        print()
    print(_sep_line(cols))
    print("Ref: the size of the report's candidate 2, (h, d, k, a, w) = (45, 5, 8, 16, 16).")
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


# export_site_data.sage sets STATEFUL_SAGE_NO_MAIN: load() runs this file with
# __name__ == '__main__'.
if __name__ == "__main__" and not os.environ.get("STATEFUL_SAGE_NO_MAIN"):
    do_csv, xmss_only, xmssmt_only, uxmss_only, show_detail, output_file = _parse_args(sys.argv)
    ref_size = PARAMETERS['stateful']['uxmss_ref_size']

    xmss_by_h   = {h: compute_tree_rows("XMSS", h, [1]) for h in H_VALS}
    xmssmt_by_h = {h: compute_tree_rows("XMSS-MT", h, [d for d in range(2, h + 1) if h % d == 0])
                   for h in H_VALS}
    uxmss_by_h  = {h: compute_uxmss_rows(ref_size, h) for h in UXMSS_H_VALS}

    if do_csv:
        write_csv(sys.stdout, xmss_by_h, xmssmt_by_h, uxmss_by_h)

    if output_file:
        save_csv_file(output_file, xmss_by_h, xmssmt_by_h, uxmss_by_h)

    if not do_csv:
        if not xmssmt_only and not uxmss_only:
            print_xmss_table(xmss_by_h)
        if not xmss_only and not uxmss_only:
            print_xmssmt_table(xmssmt_by_h)
        if not xmss_only and not xmssmt_only:
            print_uxmss_table(uxmss_by_h, ref_size)
        if show_detail and not xmss_only and not xmssmt_only:
            print_uxmss_detail(uxmss_by_h)
