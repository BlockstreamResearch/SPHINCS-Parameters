#!/usr/bin/env sage
"""
Standard SLH-DSA-128s VS custom (h=40) variants sweeping (d, k, a) for various OTS/FTS combinations.

Variant is selected via --ots and --fts flags:
  --ots {wots-tw, wots+c}        (default: wots-tw)
  --fts {fors, fors+c, pors+fp}  (default: fors)

Supported (ots, fts) combinations:
  (wots-tw, fors)    -> SPX        (plain SLH-DSA / SPHINCS+)
  (wots+c, fors)     -> W+C
  (wots+c, fors+c)   -> W+C_F+C
  (wots+c, pors+fp)  -> W+C_P+FP

Sweep behavior per OTS:
  - wots-tw : w in {16, 32}, swn = 0
  - wots+c  : (w, swn) in {(16, 240), (256, 2040)}

Filters (defaults; override via CLI):
  --max-size BYTES         Reject if size >= BYTES                (default: 7856, std SLH-DSA-128s size)
  --max-keygen-ratio X     Reject if keygen  > X * std keygen     (default: no limit)
  --max-sign-ratio X       Reject if sign    > X * std sign       (default: no limit)
  --max-verify-ratio X     Reject if verify  > X * std verify     (default: no limit)

Usage:
  sage slhdsa-2to40.sage                                  # default (SPX)
  sage slhdsa-2to40.sage --ots wots+c --fts pors+fp       # W+C_P+FP variant
  sage slhdsa-2to40.sage --ots wots+c --fts fors+c        # W+C_F+C variant
  sage slhdsa-2to40.sage --max-size 4500 --max-keygen-ratio 10 --max-sign-ratio 10
"""
import os
import sys

# -----------------------------------------------------------------------------
# CLI parsing (parse before loading costs.sage so we can suppress its CSV)
# -----------------------------------------------------------------------------

def _parse_args(argv):
    ots = "wots-tw"
    fts = "fors"
    max_size = 7856      # std SLH-DSA-128s signature size
    kg_ratio = float('inf')
    sg_ratio = float('inf')
    sv_ratio = float('inf')
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--ots" and i + 1 < len(argv):
            ots = argv[i + 1].lower()
            i += 2
        elif a == "--fts" and i + 1 < len(argv):
            fts = argv[i + 1].lower()
            i += 2
        elif a == "--max-size" and i + 1 < len(argv):
            max_size = int(argv[i + 1])
            i += 2
        elif a == "--max-keygen-ratio" and i + 1 < len(argv):
            kg_ratio = float(argv[i + 1])
            i += 2
        elif a == "--max-sign-ratio" and i + 1 < len(argv):
            sg_ratio = float(argv[i + 1])
            i += 2
        elif a == "--max-verify-ratio" and i + 1 < len(argv):
            sv_ratio = float(argv[i + 1])
            i += 2
        elif a in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        else:
            print("Unknown argument: {}".format(a), file=sys.stderr)
            print("Use --help for usage.", file=sys.stderr)
            sys.exit(2)
    return ots, fts, max_size, kg_ratio, sg_ratio, sv_ratio

OTS, FTS, MAX_SIZE, MAX_KEYGEN_RATIO, MAX_SIGN_RATIO, MAX_VERIFY_RATIO = _parse_args(sys.argv)

SCHEME_MAP = {
    ("wots-tw", "fors"):    "SPX",
    ("wots+c",  "fors"):    "W+C",
    ("wots+c",  "fors+c"):  "W+C_F+C",
    ("wots+c",  "pors+fp"): "W+C_P+FP",
}
if (OTS, FTS) not in SCHEME_MAP:
    print("Unsupported (ots, fts) combination: ({}, {})".format(OTS, FTS), file=sys.stderr)
    print("Supported:", list(SCHEME_MAP.keys()), file=sys.stderr)
    sys.exit(2)
SCHEME = SCHEME_MAP[(OTS, FTS)]

# (w, swn) sweep pairs depend on OTS
if OTS == "wots-tw":
    W_SWN_PAIRS = [(16, 0), (32, 0), (256, 0)]
else:  # wots+c
    W_SWN_PAIRS = [(16, 240), (256, 2040)]

# Security model: PORS+FP for that FTS, FORS otherwise
SECURITY_MODEL = "PORS+FP" if FTS == "pors+fp" else "FORS"

# -----------------------------------------------------------------------------
# Load costs.sage (suppress its auto-CSV)
# -----------------------------------------------------------------------------
_saved_argv = sys.argv
sys.argv = ['big_comparison.sage', '--no-auto']
load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "costs.sage"))
sys.argv = _saved_argv

# -----------------------------------------------------------------------------
# Sweep parameters
# -----------------------------------------------------------------------------

TARGET = 128

# Standard baseline is plain SLH-DSA-128s (SPX) for fair comparison
STD_SCHEME = "SPX"
STD_SWN    = 0

K_RANGE  = range(6, 25)
A_RANGE  = range(8, 21)
D_VALUES = [2, 4, 5, 8]


def evaluate(q_s_log2, h, d, k, a, w, swn, scheme, security_model):
    if h % d != 0:
        return None
    q_s = 2**q_s_log2
    try:
        security = compute_security(q_s, h, k, a, security_model, hashbytes=16)
    except Exception:
        return None
    if float(security) < TARGET:
        return None

    try:
        sign = compute_signing_time(h, d, a, k, w, swn, scheme)
    except Exception:
        return None
    mmax     = sign['mmax']
    verify   = compute_verification_time(h, d, a, k, w, swn, scheme, mmax)
    keygen_C = compute_keygen_time(h, d, w, scheme)
    size     = compute_size(h, d, a, k, w, scheme, mmax)
    l        = compute_wots_l(scheme, w)

    return {
        'q_s_log2': int(q_s_log2),
        'h':        int(h),
        'd':        int(d),
        'h_prime':  int(h // d),
        'k':        int(k),
        'a':        int(a),
        'w':        int(w),
        'l':        int(l),
        'swn':      int(swn),
        'mmax':     int(mmax),
        'security': float(security),
        'size':     int(size),
        'keygen_C': float(keygen_C),
        'sign_C':   float(sign['compressions']),
        'verify_C': float(verify['compressions']),
        'c_per_byte': float(verify['compressions']) / float(size),
        'label':    '',
    }


print("Variant: ots={}, fts={}  -> scheme={}".format(OTS, FTS, SCHEME), file=sys.stderr)
print("Computing standard SLH-DSA-128s baseline (SPX)...", file=sys.stderr)
std = evaluate(64, 63, 7, 14, 12, 16, STD_SWN, STD_SCHEME, "FORS")
if std is None:
    print("ERROR: failed to compute standard baseline.", file=sys.stderr)
    sys.exit(1)
std['label'] = 'STANDARD'

KEYGEN_LIMIT = std['keygen_C'] * MAX_KEYGEN_RATIO
SIGN_LIMIT   = std['sign_C']   * MAX_SIGN_RATIO
VERIFY_LIMIT = std['verify_C'] * MAX_VERIFY_RATIO

print("Standard baseline (compressions):", file=sys.stderr)
print("  Keygen: {:.0f} C  (limit: {:.0f} C)".format(std['keygen_C'], KEYGEN_LIMIT), file=sys.stderr)
print("  Sign:   {:.0f} C  (limit: {:.0f} C)".format(std['sign_C'],   SIGN_LIMIT),   file=sys.stderr)
print("  Verify: {:.0f} C  (limit: {:.0f} C)".format(std['verify_C'], VERIFY_LIMIT), file=sys.stderr)

print("Sweeping {} configurations...".format(SCHEME), file=sys.stderr)
all_results = [std]

rejected = {'security': 0, 'size': 0, 'keygen': 0, 'sign': 0, 'verify': 0}
considered = 0


def consider(r, label):
    global considered
    considered += 1
    if r is None:
        rejected['security'] += 1
        return
    if r['size'] >= MAX_SIZE:
        rejected['size'] += 1
        return
    if r['keygen_C'] > KEYGEN_LIMIT:
        rejected['keygen'] += 1
        return
    if r['sign_C'] > SIGN_LIMIT:
        rejected['sign'] += 1
        return
    if r['verify_C'] > VERIFY_LIMIT:
        rejected['verify'] += 1
        return
    r['label'] = label
    all_results.append(r)


def label_for(w, swn):
    if OTS == "wots-tw":
        return "w={}".format(w)
    return "w={},swn={}".format(w, swn)


for w, swn in W_SWN_PAIRS:
    label = label_for(w, swn)
    for d in D_VALUES:
        for k in K_RANGE:
            for a in A_RANGE:
                consider(
                    evaluate(40, 40, d, k, a, w, swn, SCHEME, SECURITY_MODEL),
                    label,
                )

all_results.sort(key=lambda x: x['size'])


def fmt_num(n):
    n = float(n)
    if n >= 1_000_000_000:
        return "{:.2f}G".format(n / 1_000_000_000)
    if n >= 1_000_000:
        return "{:.2f}M".format(n / 1_000_000)
    if n >= 1_000:
        return "{:.1f}K".format(n / 1_000)
    return "{}".format(int(n))


def fmt_pct(size):
    pct = (float(size) / float(std['size']) - 1.0) * 100.0
    return "{:+.1f}%".format(pct)


def fmt_ratio(r, std_val):
    return "{:.2f}x".format(float(r) / float(std_val))


# Use a wider Label column when swn is included; show S_wn column only for W+C
label_w = 12 if OTS == "wots+c" else 10

columns = [
    ("Label",     lambda r: r['label'],                                label_w, '<'),
    ("h",         lambda r: str(r['h']),                                3, '>'),
    ("d",         lambda r: str(r['d']),                                2, '>'),
    ("h'",        lambda r: str(r['h_prime']),                         3, '>'),
    ("k",         lambda r: str(r['k']),                                3, '>'),
    ("a",         lambda r: str(r['a']),                                3, '>'),
    ("w",         lambda r: str(r['w']),                                4, '>'),
    ("l",         lambda r: str(r['l']),                                3, '>'),
]
if OTS == "wots+c":
    columns.append(("S_wn", lambda r: str(r['swn']), 5, '>'))
columns += [
    ("Sec",       lambda r: "{:.1f}".format(r['security']),             6, '>'),
    ("Size(B)",   lambda r: str(r['size']),                             7, '>'),
    ("vs.std",    lambda r: fmt_pct(r['size']),                         7, '>'),
    ("Keygen(C)", lambda r: fmt_num(r['keygen_C']),                     9, '>'),
    ("KG/std",    lambda r: fmt_ratio(r['keygen_C'], std['keygen_C']),  6, '>'),
    ("Sign(C)",   lambda r: fmt_num(r['sign_C']),                       8, '>'),
    ("SG/std",    lambda r: fmt_ratio(r['sign_C'], std['sign_C']),      6, '>'),
    ("Verify(C)", lambda r: fmt_num(r['verify_C']),                     9, '>'),
    ("SV/std",    lambda r: fmt_ratio(r['verify_C'], std['verify_C']),  6, '>'),
    ("C/byte",    lambda r: "{:.2f}".format(r['c_per_byte']),           6, '>'),
]

total_width = sum(col_w for _, _, col_w, _ in columns) + len(columns) - 1

print()
print("=" * total_width)
print("  SLH-DSA-128s vs {} variants (h=40, d in {{2,4,5,8}})  ".format(SCHEME).center(total_width))
print("  ots={}, fts={}  ".format(OTS, FTS).center(total_width))
def _ratio_str(r):
    return "no limit" if r == float('inf') else "<= {:g}x std".format(r)
print("  Filters: size < {} B, keygen {}, sign {}, verify {}  ".format(
    MAX_SIZE, _ratio_str(MAX_KEYGEN_RATIO), _ratio_str(MAX_SIGN_RATIO), _ratio_str(MAX_VERIFY_RATIO)
).center(total_width))
print("  All costs in SHA-256 compression-function calls  ".center(total_width))
print("=" * total_width)

header_parts = []
for hdr, _, col_w, align in columns:
    if align == '<':
        header_parts.append("{:<{w}}".format(hdr, w=col_w))
    else:
        header_parts.append("{:>{w}}".format(hdr, w=col_w))
print(" " + " ".join(header_parts))
print("-" * total_width)

for r in all_results:
    parts = []
    for _, fn, col_w, align in columns:
        cell = fn(r)
        if align == '<':
            parts.append("{:<{w}}".format(cell, w=col_w))
        else:
            parts.append("{:>{w}}".format(cell, w=col_w))
    print(" " + " ".join(parts))

print("-" * total_width)
counts_by_label = {}
for r in all_results:
    counts_by_label[r['label']] = counts_by_label.get(r['label'], 0) + 1
parts = ["1 standard"] + [
    "{} {}".format(counts_by_label[k], k) for k in counts_by_label if k != 'STANDARD'
]
print(" Total: {} configurations passing all filters ({})".format(
    len(all_results), " + ".join(parts)))
print()

# Filter rejection summary
print("=" * total_width)
print("  FILTER REJECTION SUMMARY  ".center(total_width))
print("=" * total_width)
print()
def _rej_label(name, ratio):
    if ratio == float('inf'):
        return " Rejected ({} > no limit):       ".format(name)
    return " Rejected ({} > {:g}x std):     ".format(name, ratio)

print(" Considered configurations:        {}".format(considered))
print(" Rejected (security < 128):        {}".format(rejected['security']))
print(" Rejected (size >= {} B):         {}".format(MAX_SIZE, rejected['size']))
print("{}{}".format(_rej_label("keygen", MAX_KEYGEN_RATIO), rejected['keygen']))
print("{}{}".format(_rej_label("sign",   MAX_SIGN_RATIO),   rejected['sign']))
print("{}{}".format(_rej_label("verify", MAX_VERIFY_RATIO), rejected['verify']))
print(" Passed all filters (custom):      {}".format(len(all_results) - 1))
print()

# Summary
print("=" * total_width)
print("  SUMMARY  ".center(total_width))
print("=" * total_width)

print()
print("Standard SLH-DSA-128s baseline:")
print("  Size:   {} B".format(std['size']))
print("  Keygen: {} C".format(fmt_num(std['keygen_C'])))
print("  Sign:   {} C".format(fmt_num(std['sign_C'])))
print("  Verify: {} C".format(fmt_num(std['verify_C'])))


def describe(label, results):
    if not results:
        print()
        print("Best {}: (no configurations pass all filters)".format(label))
        return
    smallest     = min(results, key=lambda x: x['size'])
    fastest_sign = min(results, key=lambda x: x['sign_C'])
    fastest_kg   = min(results, key=lambda x: x['keygen_C'])
    print()
    print("Best {}:".format(label))
    print("  Smallest sig:    d={}, k={}, a={}  ->  {} B  ({} vs std)".format(
        smallest['d'], smallest['k'], smallest['a'],
        smallest['size'], fmt_pct(smallest['size'])))
    print("                   KG: {} C ({})  Sign: {} C ({})  Verify: {} C ({})".format(
        fmt_num(smallest['keygen_C']), fmt_ratio(smallest['keygen_C'], std['keygen_C']),
        fmt_num(smallest['sign_C']),   fmt_ratio(smallest['sign_C'],   std['sign_C']),
        fmt_num(smallest['verify_C']), fmt_ratio(smallest['verify_C'], std['verify_C'])))
    print("  Fastest sign:    d={}, k={}, a={}  ->  {} B  ({} vs std)".format(
        fastest_sign['d'], fastest_sign['k'], fastest_sign['a'],
        fastest_sign['size'], fmt_pct(fastest_sign['size'])))
    print("                   KG: {} C ({})  Sign: {} C ({})  Verify: {} C ({})".format(
        fmt_num(fastest_sign['keygen_C']), fmt_ratio(fastest_sign['keygen_C'], std['keygen_C']),
        fmt_num(fastest_sign['sign_C']),   fmt_ratio(fastest_sign['sign_C'],   std['sign_C']),
        fmt_num(fastest_sign['verify_C']), fmt_ratio(fastest_sign['verify_C'], std['verify_C'])))
    print("  Fastest keygen:  d={}, k={}, a={}  ->  {} B  ({} vs std)".format(
        fastest_kg['d'], fastest_kg['k'], fastest_kg['a'],
        fastest_kg['size'], fmt_pct(fastest_kg['size'])))
    print("                   KG: {} C ({})  Sign: {} C ({})  Verify: {} C ({})".format(
        fmt_num(fastest_kg['keygen_C']), fmt_ratio(fastest_kg['keygen_C'], std['keygen_C']),
        fmt_num(fastest_kg['sign_C']),   fmt_ratio(fastest_kg['sign_C'],   std['sign_C']),
        fmt_num(fastest_kg['verify_C']), fmt_ratio(fastest_kg['verify_C'], std['verify_C'])))


for w, swn in W_SWN_PAIRS:
    label = label_for(w, swn)
    if OTS == "wots-tw" and w == 16:
        note = " (FIPS 205-compatible algorithm structure)"
    elif OTS == "wots-tw":
        note = " (modified SPHINCS+, NOT FIPS 205)"
    else:
        note = ""
    subset = [r for r in all_results if r['label'] == label]
    describe(label + note, subset)

print()
print("Notes:")
print("  - Variant: ots={}, fts={}  (scheme={}).".format(OTS, FTS, SCHEME))
print("  - All cost metrics in SHA-256 compression-function calls (C).")
print("  - All ratios (KG/std, SG/std, SV/std) are relative to standard SLH-DSA-128s.")
print("  - Sec(bits) is capped at 128.0 by the n=128 preimage bound.")
if OTS == "wots+c":
    print("  - swn is the WOTS+C target chain sum S_{w,n}; values mirror PARAMETER_SETS in costs.sage.")
print("  - Sweep ranges: d in {}, k in [{}, {}], a in [{}, {}], (w,swn) in {}.".format(
    D_VALUES, K_RANGE.start, K_RANGE.stop - 1, A_RANGE.start, A_RANGE.stop - 1, W_SWN_PAIRS))
