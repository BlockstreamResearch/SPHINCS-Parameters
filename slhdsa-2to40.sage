#!/usr/bin/env sage
"""
Sweeps the stateless grid of parameters.json for one scheme, keeps the parameter
sets that reach the security target and pass the filters, prints them against
SLH-DSA-128s, and writes them to candidates.csv, SLH-DSA-128s first as STANDARD.
make sweeps runs it twice for utils/all_size_capped_candidates.csv and
utils/all_unbound_candidates.csv.

  sage slhdsa-2to40.sage [--ots wots-tw|wots+c] [--fts fors|fors+c|pors+fp] [filters]
  sage slhdsa-2to40.sage --help
"""
import csv
import os
import sys

os.environ['COSTS_SAGE_NO_MAIN'] = '1'   # its functions, without its CLI
load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "costs.sage"))

GRID = PARAMETERS['stateless']['grid']

USAGE = """usage: sage slhdsa-2to40.sage [options]

  --ots wots-tw|wots+c         the one-time signature (default wots-tw); wots+c
                               sweeps the w of wc_w with their S_wn
  --fts fors|fors+c|pors+fp    the few-time signature (default fors); wots-tw
                               goes with fors only
  --h N1,N2,...                hypertree heights (default: the grid)
  --d N1,N2,...                layers (default: the grid); d must divide h
  --max-size BYTES             keep sizes below BYTES (default: the grid's max_size)
  --max-keygen-ratio X         keep KeyGen up to X times that of SLH-DSA-128s
  --max-sign-ratio X           the same for SigGen
  --max-verify-ratio X         the same for SigVer
  --max-c-per-byte X           keep SigVer compressions per byte up to X
  --max-cpb-ratio X            keep them up to X times those of SLH-DSA-128s

The filters other than the size have no limit by default.
"""


def _parse_int_list(s):
    return [int(x) for x in s.split(",") if x.strip()]

def _parse_args(argv):
    ots = "wots-tw"
    fts = "fors"
    max_size = GRID['max_size']
    kg_ratio = float('inf')
    sg_ratio = float('inf')
    sv_ratio = float('inf')
    cpb_max  = float('inf')
    cpb_ratio = float('inf')
    h_values = list(range(GRID['h'][0], GRID['h'][1] + 1))
    d_values = list(range(GRID['d'][0], GRID['d'][1] + 1))
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
        elif a == "--max-c-per-byte" and i + 1 < len(argv):
            cpb_max = float(argv[i + 1])
            i += 2
        elif a == "--max-cpb-ratio" and i + 1 < len(argv):
            cpb_ratio = float(argv[i + 1])
            i += 2
        elif a == "--h" and i + 1 < len(argv):
            h_values = _parse_int_list(argv[i + 1])
            i += 2
        elif a == "--d" and i + 1 < len(argv):
            d_values = _parse_int_list(argv[i + 1])
            i += 2
        elif a == "--help":
            print(USAGE)
            sys.exit(0)
        else:
            print("Unknown argument: {}".format(a), file=sys.stderr)
            print("Use --help for usage.", file=sys.stderr)
            sys.exit(2)
    return ots, fts, max_size, kg_ratio, sg_ratio, sv_ratio, cpb_max, cpb_ratio, h_values, d_values

(OTS, FTS, MAX_SIZE,
 MAX_KEYGEN_RATIO, MAX_SIGN_RATIO, MAX_VERIFY_RATIO,
 MAX_C_PER_BYTE, MAX_CPB_RATIO, H_VALUES, D_VALUES) = _parse_args(sys.argv)

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

if OTS == "wots-tw":
    W_SWN_PAIRS = [(w, 0) for w in GRID['w']]
else:  # wots+c
    W_SWN_PAIRS = [(w, SWN[w]) for w in PARAMETERS['stateless']['wc_w']]

# Every scheme is compared with SLH-DSA-128s
STD_SCHEME = "SPX"
STD_SWN    = 0

K_RANGE  = range(GRID['k'][0], GRID['k'][1] + 1)
A_RANGE  = range(GRID['a'][0], GRID['a'][1] + 1)


def csv_row(q_s_log2, r):
    """The CSV fields of an evaluate() result."""
    return {
        'q_s_log2': int(q_s_log2),
        'h':        int(r['h']),
        'd':        int(r['d']),
        'h_prime':  int(r['h'] // r['d']),
        'k':        int(r['k']),
        'a':        int(r['a']),
        'w':        int(r['w']),
        'l':        int(r['l']),
        'swn':      int(r['swn']),
        'mmax':     int(r['mmax']),
        'security': float(r['security']),
        'size':     int(r['size']),
        'keygen_C': float(r['keygen']),
        'sign_C':   float(r['sign']),
        'verify_C': float(r['verify']),
        'verify_worst_C': float(r['verify_worst']),
        'c_per_byte': float(r['verify']) / float(r['size']),
        'c_per_byte_worst': float(r['verify_worst']) / float(r['size']),
        'label':    '',
    }


print("Variant: ots={}, fts={}  -> scheme={}".format(OTS, FTS, SCHEME), file=sys.stderr)
print("Computing standard SLH-DSA-128s baseline (SPX)...", file=sys.stderr)
B = PARAMETERS['baseline']
std = evaluate(B['q_s_log2'], B['h'], B['d'], B['k'], B['a'], B['w'], STD_SWN, STD_SCHEME)
if std is None:
    print("ERROR: failed to compute standard baseline.", file=sys.stderr)
    sys.exit(1)
std = csv_row(B['q_s_log2'], std)
std['label'] = 'STANDARD'

KEYGEN_LIMIT = std['keygen_C'] * MAX_KEYGEN_RATIO
SIGN_LIMIT   = std['sign_C']   * MAX_SIGN_RATIO
VERIFY_LIMIT = std['verify_C'] * MAX_VERIFY_RATIO
CPB_LIMIT    = min(MAX_C_PER_BYTE, std['c_per_byte'] * MAX_CPB_RATIO)

print("Standard baseline (compressions):", file=sys.stderr)
print("  Keygen: {:.0f} C  (limit: {:.0f} C)".format(std['keygen_C'], KEYGEN_LIMIT), file=sys.stderr)
print("  Sign:   {:.0f} C  (limit: {:.0f} C)".format(std['sign_C'],   SIGN_LIMIT),   file=sys.stderr)
print("  Verify: {:.0f} C  (limit: {:.0f} C)".format(std['verify_C'], VERIFY_LIMIT), file=sys.stderr)

print("Sweeping {} configurations...".format(SCHEME), file=sys.stderr)
all_results = [std]

rejected = {'security': 0, 'size': 0, 'keygen': 0, 'sign': 0, 'verify': 0, 'c_per_byte': 0}
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
    if r['c_per_byte'] > CPB_LIMIT:
        rejected['c_per_byte'] += 1
        return
    r['label'] = label
    all_results.append(r)


def label_for(w, swn):
    if OTS == "wots-tw":
        return "w={}".format(w)
    return "w={},swn={}".format(w, swn)


for (w, swn, h, d, k, a), r in sweep(SCHEME, W_SWN_PAIRS, H_VALUES, D_VALUES,
                                      K_RANGE, A_RANGE, GRID['q_s_log2']):
    consider(None if r is None else csv_row(GRID['q_s_log2'], r), label_for(w, swn))

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


# Only WOTS+C labels and rows carry S_wn
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
print("  SLH-DSA-128s vs {} variants (h in {}, d in {})  ".format(
    SCHEME, H_VALUES, D_VALUES).center(total_width))
print("  ots={}, fts={}  ".format(OTS, FTS).center(total_width))
def _ratio_str(r):
    return "no limit" if r == float('inf') else "<= {:g}x std".format(r)
def _cpb_str(x):
    return "no limit" if x == float('inf') else "<= {:g}".format(x)
print("  Filters: size < {} B, keygen {}, sign {}, verify {}, C/byte {}  ".format(
    MAX_SIZE,
    _ratio_str(MAX_KEYGEN_RATIO), _ratio_str(MAX_SIGN_RATIO), _ratio_str(MAX_VERIFY_RATIO),
    _cpb_str(CPB_LIMIT)
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

print("=" * total_width)
print("  FILTER REJECTION SUMMARY  ".center(total_width))
print("=" * total_width)
print()
def _rej_label(name, ratio):
    if ratio == float('inf'):
        return " Rejected ({} > no limit):       ".format(name)
    return " Rejected ({} > {:g}x std):     ".format(name, ratio)

print(" Considered configurations:        {}".format(considered))
print(" Rejected (security < {}):        {}".format(PARAMETERS['security_bits'], rejected['security']))
print(" Rejected (size >= {} B):         {}".format(MAX_SIZE, rejected['size']))
print("{}{}".format(_rej_label("keygen", MAX_KEYGEN_RATIO), rejected['keygen']))
print("{}{}".format(_rej_label("sign",   MAX_SIGN_RATIO),   rejected['sign']))
print("{}{}".format(_rej_label("verify", MAX_VERIFY_RATIO), rejected['verify']))
if CPB_LIMIT == float('inf'):
    print(" Rejected (C/byte > no limit):     {}".format(rejected['c_per_byte']))
else:
    print(" Rejected (C/byte > {:g}):           {}".format(CPB_LIMIT, rejected['c_per_byte']))
print(" Passed all filters (custom):      {}".format(len(all_results) - 1))
print()

print("=" * total_width)
print("  SUMMARY  ".center(total_width))
print("=" * total_width)

print()
print("Standard SLH-DSA-128s baseline:")
print("  Size:   {} B".format(std['size']))
print("  Keygen: {} C".format(fmt_num(std['keygen_C'])))
print("  Sign:   {} C".format(fmt_num(std['sign_C'])))
print("  Verify: {} C".format(fmt_num(std['verify_C'])))
print("  C/byte: {:.2f}".format(std['c_per_byte']))


def describe(label, results):
    if not results:
        print()
        print("Best {}: (no configurations pass all filters)".format(label))
        return
    smallest     = min(results, key=lambda x: x['size'])
    fastest_sign = min(results, key=lambda x: x['sign_C'])
    fastest_kg   = min(results, key=lambda x: x['keygen_C'])
    lowest_cpb   = min(results, key=lambda x: x['c_per_byte'])
    print()
    print("Best {}:".format(label))

    def _print(title, r):
        print("  {:<16} d={}, k={}, a={}  ->  {} B  ({} vs std)".format(
            title, r['d'], r['k'], r['a'], r['size'], fmt_pct(r['size'])))
        print("                   KG: {} C ({})  Sign: {} C ({})  Verify: {} C ({})  C/byte: {:.2f}".format(
            fmt_num(r['keygen_C']), fmt_ratio(r['keygen_C'], std['keygen_C']),
            fmt_num(r['sign_C']),   fmt_ratio(r['sign_C'],   std['sign_C']),
            fmt_num(r['verify_C']), fmt_ratio(r['verify_C'], std['verify_C']),
            r['c_per_byte']))

    _print("Smallest sig:",    smallest)
    _print("Fastest sign:",    fastest_sign)
    _print("Fastest keygen:",  fastest_kg)
    _print("Lowest C/byte:",   lowest_cpb)


for w, swn in W_SWN_PAIRS:
    label = label_for(w, swn)
    if OTS == "wots-tw" and w == 16:
        note = " (FIPS 205-compatible algorithm structure)"
    elif OTS == "wots-tw":
        note = " (modified SPHINCS+, not FIPS 205)"
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
    print("  - swn is the WOTS+C target chain sum S_{w,n}, from parameters.json.")
print("  - Sweep ranges: h in {}, d in {}, k in [{}, {}], a in [{}, {}], (w,swn) in {}.".format(
    H_VALUES, D_VALUES, K_RANGE.start, K_RANGE.stop - 1, A_RANGE.start, A_RANGE.stop - 1, W_SWN_PAIRS))

csv_filename = "candidates.csv"
print("\nSaving candidate configurations to {}...".format(csv_filename))

fieldnames = [
    'label', 'h', 'd', 'h_prime', 'k', 'a', 'w', 'l',
    'swn', 'mmax', 'security', 'size', 'keygen_C',
    'sign_C', 'verify_C', 'verify_worst_C', 'c_per_byte', 'c_per_byte_worst'
]

with open(csv_filename, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in all_results:
        writer.writerow({k: r[k] for k in fieldnames})

print("Successfully saved {} candidates to {}.".format(len(all_results), csv_filename))