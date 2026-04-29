#!/usr/bin/env sage
"""
Standard SLH-DSA-128s VS custom (h=40) variants sweeping (d, k, a) for both w=16 and w=32

Filters applied:
  - Size strictly smaller than standard SLH-DSA-128s
  - Keygen <= 3x std
  - Signing <= 3x std
  - Verify <= 3x std
"""
import os
import sys

# Suppress costs.sage's auto-CSV output by hiding sys.argv during load
_saved_argv = sys.argv
sys.argv = ['big_comparison.sage', '--no-auto']
load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "costs.sage"))
sys.argv = _saved_argv

TARGET = 128
SCHEME = "SPX"
SWN    = 0

K_RANGE  = range(6, 25)
A_RANGE  = range(8, 21)
D_VALUES = [2, 4, 5, 8]

STD_SIZE = 7856

MAX_KEYGEN_RATIO = 3.0
MAX_SIGN_RATIO   = 3.0
MAX_VERIFY_RATIO = 3.0

def compute_keygen_cost(h, d, k, a, w, scheme):
    h_prime = h // d
    l       = compute_wots_l(scheme, w)
    Thl     = compute_Th(l)

    leaves = 2**h_prime
    h_per_leaf = l + l*(w-1) + 1
    c_per_leaf = l*C_PRF + l*(w-1)*C_Th1 + Thl

    h_keygen = leaves * h_per_leaf + (leaves - 1)
    c_keygen = leaves * c_per_leaf + (leaves - 1)*C_Th2

    return {'hashes': h_keygen, 'compressions': c_keygen}

def evaluate(q_s_log2, h, d, k, a, w):
    q_s = 2**q_s_log2
    try:
        security = compute_security(q_s, h, k, a, "FORS", hashbytes=16)
    except Exception:
        return None
    if float(security) < TARGET:
        return None

    sign   = compute_signing_time(h, d, a, k, w, SWN, SCHEME)
    verify = compute_verification_time(h, d, a, k, w, SWN, SCHEME, sign['mmax'])
    keygen = compute_keygen_cost(h, d, k, a, w, SCHEME)
    size   = compute_size(h, d, a, k, w, SCHEME, sign['mmax'])
    l      = compute_wots_l(SCHEME, w)

    return {
        'q_s_log2': int(q_s_log2),
        'h':        int(h),
        'd':        int(d),
        'h_prime':  int(h // d),
        'k':        int(k),
        'a':        int(a),
        'w':        int(w),
        'l':        int(l),
        'security': float(security),
        'size':     int(size),
        'keygen_C': float(keygen['compressions']),
        'sign_C':   float(sign['compressions']),
        'verify_C': float(verify['compressions']),
        'c_per_byte': float(verify['compressions']) / float(size),
        'label':    '',
    }

print("Computing standard SLH-DSA-128s baseline...", file=sys.stderr)
std = evaluate(64, 63, 7, 14, 12, 16)
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

print("Sweeping configurations...", file=sys.stderr)
all_results = [std]

rejected = {'security': 0, 'size': 0, 'keygen': 0, 'sign': 0, 'verify': 0}
considered = 0

def consider(r, label):
    global considered
    considered += 1
    if r is None:
        rejected['security'] += 1
        return
    if r['size'] >= STD_SIZE:
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

for d in D_VALUES:
    for k in K_RANGE:
        for a in A_RANGE:
            consider(evaluate(40, 40, d, k, a, 16), 'w=16')

for d in D_VALUES:
    for k in K_RANGE:
        for a in A_RANGE:
            consider(evaluate(40, 40, d, k, a, 32), 'w=32')

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
    pct = (float(size) / float(STD_SIZE) - 1.0) * 100.0
    return "{:+.1f}%".format(pct)

def fmt_ratio(r, std_val):
    return "{:.2f}x".format(float(r) / float(std_val))

columns = [
    ("Label",     lambda r: r['label'],                                10, '<'),
    ("h",         lambda r: str(r['h']),                                3, '>'),
    ("d",         lambda r: str(r['d']),                                2, '>'),
    ("h'",        lambda r: str(r['h_prime']),                         3, '>'),
    ("k",         lambda r: str(r['k']),                                3, '>'),
    ("a",         lambda r: str(r['a']),                                3, '>'),
    ("w",         lambda r: str(r['w']),                                3, '>'),
    ("l",         lambda r: str(r['l']),                                3, '>'),
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

total_width = sum(w for _, _, w, _ in columns) + len(columns) - 1

print()
print("=" * total_width)
print("  SLH-DSA-128s vs Custom Variants (h=40, d in {2,4,5,8})  ".center(total_width))
print("  Filters: size < std, keygen/sign/verify each <= 3x std  ".center(total_width))
print("  All costs in SHA-256 compression-function calls  ".center(total_width))
print("=" * total_width)

header_parts = []
for hdr, _, w, align in columns:
    if align == '<':
        header_parts.append("{:<{w}}".format(hdr, w=w))
    else:
        header_parts.append("{:>{w}}".format(hdr, w=w))
print(" " + " ".join(header_parts))
print("-" * total_width)

for r in all_results:
    parts = []
    for _, fn, w, align in columns:
        cell = fn(r)
        if align == '<':
            parts.append("{:<{w}}".format(cell, w=w))
        else:
            parts.append("{:>{w}}".format(cell, w=w))
    print(" " + " ".join(parts))

print("-" * total_width)
n_w16 = sum(1 for r in all_results if r['label'] == 'w=16')
n_w32 = sum(1 for r in all_results if r['label'] == 'w=32')
print(" Total: {} configurations passing all filters (1 standard + {} w=16 + {} w=32)".format(
    len(all_results), n_w16, n_w32))
print()

# Filters
print("=" * total_width)
print("  FILTER REJECTION SUMMARY  ".center(total_width))
print("=" * total_width)
print()
print(" Considered configurations:        {}".format(considered))
print(" Rejected (security < 128):        {}".format(rejected['security']))
print(" Rejected (size >= std):           {}".format(rejected['size']))
print(" Rejected (keygen > {:.0f}x std):       {}".format(MAX_KEYGEN_RATIO, rejected['keygen']))
print(" Rejected (sign > {:.0f}x std):         {}".format(MAX_SIGN_RATIO, rejected['sign']))
print(" Rejected (verify > {:.0f}x std):       {}".format(MAX_VERIFY_RATIO, rejected['verify']))
print(" Passed all filters (custom):      {}".format(len(all_results) - 1))
print()

# Summary
print("=" * total_width)
print("  SUMMARY  ".center(total_width))
print("=" * total_width)

w16_results = [r for r in all_results if r['label'] == 'w=16']
w32_results = [r for r in all_results if r['label'] == 'w=32']

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

describe("w=16 (FIPS 205-compatible algorithm structure)", w16_results)
describe("w=32 (modified SPHINCS+, NOT FIPS 205)", w32_results)

print()
print("Notes:")
print("  - All cost metrics in SHA-256 compression-function calls (C).")
print("  - All ratios (KG/std, SG/std, SV/std) are relative to standard SLH-DSA-128s.")
print("  - Sec(bits) is capped at 128.0 by the n=128 preimage bound.")
print("  - Sweep ranges: d in {}, k in [{}, {}], a in [{}, {}].".format(
    D_VALUES, K_RANGE.start, K_RANGE.stop - 1, A_RANGE.start, A_RANGE.stop - 1))