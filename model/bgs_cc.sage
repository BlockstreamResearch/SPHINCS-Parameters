#!/usr/bin/env sage
"""
BGS-CC, the few-time signature of Ren and Yu (ePrint 2026/2502), in place of
FORS under the hypertree of SPX or of W+C: sizes in bytes and costs in SHA-256
compressions (docs/model.md, BGS-CC). The few-time configurations and their
security come from the search of third_party/bgs_cc;
scripts/export_site_data.sage loads this file for the two BGS-CC modes.

  sage model/bgs_cc.sage scheme h d w K L r b u c E delta
  sage model/bgs_cc.sage W+C_BGS 36 4 16 1 6 8 1 6 2,3,4,4,4,4,4 11 74752
"""
import csv
import json
import os
import sys

_DOC = __doc__   # loading costs.sage replaces __doc__
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # see model/costs.sage
# Once only: loading costs.sage again would import sage.all again, over the
# names a script has set since, like the N of stateful.sage.
if 'compute_wots_l' not in globals():
    os.environ['COSTS_SAGE_NO_MAIN'] = '1'   # its functions, without its CLI
    load(os.path.join(ROOT, "model", "costs.sage"))

# scheme -> the scheme of costs.sage whose hypertree it has
BGS_SCHEMES = {"BGS": "SPX", "W+C_BGS": "W+C"}
BGS_FTS_FIELDS = ['h', 'K', 'L', 'r', 'b', 'u', 'c', 'E', 'delta']

bgs_counter_size = 4   # the encoder counter
C_enc = 1              # an encoder block: a role byte, M, the counter and the block index


def bgs_code_size(c, e):
    """Codewords of the constant-sum code: the vectors x with 0 <= x_j <= c_j
    that sum to e (the paper's N)."""
    counts = [Integer(1)]
    for cap in c:
        nxt = [Integer(0)]*(len(counts) + cap)
        for s, n in enumerate(counts):
            for x in range(cap + 1):
                nxt[s + x] += n
        counts = nxt
    return counts[e] if e < len(counts) else Integer(0)


def compute_bgs_fts(h, K, L, r, b, u, c, E, delta):
    """{'size': bytes, 'sign', 'verify': compressions} of the BGS-CC signature
    of one configuration at hypertree height h; the height only sets how many
    blocks the encoder reads (docs/model.md, BGS-CC)."""
    h, K, L, r, b, u, E, delta = (Integer(x) for x in (h, K, L, r, b, u, E, delta))
    c = [Integer(x) for x in c]
    assert len(c) == L + 1 and 0 <= E <= sum(c) and 1 <= delta <= 2**32
    t = 2**L
    B = 2**b
    O = 2**u
    words = bgs_code_size(c, E)**(r*K)   # codeword choices of one encoding
    e_bits = (words - 1).nbits()         # ceil(log2 words)
    blocks = ceil((32 + h + K*(b + u + r*L) + e_bits)/(8*hashbytes))

    # One owner tree: t sources, their guard chains and leaves, the edge chains
    # and the t - 1 nodes
    c_owner = (t*(C_PRF + c[L]*C_Th1 + C_Th2)
               + sum(2**(d + 1)*c[d] for d in range(L))*C_Th1 + (t - 1)*C_Th2)
    # K coordinates of B buckets: O owners in the first layer and t in each of
    # the other r - 1, the O - 1 nodes above the first, then the bucket trees
    # and the K - 1 nodes above the coordinates
    c_graph = K*B*((O + (r - 1)*t)*c_owner + (O - 1)*C_Th2) + (K*B - 1)*C_Th2
    # Encoder blocks until a counter passes: one per attempt, the other
    # blocks - 1 for the attempts below the threshold
    c_search = ceil(2**e_bits*(2**32 + (blocks - 1)*delta)/(delta*words))*C_enc

    c_layer = (E + sum(c[:L]))*C_Th1 + (L + 1)*C_Th2
    return {
        'size': bgs_counter_size + hashbytes*K*(b + u + r*(L + 1)),
        'sign': c_graph + c_search,
        'verify': blocks*C_enc + K*((b + u)*C_Th2 + r*c_layer) + (K - 1)*C_Th2,
    }


def compute_hypertree(h, d, w, swn, scheme):
    """What surrounds the few-time signature of SPX (WOTS-TW) or W+C: R, the d
    layers of the hypertree and the message hashing. With FORS added it is the
    size and the costs of costs.sage."""
    assert h % d == 0, "h must be divisible by d"
    h_prime = h // d
    l = compute_wots_l(scheme, w)
    Thl = compute_Th(l)
    c_merkle = compute_keygen_time(h, d, w, scheme)
    if scheme == "SPX":
        l1, l2 = wots_lengths(w)
        search = 0
        c_wots = compute_wots_tw_mean_steps(l1, l2, w, d)*C_Th1 + d*Thl
        c_wots_worst = d*(compute_wots_tw_worst_steps(l1, l2, w)*C_Th1 + Thl)
    else:
        search = d*ceil((w**l)/compute_nu(l, swn, w))
        c_wots = d*(((w - 1)*l - swn)*C_Th1 + C_Th1c + Thl)
        c_wots_worst = c_wots
    return {
        'size': compute_size(h, d, 0, 0, w, scheme),   # no FORS trees
        'keygen': c_merkle,
        'sign': (C_Hmsg + C_PRFmsg + d*c_merkle + search*C_Th1c
                 - compute_top_layer_saving(h_prime, w, swn, scheme)),
        'verify': C_Hmsg + c_wots + h*C_Th2,
        'verify_worst': C_Hmsg + c_wots_worst + h*C_Th2,
    }


def compute_bgs(scheme, h, d, w, K, L, r, b, u, c, E, delta):
    """Size and costs of BGS-CC under the hypertree of scheme: the two parts add up."""
    wc = BGS_SCHEMES[scheme] != "SPX"
    ht = compute_hypertree(h, d, w, SWN[w] if wc else 0, BGS_SCHEMES[scheme])
    fts = compute_bgs_fts(h, K, L, r, b, u, c, E, delta)
    return {
        'size': ht['size'] + fts['size'],
        'keygen': ht['keygen'],
        'sign': ht['sign'] + fts['sign'],
        'verify': ht['verify'] + fts['verify'],
        'verify_worst': ht['verify_worst'] + fts['verify'],
    }


def bgs_fts_rows():
    """The few-time configurations of the search (third_party/bgs_cc): dicts
    with the BGS_FTS_FIELDS, 'bits', the cover bits of the search, and 'trees':
    per scheme the (d, w) of the hypertrees the search kept for the
    configuration."""
    rows = []
    with open(os.path.join(ROOT, PARAMETERS['bgs_cc']['fts'])) as f:
        for r in csv.DictReader(f):
            row = {key: int(r[key]) for key in BGS_FTS_FIELDS if key != 'c'}
            row['c'] = [int(x) for x in r['c'].split()]
            row['bits'] = float(r['cover_bits'])
            row['trees'] = {scheme: [tuple(int(x) for x in tree.split('/'))
                                     for tree in r[scheme].split()] for scheme in BGS_SCHEMES}
            rows.append(row)
    return rows


def bgs_search():
    """What the search covered: the .json beside the configurations."""
    with open(os.path.join(ROOT, os.path.splitext(PARAMETERS['bgs_cc']['fts'])[0] + '.json')) as f:
        return json.load(f)


def bgs_w(scheme):
    """The w of a BGS-CC scheme's hypertrees: the standard ones of the scheme
    it builds on, then w_optional."""
    stateless = PARAMETERS['stateless']
    standard = stateless['grid']['w'] if BGS_SCHEMES[scheme] == "SPX" else stateless['wc_w']
    return list(standard) + list(stateless['w_optional'])


def bgs_hypertrees(scheme, heights):
    """(h, d, w, swn) of the stateless grid for the heights of the few-time
    configurations: every d of the grid that divides h, and every w of the
    scheme."""
    grid = PARAMETERS['stateless']['grid']
    pairs = [(w, 0 if BGS_SCHEMES[scheme] == "SPX" else SWN[w]) for w in bgs_w(scheme)]
    return [(h, d, w, swn) for w, swn in pairs for h in sorted(heights)
            for d in range(grid['d'][0], grid['d'][1] + 1) if h % d == 0]


# export_site_data.sage sets BGS_CC_SAGE_NO_MAIN: load() runs this file with
# __name__ == '__main__'.
if __name__ == "__main__" and not os.environ.get("BGS_CC_SAGE_NO_MAIN"):
    if len(sys.argv) != 13 or sys.argv[1] not in BGS_SCHEMES:
        print(_DOC)
        # int(): sys.exit takes a Sage Integer for a message and exits with 1
        sys.exit(int(0) if sys.argv[1:] == ['--help'] else int(2))
    scheme = sys.argv[1]
    h, d, w, K, L, r, b, u = (int(x) for x in sys.argv[2:10])
    c = [int(x) for x in sys.argv[10].split(',')]
    E, delta = int(sys.argv[11]), int(sys.argv[12])
    m = compute_bgs(scheme, h, d, w, K, L, r, b, u, c, E, delta)
    print("Scheme:     " + scheme)
    print("(h, d, w):  (" + str(h) + ", " + str(d) + ", " + str(w) + ")")
    print("BGS-CC:     K=" + str(K) + " L=" + str(L) + " r=" + str(r) + " b=" + str(b) + " u=" + str(u)
          + " c=" + ",".join(str(x) for x in c) + " E=" + str(E) + " delta=" + str(delta))
    print("Size:       " + str(int(m['size'])) + " bytes")
    print("Keygen(C):  " + str(int(m['keygen'])))
    print("Sign(C):    " + str(int(m['sign'])))
    print("Verify(C):  " + str(int(m['verify'])) + "  (worst: " + str(int(m['verify_worst'])) + ")")
