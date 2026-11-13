#!/usr/bin/env python3
"""Build master_extremes_summary.csv (per-metric extreme winners) from an
existing sweep CSV.

For each of the five metrics, picks the best custom candidate from the
size-capped sweep and records it alongside the STANDARD baseline row.
"""
import argparse
import os

import pandas as pd

EXTREMES = [
    ('size', 'Smallest Signature'),
    ('keygen_C', 'Fastest Keygen'),
    ('sign_C', 'Fastest Signing'),
    ('verify_C', 'Fastest Verification'),
    ('c_per_byte', 'Best C/Byte Ratio'),
]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', default=os.path.join(here, 'all_size_capped_candidates.csv'))
    parser.add_argument('--output', default=os.path.join(here, 'master_extremes_summary.csv'))
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    std = df[df.label == 'STANDARD']
    assert len(std) == 1, 'STANDARD baseline row missing from %s' % args.input
    std = std.iloc[0]
    custom = df[df.label != 'STANDARD']

    rows = [std.to_dict() | {'cat1_award': ''}]
    for col, award in EXTREMES:
        winner = custom.sort_values([col, 'size', 'h', 'd', 'k', 'a', 'w']).iloc[0]
        rows.append(winner.to_dict() | {'cat1_award': award})
        print(f'  {award}: ({winner.h:.0f},{winner.d:.0f},{winner.k:.0f},'
              f'{winner.a:.0f},{winner.w:.0f})  {col} = {winner[col]}')

    out = pd.DataFrame(rows)[list(df.columns) + ['cat1_award']]
    out.to_csv(args.output, index=False)
    print(f'wrote {args.output}')


if __name__ == '__main__':
    main()
