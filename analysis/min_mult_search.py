#!/usr/bin/env python3
"""For every candidate of a sweep CSV, the smallest X for which each of its
metrics (size, KeyGen, SigGen, SigVer and C/byte) is at most X times that of
the STANDARD row, and the metric that sets X. Writes the candidates by
increasing X to global_X_thresholds.csv, which venn_diagram_draw.py reads.

  cd analysis && python3 min_mult_search.py [--input CSV] [--output CSV]
"""

import argparse
import pandas as pd
import os

METRICS = ['size', 'keygen_C', 'sign_C', 'verify_C', 'c_per_byte']

def find_global_x_thresholds(csv_path, output_csv):
    if not os.path.exists(csv_path):
        print(f"Error: File '{csv_path}' not found.")
        return

    df = pd.read_csv(csv_path)
    std_row = df[df['label'] == 'STANDARD']
    
    if std_row.empty:
        print("Error: Could not find the 'STANDARD' baseline row.")
        return
    std_row = std_row.iloc[0]
    
    candidates = df[df['label'] != 'STANDARD'].copy()
    
    for col in METRICS:
        candidates[f'{col}_ratio'] = candidates[col] / std_row[col]

    ratio_columns = [f'{col}_ratio' for col in METRICS]
    candidates['required_global_X'] = candidates[ratio_columns].max(axis=1)
    
    candidates['bottleneck_metric'] = candidates[ratio_columns].idxmax(axis=1).str.replace('_ratio', '')

    candidates = candidates.sort_values(by='required_global_X', ascending=True).reset_index(drop=True)

    results = []
    for i, row in candidates.iterrows():
        cumulative_total = i + 1   # candidates with at most this X
        results.append({
            'cumulative_total': cumulative_total,
            'required_global_X': round(row['required_global_X'], 4),
            'bottleneck_metric': row['bottleneck_metric'],
            'h': row['h'],
            'd': row['d'],
            'k': row['k'],
            'a': row['a'],
            'w': row['w'],
            'size_bytes': row['size'],
            'size_X': round(row['size_ratio'], 4),
            'keygen_X': round(row['keygen_C_ratio'], 4),
            'sign_X': round(row['sign_C_ratio'], 4),
            'verify_X': round(row['verify_C_ratio'], 4),
            'cpb_X': round(row['c_per_byte_ratio'], 4)
        })

    results_df = pd.DataFrame(results)
    
    out_dir = os.path.dirname(output_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    
    results_df.to_csv(output_csv, index=False)
    
    print("=========================================================================================")
    print(f" GLOBAL X FILTER THRESHOLDS SAVED TO: {output_csv}")
    print("=========================================================================================\n")
    
    print(results_df.head(10).to_string(index=False))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find smallest common X for all metrics filter and save to CSV.")
    parser.add_argument("--input", type=str, default="all_size_capped_candidates.csv", help="Input candidates CSV")
    parser.add_argument("--output", type=str, default="global_X_thresholds.csv", help="Output CSV filename")
    
    args = parser.parse_args()
    
    find_global_x_thresholds(args.input, args.output)