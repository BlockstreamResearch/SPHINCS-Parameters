#!/usr/bin/env python3
"""
Sweeps a global uniform filter X across 4 operational metrics.
Finds the absolute minimum global X required to yield the smallest 
possible set of valid candidates.
Aligned with run_experiments.py folder structure and venn_diagram_draw.py keys.
"""

import argparse
import pandas as pd
import os

METRICS = ['keygen_C', 'sign_C', 'verify_C', 'c_per_byte']

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
    
    # 1. Calculate ratios against standard for the 4 metrics
    for col in METRICS:
        candidates[f'{col}_ratio'] = candidates[col] / std_row[col]

    # 2. Determine the minimum global X required for each candidate
    ratio_columns = [f'{col}_ratio' for col in METRICS]
    candidates['required_global_X'] = candidates[ratio_columns].max(axis=1)
    
    # 3. Identify the specific bottleneck metric that forced X to be this high
    candidates['bottleneck_metric'] = candidates[ratio_columns].idxmax(axis=1).str.replace('_ratio', '')

    # 4. Sort by the required global X to find our expanding thresholds
    candidates = candidates.sort_values(by='required_global_X', ascending=True).reset_index(drop=True)

    # 5. Build the output dataset with the explicit "cumulative_total" key
    results = []
    for i, row in candidates.iterrows():
        cumulative_total = i + 1  # 1 candidate, 2 candidates, 3 candidates...
        results.append({
            'cumulative_total': cumulative_total,  # Renamed to match Venn Diagram script
            'required_global_X': round(row['required_global_X'], 4),
            'bottleneck_metric': row['bottleneck_metric'],
            'h': row['h'],
            'd': row['d'],
            'k': row['k'],
            'a': row['a'],
            'w': row['w'],
            'size_bytes': row['size'],
            'keygen_X': round(row['keygen_C_ratio'], 4),
            'sign_X': round(row['sign_C_ratio'], 4),
            'verify_X': round(row['verify_C_ratio'], 4),
            'cpb_X': round(row['c_per_byte_ratio'], 4)
        })

    results_df = pd.DataFrame(results)
    
    # 6. Ensure the target directory exists (Matching run_experiments behavior)
    out_dir = os.path.dirname(output_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    
    # 7. Save to CSV
    results_df.to_csv(output_csv, index=False)
    
    print("=========================================================================================")
    print(f" GLOBAL X FILTER THRESHOLDS SAVED TO: {output_csv}")
    print("=========================================================================================\n")
    
    # Print the first 10 rows to the terminal as a preview
    print(results_df.head(10).to_string(index=False))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find smallest common X for all metrics filter and save to CSV.")
    parser.add_argument("--input", type=str, default="outputs_specialized/cat1_extremes/all_size_capped_candidates.csv", help="Input candidates CSV")
    
    # Default output path now perfectly aligns with Category 4 structural expectations
    parser.add_argument("--output", type=str, default="outputs_specialized/cat4_minimax/global_X_thresholds.csv", help="Output CSV filename")
    
    args = parser.parse_args()
    
    find_global_x_thresholds(args.input, args.output)