#!/usr/bin/env python3
"""
Generates normalized 2D scatter plots for SLH-DSA metrics.
Logic: For any pair of plotted metrics (X, Y), the remaining 3 metrics 
are strictly constrained to be <= 1.0x the Standard Baseline.
"""

import os
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from itertools import combinations

# Define the core metrics and their readable display titles
METRICS = {
    'size': 'Signature Size',
    'keygen_C': 'Key Generation',
    'sign_C': 'Signing Cost',
    'verify_C': 'Verification Cost',
    'c_per_byte': 'Compressions per Byte'
}

def generate_constrained_scatter_plots(csv_path, output_dir, max_zoom=20.0):
    if not os.path.exists(csv_path):
        print(f"Error: Could not find '{csv_path}'")
        return

    # Load data
    df = pd.read_csv(csv_path)
    
    # Locate the standard baseline
    std_row = df[df['label'] == 'STANDARD']
    if std_row.empty:
        print("Error: Could not find the 'STANDARD' baseline row.")
        return
    std_row = std_row.iloc[0]
    
    custom_df = df[df['label'] != 'STANDARD'].copy()
    if custom_df.empty:
        print("No custom candidates found.")
        return

    # Normalize metrics relative to the Standard anchor
    for col in METRICS.keys():
        custom_df[f"{col}_norm"] = custom_df[col] / std_row[col]
        
    os.makedirs(output_dir, exist_ok=True)
    sns.set_theme(style="whitegrid", context="paper")

    metric_keys = list(METRICS.keys())
    pairs = list(combinations(metric_keys, 2))
    
    print(f"Generating {len(pairs)} strictly constrained scatter plots...")

    for col_x, col_y in pairs:
        norm_x = f"{col_x}_norm"
        norm_y = f"{col_y}_norm"
        
        # Identify the 3 metrics that must be fixed to <= 1.0x
        fixed_metrics = [m for m in metric_keys if m not in (col_x, col_y)]
        
        # Start with all valid
        mask = pd.Series(True, index=custom_df.index)
        
        # 1. Apply the strict <= 1.0x constraint to the 3 fixed metrics
        for fm in fixed_metrics:
            mask &= (custom_df[f"{fm}_norm"] <= 1.0)
            
        # 2. Apply the zoom constraint to the plotted metrics
        mask &= (custom_df[norm_x] <= max_zoom) & (custom_df[norm_y] <= max_zoom)
        
        plot_df = custom_df[mask].copy()

        fixed_titles = ", ".join([METRICS[m].replace(" Cost", "") for m in fixed_metrics])

        if plot_df.empty:
            print(f"  [!] Skipping {col_x} vs {col_y}: No candidates satisfy constraints.")
            continue
        
        fig, ax = plt.subplots(figsize=(9, 7))
        
        # Draw Crosshairs for the Origin Standard
        ax.axhline(1.0, color='gray', linestyle='--', alpha=0.8, linewidth=1.2)
        ax.axvline(1.0, color='gray', linestyle='--', alpha=0.8, linewidth=1.2)

        # Plot valid custom candidates
        ax.scatter(
            plot_df[norm_x], plot_df[norm_y], 
            alpha=0.7, color='#0275d8', edgecolor='white', s=70, linewidth=0.5, 
            label=f"Candidates (N={len(plot_df)})"
        )
        
        # Plot the Standard Anchor (1.0, 1.0)
        ax.scatter(
            1.0, 1.0, 
            color='#f0ad4e', marker='*', s=400, edgecolor='black', 
            linewidth=1.25, zorder=10, label="Standard Anchor"
        )
        
        # Formatting
        ax.set_title(f"{METRICS[col_x]} vs {METRICS[col_y]}\nConstrained: [{fixed_titles}] $\\leq 1.0x$", fontsize=13, pad=15)
        ax.set_xlabel(f"{METRICS[col_x]} ($X \\cdot$ Std)", fontsize=12, fontweight='bold')
        ax.set_ylabel(f"{METRICS[col_y]} ($X \\cdot$ Std)", fontsize=12, fontweight='bold')
        
        # Dynamic Limits
        x_max = max(max_zoom, plot_df[norm_x].max() * 1.05)
        y_max = max(max_zoom, plot_df[norm_y].max() * 1.05)
        ax.set_xlim(left=0, right=max(1.05, x_max))
        ax.set_ylim(bottom=0, top=max(1.05, y_max))

        ax.legend(loc='upper right', fontsize=11, frameon=True, shadow=True)
        plt.tight_layout()
        
        # Save output
        filename = f"constrained_{col_x}_vs_{col_y}.png"
        out_path = os.path.join(output_dir, filename)
        plt.savefig(out_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  [v] Saved: {filename} (Contains {len(plot_df)} points)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Constrained Scatter Plots for SLH-DSA parameters.")
    parser.add_argument("--input", type=str, default="outputs_specialized/cat1_extremes/all_size_capped_candidates.csv", help="Path to the target CSV database.")
    parser.add_argument("--outdir", type=str, default="scatter_constrained", help="Directory to save the generated scatter images.")
    parser.add_argument("--zoom", type=float, default=5.0, help="Maximum multiplier to display on axes (default: 20.0).")
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("SLH-DSA Constrained Scatter Plot Generator")
    print("="*60)
    generate_constrained_scatter_plots(args.input, args.outdir, args.zoom)
    print("\nGeneration complete!")