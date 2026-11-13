#!/usr/bin/env python3
"""Draws the report's concentric diagram, euler_custom_minimax.png: how many
candidates of global_X_thresholds.csv (min_mult_search.py) have all metrics
within X times SLH-DSA-128s, for the smallest X and for TARGET_MULTIPLIERS.

  cd utils && python3 venn_diagram_draw.py
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# The rings after the smallest X
TARGET_MULTIPLIERS = [0.9, 1.0, 2.0, 5.0, 10.0, 15.0]

def draw_custom_euler(factors, counts):
    """Draws one ring per factor, the innermost first in factors."""
    fig, ax = plt.subplots(figsize=(12, 10))
    ax.set_aspect('equal')
    
    N = len(factors)
    max_radius = 0.45
    radii = [max_radius * (i + 1) / N for i in range(N)]
    
    # Light yellow on the outside to dark brown at the centre
    palette = ['#fff7bc', '#fee391', '#fec44f', '#fe9929', '#ec7014', '#cc4c02', '#8c2d04']
    
    for i in range(N - 1, -1, -1):
        color_idx = N - 1 - i
        
        circle = patches.Circle(
            (0.5, 0.5), 
            radii[i], 
            facecolor=palette[color_idx % len(palette)], 
            edgecolor='white', 
            linewidth=2.5, 
            zorder=color_idx + 1
        )
        ax.add_patch(circle)
        
        # Candidates this ring adds
        added = counts[i] if i == 0 else counts[i] - counts[i-1]
        
        txt = f"{factors[i]} Cap | Total: {counts[i]} candidates (+{added} new)"
        
        x_target = 0.64 if i == 0 else 0.64 + (radii[i] + radii[i-1]) / 6
        y_target = 0.525 if i == 0 else 0.5 + (radii[i] + radii[i-1]) / 2.05
        
        ax.annotate(
            txt,
            xy=(0.51, y_target),
            xytext=(x_target, y_target),
            arrowprops=dict(arrowstyle="->", color='black', lw=1.5),
            ha='left', va='center', 
            color='black', fontsize=11, fontweight='bold', 
            zorder=10
        )
        
    ax.set_xlim(0, 1.35)
    ax.set_ylim(0, 1)
    ax.axis('off')

    out_path = "euler_custom_minimax.png"
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  [v] Diagram successfully saved to: {out_path}")

def main():
    csv_file = 'global_X_thresholds.csv'
    
    if not os.path.exists(csv_file):
        print(f"Error: Cannot find {csv_file} in the current directory.")
        return
        
    df = pd.read_csv(csv_file)
    
    min_x = df['required_global_X'].min()
    print(f"[*] Smallest possible X discovered: {min_x:.4f}x")
    
    thresholds = [min_x] + TARGET_MULTIPLIERS
    
    factors = []
    counts = []
    
    for target in thresholds:
        surviving_count = len(df[df['required_global_X'] <= target])
        
        label = f"{target:.4f}x" if target == min_x else f"{target}x"
        
        factors.append(label)
        counts.append(surviving_count)
        print(f"    -> At <= {label}: {surviving_count} candidates")
        
    draw_custom_euler(factors, counts)

if __name__ == "__main__":
    main()