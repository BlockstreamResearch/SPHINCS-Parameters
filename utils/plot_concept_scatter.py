#!/usr/bin/env python3
"""
Generates a conceptual scatter plot with explicit constraint zones.
Includes a vector pointing to the valid candidate with the shortest Euclidean 
distance from the absolute origin (0, 0).
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import seaborn as sns

def generate_bounded_plot():
    sns.set_theme(style="whitegrid", context="paper")
    fig, ax = plt.subplots(figsize=(10, 8))

    # 1. Define Constraints and Maximum Plot Area
    anchor_x, anchor_y = 1.0, 1.0
    limit_x = 3.0
    limit_y = 2.0
    max_val = 5.5

    # 2. Draw the Zones (Backgrounds)
    # Zone: Fails Y, Passes X (Yellow)
    rect_top_left = patches.Rectangle((0, limit_y), limit_x, max_val - limit_y, 
                                      facecolor='#ffecb3', alpha=0.5, zorder=1)
    ax.add_patch(rect_top_left)

    # Zone: Fails X, Passes Y (Yellow)
    rect_bottom_right = patches.Rectangle((limit_x, 0), max_val - limit_x, limit_y, 
                                          facecolor='#ffecb3', alpha=0.5, zorder=1)
    ax.add_patch(rect_bottom_right)

    # Zone: Valid Bounding Box (Green)
    rect_desired = patches.Rectangle((0, 0), limit_x, limit_y, 
                                     facecolor='#d4edda', edgecolor=None, 
                                     linewidth=2.5, alpha=0.6, zorder=2)
    ax.add_patch(rect_desired)

    # Dashed threshold lines
    ax.axvline(x=limit_x, color='black', linestyle='--', linewidth=1.5, zorder=3)
    ax.axhline(y=limit_y, color='black', linestyle='--', linewidth=1.5, zorder=3)

    # 1.0x Standard Square
    rect_standard = patches.Rectangle((0, 0), 1.0, 1.0, fill=False, 
                                     edgecolor='gray', linestyle=':', linewidth=1.5, zorder=1)
    ax.add_patch(rect_standard)

    # 3. Generate the Scatter Points
    np.random.seed(42)
    
    utopian_x = np.random.uniform(0.4, 0.95, 15)
    utopian_y = np.random.uniform(0.4, 0.95, 15)
    general_x = np.random.uniform(0.3, max_val - 0.2, 180)
    general_y = np.random.uniform(0.3, max_val - 0.2, 180)
    
    all_x = np.concatenate([utopian_x, general_x])
    all_y = np.concatenate([utopian_y, general_y])

    valid_x, valid_y = [], []
    invalid_x, invalid_y = [], []

    for x, y in zip(all_x, all_y):
        if x <= 1.0 and y <= 1.0:
            pass 
        else:
            # Create a conceptual pareto frontier curve so points don't collapse too close to (0,0)
            min_y = 1.0 / (x + 0.1) + 0.15
            if y < min_y:
                y = min_y + np.random.uniform(0.1, 0.3)

        if x <= limit_x and y <= limit_y:
            valid_x.append(x)
            valid_y.append(y)
        else:
            invalid_x.append(x)
            invalid_y.append(y)

    # 4. Plot the Regular Points
    ax.scatter(invalid_x, invalid_y, alpha=0.4, color='#d9534f', edgecolor='white', 
               s=70, linewidth=1.0, label="Invalid Candidates", zorder=4)
               
    ax.scatter(valid_x, valid_y, alpha=0.9, color='#0275d8', edgecolor='white', 
               s=70, linewidth=1.0, label="Valid Candidates (Acceptable)", zorder=4)

    # 5. Plot the Standard Anchor
    ax.scatter(anchor_x, anchor_y, color='#f0ad4e', marker='*', s=250, 
               edgecolor='black', linewidth=1.5, zorder=5, label="Standard Anchor (1.0x)")

    # =========================================================================
    # NEW LOGIC: FIND SHORTEST DISTANCE VECTOR FROM (0,0)
    # =========================================================================
    origin_x, origin_y = 0.0, 0.0
    
    if valid_x:
        # Calculate Euclidean distances from the Absolute Origin (0, 0)
        dists = [np.sqrt((x - origin_x)**2 + (y - origin_y)**2) for x, y in zip(valid_x, valid_y)]
        
        # Isolate the point with the absolute minimum distance
        min_idx = np.argmin(dists)
        closest_x, closest_y = valid_x[min_idx], valid_y[min_idx]
        
        # Draw a bold vector (arrow) pointing from (0,0) to this nearest candidate
        ax.annotate('', xy=(closest_x, closest_y), xytext=(origin_x, origin_y),
                    arrowprops=dict(facecolor='black', edgecolor='black', width=1.5, headwidth=8, shrink=0.0),
                    zorder=6)
        
        # Highlight this specific candidate to make the shortest-distance end point pop
        ax.scatter(closest_x, closest_y, color='#5cb85c', s=100, edgecolor='black', 
                   linewidth=1.5, zorder=7, label=f"Optimal Point (Closest to Origin)")
    # =========================================================================

    # 6. Formatting
    ax.set_title("Signature Size vs Signing Cost\n(Showing Vector to Globally Optimal Candidate)", 
                 fontsize=14, pad=15)
    ax.set_xlabel(r" Signature Size ($X \cdot$ Std)", fontsize=12, fontweight='bold')
    ax.set_ylabel(r" Signing Cost ($X \cdot$ Std)", fontsize=12, fontweight='bold')
    
    ax.set_xlim(0, max_val)
    ax.set_ylim(0, max_val)

    # Move legend to not overlap with the new vector
    ax.legend(loc='upper right', fontsize=11, frameon=True, shadow=True)
    plt.tight_layout()

    # Save output
    filename = "conceptual_bounded_zones_origin_vector.png"
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Successfully generated bounded zone diagram: {filename}")

if __name__ == "__main__":
    generate_bounded_plot()