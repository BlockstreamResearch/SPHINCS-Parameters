#!/usr/bin/env python3

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import pandas as pd
import seaborn as sns
import os
import argparse
from scipy.spatial.distance import pdist, squareform

np.random.seed(42)

METRIC_WEIGHTS = {
    'size': 15.0,
    'keygen': 0.1,
    'sign': 0.1,
    'verify': 15.0,
    'rho': 0.1
}

def load_and_preprocess_data(csv_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Could not find '{csv_path}'")
        
    df_raw = pd.read_csv(csv_path)
    
    std_row = df_raw[df_raw['label'] == 'STANDARD']
    if std_row.empty:
        raise ValueError("No 'STANDARD' baseline row found in the dataset.")
    std_row = std_row.iloc[0]
    
    df = df_raw[df_raw['label'] != 'STANDARD'].copy().reset_index(drop=True)
    
    df['size_X'] = df['size'] / std_row['size']
    df['keygen_X'] = df['keygen_C'] / std_row['keygen_C']
    df['sign_X'] = df['sign_C'] / std_row['sign_C']
    df['verify_X'] = df['verify_C'] / std_row['verify_C']
    df['rho_X'] = df['c_per_byte'] / std_row['c_per_byte']
    
    df['max_X'] = df[['size_X', 'keygen_X', 'sign_X', 'verify_X', 'rho_X']].max(axis=1)
    
    winner_idx = df['max_X'].idxmin()
    minimax_val = df.loc[winner_idx, 'max_X']
    
    total_weight = sum(METRIC_WEIGHTS.values())
    norm_weights = {k: v / total_weight for k, v in METRIC_WEIGHTS.items()}
    
    df['weighted_dist'] = np.sqrt(
        norm_weights['size'] * (df['size_X'] ** 2) +
        norm_weights['keygen'] * (df['keygen_X'] ** 2) +
        norm_weights['sign'] * (df['sign_X'] ** 2) +
        norm_weights['verify'] * (df['verify_X'] ** 2) +
        norm_weights['rho'] * (df['rho_X'] ** 2)
    )
    
    return df, winner_idx, minimax_val, norm_weights

def place_candidates(n_points, x_range, y_range):
    if n_points > 1500:
        pts = np.random.rand(n_points, 2)
        pts[:, 0] = pts[:, 0] * (x_range[1] - x_range[0]) + x_range[0]
        pts[:, 1] = pts[:, 1] * (y_range[1] - y_range[0]) + y_range[0]
        return pts

    pts = np.random.rand(n_points, 2)
    pts[:, 0] = pts[:, 0] * (x_range[1] - x_range[0]) + x_range[0]
    pts[:, 1] = pts[:, 1] * (y_range[1] - y_range[0]) + y_range[0]
    
    min_dist = 4.5 if n_points < 500 else 2.5
    
    for _ in range(100):
        dists = squareform(pdist(pts))
        np.fill_diagonal(dists, np.inf)
        
        forces = np.zeros_like(pts)
        too_close = dists < min_dist
        
        for i in range(n_points):
            close_indices = np.where(too_close[i])[0] 
            if len(close_indices) > 0:
                for j in close_indices:
                    diff = pts[i] - pts[j]
                    dist = dists[i, j]
                    if dist < 0.1: 
                         diff = np.random.rand(2) * 0.1
                         dist = np.linalg.norm(diff)
                    force = diff / (dist**3 + 1e-6) 
                    forces[i] += force
        
        pts += forces * 0.3 
        pts[:, 0] = np.clip(pts[:, 0], x_range[0]+1, x_range[1]-1)
        pts[:, 1] = np.clip(pts[:, 1], y_range[0]+1, y_range[1]-1)
        
    return pts

def apply_sequential_filters(df, minimax_val):
    n_points = len(df)
    alive_mask = np.ones(n_points, dtype=bool)
    
    history = [np.arange(n_points)]
    
    conditions = [
        ('size_X', '<=', 0.74, "Size <= X * Std"),
        ('keygen_X', '<=', 1.0, "KeyGen <= X * std"),
        ('sign_X', '<=', 1.6, "SigGen <= X * Std"),
        ('verify_X', '<=', 0.8, "Verify <= X * Std"),
        ('rho_X', '<=', 1.0, f"Rho <= X * Std")
    ]
    
    newly_killed_indices_list = []
    
    for col, op, val, desc in conditions:
        passes_current_stage = df[col] <= val
        
        newly_killed = alive_mask & ~passes_current_stage
        killed_indices = df.index[newly_killed].tolist()
        newly_killed_indices_list.append(killed_indices)
        
        alive_mask = alive_mask & passes_current_stage
        history.append(df.index[alive_mask].tolist())
        
    history.append(history[-1].copy())
        
    return history, newly_killed_indices_list

def draw_sieve_stage(stage_index, pts, survived_indices, newly_killed_indices_list, filenames, winner_idx, df, euclidean_winner_idx):
    stages_meta = [
        {"title": "Image 1: Initial Pool (128-bit Secure)", "color": "white", "label": "Security", "filter_txt": "Initial Data"},
        {"title": r"Image 2: Filter Size", "color": "#a0c4ff", "label": "Size Sieve", "filter_txt": "Signature Size Sieve"},       
        {"title": r"Image 3: Filter KeyGen", "color": "#bdb2ff", "label": "KG Sieve", "filter_txt": "Key Generation Sieve"},     
        {"title": r"Image 4: Filter SigGen", "color": "#ffadad", "label": "SG Sieve", "filter_txt": "Signature Generation Sieve"},     
        {"title": r"Image 5: Filter Verification", "color": "#b9fbc0", "label": "VF Sieve", "filter_txt": "Signature Verification Sieve"}, 
        {"title": "Image 6: Filter Compression per Byte", "color": "#ffd6a5", "label": "C/B Sieve", "filter_txt": "Compression per Byte Sieve"},
        {"title": "Image 7: Weighted Euclidean Distance", "color": "#e2e2e2", "label": "Dist Sieve", "filter_txt": "Distance to Ideal Origin (0,0,0,0,0)"} 
    ]

    sns.set_theme(style="white", context="paper")
    fig, ax = plt.subplots(figsize=(10, 10))
    ax.set_aspect('equal')
    
    x_origin_ref = 15     
    offset_step = 3      
    card_width = 120
    card_height = 120
    
    if stage_index == 0:
        rect = patches.Rectangle((x_origin_ref, 10), card_width, card_height, 
                                 facecolor='white', edgecolor='black', linewidth=1.5, zorder=1)
        ax.add_patch(rect)
    else:
        for prev_stage in range(1, stage_index + 1):
            is_current = (prev_stage == stage_index)
            zorder_val = prev_stage + 1
            
            stage_order_inv = stage_index - prev_stage 
            x_offset = -offset_step * stage_order_inv
            y_offset = -offset_step * stage_order_inv
            
            final_facecolor = stages_meta[prev_stage]["color"]
            final_edgecolor = 'black' if is_current else 'gray'
            final_lw = 2.5 if is_current else 1.0
            
            rect = patches.Rectangle((x_origin_ref + x_offset, 10 + y_offset), card_width, card_height, 
                                     facecolor=final_facecolor, edgecolor=final_edgecolor, linewidth=final_lw, alpha=0.95, zorder=zorder_val)
            ax.add_patch(rect)
            
            if not is_current:
                label_txt = stages_meta[prev_stage]["label"]
                ax.text(x_origin_ref + x_offset + 1, 10 + y_offset + card_height - 3, label_txt, 
                        ha='left', va='top', fontsize=9, fontweight='bold', rotation=90, color='gray', alpha=0.9, zorder=zorder_val+1)

    current_filter_text = stages_meta[stage_index]["filter_txt"]
    ax.text(x_origin_ref, 10 + card_height + 1.5, f"{current_filter_text}",
            ha='left', va='bottom', fontsize=12, fontweight='bold', color='#2c3e50', zorder=20)

    padding = 1.1  # Controls the spacing offset from the boundary line
    pts_mapped = pts.copy()
    pts_mapped[:, 0] = (pts[:, 0] / 100) * (card_width - 2 * padding) + x_origin_ref + padding
    pts_mapped[:, 1] = (pts[:, 1] / 100) * (card_height - 2 * padding) + 10 + padding
    
    mapped_survivor_pts = pts_mapped[survived_indices]
    if stage_index == 6:
        if len(survived_indices) > 0:
            distances = df.loc[survived_indices, 'weighted_dist'].values
            sc = ax.scatter(mapped_survivor_pts[:, 0], mapped_survivor_pts[:, 1], 
                            c=distances, cmap='coolwarm', 
                            s=45, edgecolor='black', linewidth=0.8, alpha=0.9, zorder=12)
            cbar = plt.colorbar(sc, ax=ax, fraction=0.046, pad=0.04)
            cbar.set_label('Weighted Distance', rotation=270, labelpad=20, fontweight='bold')
            
            if euclidean_winner_idx is not None and euclidean_winner_idx in survived_indices:
                euc_pt = pts_mapped[euclidean_winner_idx]
                optimum_dist = df.loc[euclidean_winner_idx, 'weighted_dist']
                optimum_color = sc.to_rgba(optimum_dist)
                ax.scatter(euc_pt[0], euc_pt[1], color=optimum_color, marker='o', s=215, edgecolor='black', linewidth=2.0, zorder=15, label="The Best Candidate")
    else:
        if len(survived_indices) > 0:
            if winner_idx in survived_indices:
                 mask = np.array(survived_indices) != winner_idx
                 other_survivors = mapped_survivor_pts[mask]
                 
                 if len(other_survivors) > 0:
                    ax.scatter(other_survivors[:, 0], other_survivors[:, 1], color='#5cb85c', marker='o', s=45, edgecolor='black', linewidth=0.8, alpha=0.9, zorder=12, label=f"Passed ({len(survived_indices)})")
            else:
                ax.scatter(mapped_survivor_pts[:, 0], mapped_survivor_pts[:, 1], color='#5cb85c', marker='o', s=45, edgecolor='black', linewidth=0.8, alpha=0.9, zorder=12, label=f"Passed ({len(survived_indices)})")

    if stage_index != 6:
        ax.legend(loc='lower center', fontsize=14, frameon=True, shadow=True, bbox_to_anchor=(0.5, 0.05), ncol=4, markerscale=1.5)
    
    ax.set_xlim(x_origin_ref - offset_step * 6 - 5, x_origin_ref + card_width + 5)
    ax.set_ylim(10 - offset_step * 6 - 5, 10 + card_height + 5)
    ax.axis('off')
    
    plt.tight_layout()
    plt.savefig(filenames[stage_index], dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  [v] Compiled: {filenames[stage_index]}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default="outputs_specialized/cat1_extremes/all_unbound_candidates.csv")
    args = parser.parse_args()

    print("\n" + "="*80)
    print(f"Sieve Stacked Card Visualization")
    print("="*80)

    print("[1/3] Loading dataset...")
    df, winner_idx, minimax_val, norm_weights = load_and_preprocess_data(args.input)
    n_total = len(df)
    print(f"      -> Found {n_total} valid candidates.")
    print("      -> Normalized Priority Weights:")
    for k, v in norm_weights.items():
        print(f"         - {k.capitalize():<7}: {v*100:>5.1f}%")

    print("[2/3] Calculating 2D placement coordinates...")
    plane_points = place_candidates(n_total, (0, 100), (0, 100))

    history, newly_killed_list = apply_sequential_filters(df, minimax_val)
    print(f"      - Sieve 1 (Size):   {len(history[1])} passing")
    print(f"      - Sieve 2 (KeyGen): {len(history[2])} passing")
    print(f"      - Sieve 3 (SigGen): {len(history[3])} passing")
    print(f"      - Sieve 4 (Verify): {len(history[4])} passing")
    print(f"      - Sieve 5 (Rho):    {len(history[5])} passing")

    final_survivors = history[-1]
    if len(final_survivors) > 0:
        euclidean_winner_idx = df.loc[final_survivors, 'weighted_dist'].idxmin()
        best_cand = df.loc[euclidean_winner_idx]
        print(f"\n      -> The Shortest Distance Found at Index {euclidean_winner_idx}")
        print(f"      -> Parameters: (h={best_cand['h']}, d={best_cand['d']}, k={best_cand['k']}, a={best_cand['a']}, w={best_cand['w']})")
        print(f"      -> Metrics: Size={best_cand['size']} B | KeyGen={best_cand['keygen_C']} C | Sign={best_cand['sign_C']} C | Verify={best_cand['verify_C']} C | C/B={best_cand['c_per_byte']:.6f}")
    else:
        euclidean_winner_idx = None
        print("\n      -> No survivors left to calculate Euclidean optimum.")

    filenames = [
        "sieve_step1_initial.png", 
        "sieve_step2_size.png",    
        "sieve_step3_keygen.png",  
        "sieve_step4_siggen.png",  
        "sieve_step5_verify.png",  
        "sieve_step6_rho.png",
        "sieve_step7_distance.png"
    ]

    print(f"\n[3/3] Rendering stacked card visualizations...")
    for i in range(len(filenames)):
        draw_sieve_stage(i, plane_points, history[i], newly_killed_list, filenames, winner_idx, df, euclidean_winner_idx)

    print("\n" + "="*80)
    print("Sieve visualization sequence complete.")
    print("="*80)

if __name__ == "__main__":
    main()