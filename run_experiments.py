#!/usr/bin/env python3
"""
Executes specialized SLH-DSA parameter sweeps using basic WOTS-TW + FORS architecture.
UNIVERSAL CONSTRAINT: Signature sizes in ALL categories strictly cannot exceed the Standard Baseline (7856B).

Selective execution flags:
  --cat1    Run Category 1: Absolute Extremes
  --cat2    Run Category 2: Time-Constrained Signatures
  --cat3    Run Category 3: Speed & CPB Optimized Tracks
  (If no flags are provided, all categories are executed by default.)
"""

import os
import subprocess
import shutil
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

STD_SIZE = 7856
STD_CPB = 0.303845

BASE_DIR = "outputs_specialized"
CAT1_DIR = os.path.join(BASE_DIR, "cat1_extremes")
CAT2_DIR = os.path.join(BASE_DIR, "cat2_time_constrained")
CAT3_DIR = os.path.join(BASE_DIR, "cat3_speed_optimized")

for d in [CAT1_DIR, CAT2_DIR, CAT3_DIR]:
    os.makedirs(d, exist_ok=True)

def run_basic_sweep(max_size=STD_SIZE, kg_r="inf", sg_r="inf", sv_r="inf", cpb_max="inf"):
    """Runs the Sage script strictly for basic wots-tw and fors architecture under given filter caps."""
    cmd = [
        "sage", "slhdsa-2to40.sage",
        "--ots", "wots-tw",
        "--fts", "fors",
        "--max-size", str(max_size),
        "--max-keygen-ratio", str(kg_r),
        "--max-sign-ratio", str(sg_r),
        "--max-verify-ratio", str(sv_r),
        "--max-c-per-byte", str(cpb_max)
    ]
    
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL)
    if res.returncode != 0 or not os.path.exists("candidates.csv"):
        return pd.DataFrame()
    
    df = pd.read_csv("candidates.csv")
    os.remove("candidates.csv")
    return df.drop_duplicates(subset=['label', 'h', 'd', 'k', 'a', 'w']).reset_index(drop=True)

def make_label(row):
    lbl = str(row['label'])
    if lbl == 'STANDARD':
        return f"STANDARD Baseline\n(h={row['h']},d={row['d']})"
    return f"{lbl}\n(h={row['h']},d={row['d']},k={row['k']},a={row['a']})"

def generate_five_metric_plots(df_plot, folder_path, filter_title):
    """
    Takes a focused DataFrame (Standard + Top Candidates) and generates
    exactly 5 comparison graphs saved into the specified folder.
    """
    if 'disp_name' not in df_plot.columns:
        df_plot['disp_name'] = df_plot.apply(make_label, axis=1)

    metrics = [
        {"file": "1_size.png", "col": "size", "title": "Signature Size", "ylabel": "Bytes", "log": False},
        {"file": "2_keygen.png", "col": "keygen_C", "title": "Key Generation Cost", "ylabel": "SHA-256 Compressions", "log": True},
        {"file": "3_signing.png", "col": "sign_C", "title": "Signing Cost", "ylabel": "SHA-256 Compressions", "log": True},
        {"file": "4_verification.png", "col": "verify_C", "title": "Verification Cost", "ylabel": "SHA-256 Compressions", "log": False},
        {"file": "5_compression_per_byte.png", "col": "c_per_byte", "title": "Compressions per Byte Ratio", "ylabel": "Ratio (C / Byte)", "log": False}
    ]

    sns.set_theme(style="whitegrid")
    colors = ['#d9534f' if 'STANDARD' in name else '#0275d8' for name in df_plot['disp_name']]

    for m in metrics:
        fig, ax = plt.subplots(figsize=(11, 6), constrained_layout=True)
        
        ax.bar(df_plot['disp_name'], df_plot[m["col"]], color=colors, width=0.5)
        
        ax.set_title(f"{filter_title}\n{m['title']} Comparison", fontsize=13, pad=12)
        ax.set_ylabel(m["ylabel"], fontsize=11)
        ax.set_xlabel("Candidate Parameter Sets", fontsize=11)
        
        ax.set_xticks(range(len(df_plot)))
        ax.set_xticklabels(df_plot['disp_name'], rotation=45, ha="right")
        
        if m["log"]:
            ax.set_yscale("log")
            
        out_path = os.path.join(folder_path, m["file"])
        plt.savefig(out_path, dpi=300, bbox_inches='tight')
        plt.close()

# =============================================================================
# CATEGORY 1: Absolute Extremes
# =============================================================================
def run_category_1():
    print("\n" + "="*70)
    print("Category 1: Absolute Extremes (Capped at Standard Size <= 7856B)")
    print("="*70)
    
    print("-> Sweeping parameter space strictly within standard signature footprint...")
    df_pool = run_basic_sweep(max_size=STD_SIZE)
    if df_pool.empty or len(df_pool) <= 1:
        print("   [!] Candidate pool empty or contains only standard baseline.")
        return

    df_pool.to_csv(os.path.join(CAT1_DIR, "all_size_capped_candidates.csv"), index=False)

    std_row = df_pool[df_pool['label'] == 'STANDARD'].iloc[0]
    custom_df = df_pool[df_pool['label'] != 'STANDARD']

    extremes = [
        {"folder": "1_smallest_signature", "col": "size", "desc": "Smallest Signature"},
        {"folder": "2_fastest_keygen", "col": "keygen_C", "desc": "Fastest Keygen"},
        {"folder": "3_fastest_signing", "col": "sign_C", "desc": "Fastest Signing"},
        {"folder": "4_fastest_verification", "col": "verify_C", "desc": "Fastest Verification"},
        {"folder": "5_best_compression_ratio", "col": "c_per_byte", "desc": "Best C/Byte Ratio"}
    ]

    master_summary = [std_row]

    for ex in extremes:
        ex_dir = os.path.join(CAT1_DIR, ex["folder"])
        os.makedirs(ex_dir, exist_ok=True)

        winner = custom_df.sort_values(by=ex["col"], ascending=True).iloc[0].copy()
        winner['cat1_award'] = ex["desc"]
        master_summary.append(winner)

        df_focused = pd.DataFrame([std_row, winner]).reset_index(drop=True)
        df_focused.to_csv(os.path.join(ex_dir, "winner_vs_standard.csv"), index=False)

        generate_five_metric_plots(df_focused, ex_dir, f"Cat 1: {ex['desc']} Winner vs Standard")
        print(f"   [v] Populated extreme folder: '{ex_dir}/'")

    pd.DataFrame(master_summary).to_csv(os.path.join(CAT1_DIR, "master_extremes_summary.csv"), index=False)

# =============================================================================
# CATEGORY 2: Smallest Signatures Under Strictly Capped Times
# =============================================================================
def run_category_2():
    print("\n" + "="*70)
    print("Category 2: Smallest Signatures Capped by Execution Time")
    print("="*70)
    
    factors = [1.0, 1.5, 2.0, 5.0, 10.0]
    
    for x in factors:
        folder_path = os.path.join(CAT2_DIR, f"time_cap_{x}x")
        os.makedirs(folder_path, exist_ok=True)
        
        print(f"-> Sweeping for Smallest Size (Size <= Std) with All Times <= {x}x Standard...")
        df_pool = run_basic_sweep(max_size=STD_SIZE, kg_r=x, sg_r=x, sv_r=x)
        
        if len(df_pool) <= 1:
            print(f"   [!] No custom candidates pass operational caps at {x}x std.")
            continue
            
        df_pool.to_csv(os.path.join(folder_path, "all_passing_candidates.csv"), index=False)
        
        std_row = df_pool[df_pool['label'] == 'STANDARD'].iloc[0]
        custom_df = df_pool[df_pool['label'] != 'STANDARD']
        
        top10_custom = custom_df.sort_values(by="size", ascending=True).head(10)
        df_plot = pd.concat([pd.DataFrame([std_row]), top10_custom]).reset_index(drop=True)
        
        generate_five_metric_plots(df_plot, folder_path, f"Cat 2: Smallest Signatures (Times <= {x}x Std)")
        print(f"   [v] Populated folder: '{folder_path}/'")

# =============================================================================
# CATEGORY 3: 4 Tracks Optimized One-by-One (Remaining Overheads Scaled)
# =============================================================================
def run_category_3():
    print("\n" + "="*70)
    print("Category 3: 4 Tracks Optimized One-by-One Under Scaled Overheads")
    print("="*70)
    
    factors = [1.0, 1.5, 2.0, 5.0, 10.0]
    
    tracks = [
        {
            "sub_dir": "fastest_keygen", 
            "target_col": "keygen_C", 
            "title": "Fastest Keygen", 
            "kg": "inf", "sg": lambda x: x, "sv": lambda x: x, "cpb": lambda x: STD_CPB * x
        },
        {
            "sub_dir": "fastest_signing", 
            "target_col": "sign_C", 
            "title": "Fastest Signing", 
            "kg": lambda x: x, "sg": "inf", "sv": lambda x: x, "cpb": lambda x: STD_CPB * x
        },
        {
            "sub_dir": "fastest_verification", 
            "target_col": "verify_C", 
            "title": "Fastest Verification", 
            "kg": lambda x: x, "sg": lambda x: x, "sv": "inf", "cpb": lambda x: STD_CPB * x
        },
        {
            "sub_dir": "best_compression_ratio", 
            "target_col": "c_per_byte", 
            "title": "Best Compression per Byte", 
            "kg": lambda x: x, "sg": lambda x: x, "sv": lambda x: x, "cpb": "inf"
        }
    ]
    
    for t in tracks:
        track_base_dir = os.path.join(CAT3_DIR, t["sub_dir"])
        os.makedirs(track_base_dir, exist_ok=True)
        
        print(f"\n--- Executing Track: {t['title']} ---")
        
        for x in factors:
            folder_path = os.path.join(track_base_dir, f"other_caps_{x}x")
            os.makedirs(folder_path, exist_ok=True)
            
            kg_ratio = t["kg"] if isinstance(t["kg"], str) else t["kg"](x)
            sg_ratio = t["sg"] if isinstance(t["sg"], str) else t["sg"](x)
            sv_ratio = t["sv"] if isinstance(t["sv"], str) else t["sv"](x)
            cpb_limit = t["cpb"] if isinstance(t["cpb"], str) else t["cpb"](x)
            
            print(f"-> Optimizing {t['title']} | Size <= Std, Other Overheads <= {x}x...")
            df_pool = run_basic_sweep(
                max_size=STD_SIZE, 
                kg_r=kg_ratio, 
                sg_r=sg_ratio, 
                sv_r=sv_ratio, 
                cpb_max=cpb_limit
            )
            
            if len(df_pool) <= 1:
                print(f"   [!] No custom candidates found passing overhead limits at {x}x std.")
                continue
                
            df_pool.to_csv(os.path.join(folder_path, "all_passing_candidates.csv"), index=False)
            
            std_row = df_pool[df_pool['label'] == 'STANDARD'].iloc[0]
            custom_df = df_pool[df_pool['label'] != 'STANDARD']
            
            top10_custom = custom_df.sort_values(by=t["target_col"], ascending=True).head(10)
            df_plot = pd.concat([pd.DataFrame([std_row]), top10_custom]).reset_index(drop=True)
            
            generate_five_metric_plots(df_plot, folder_path, f"Cat 3: {t['title']} Optimized (Caps <= {x}x)")
            print(f"   [v] Populated folder: '{folder_path}/'")

def main():
    parser = argparse.ArgumentParser(description="Specialized SLH-DSA parameter sweep orchestrator.")
    parser.add_argument("--cat1", action="store_true", help="Execute strictly Category 1: Absolute Extremes")
    parser.add_argument("--cat2", action="store_true", help="Execute strictly Category 2: Time-Constrained Signatures")
    parser.add_argument("--cat3", action="store_true", help="Execute strictly Category 3: Individual Operational Tracks")
    args = parser.parse_args()

    run_all = not (args.cat1 or args.cat2 or args.cat3)

    if not shutil.which("sage"):
        print("Critical Error: 'sage' engine is inaccessible. Initialize Sage environment first.")
        return

    print("\n" + "="*70)
    print("Initializing Specialized SLH-DSA Execution Suite")
    print("="*70)

    if run_all or args.cat1:
        run_category_1()
    if run_all or args.cat2:
        run_category_2()
    if run_all or args.cat3:
        run_category_3()

    print("\n" + "="*70)
    print(f"Requested execution scope successfully finished! Workspace stored in: '{BASE_DIR}/'")
    print("="*70)

if __name__ == "__main__":
    main()