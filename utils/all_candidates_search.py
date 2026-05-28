#!/usr/bin/env python3
"""
Evaluates the search space reduction achieved by applying the 
Standard Baseline signature size constraint (<= 7856 Bytes) 
to the 128-bit security parameter grid, and saves the unconstrained grid.
"""

import subprocess
import os
import pandas as pd

STD_SIZE = 7856
SAVE_LOCALLY = True 
FILENAME = "all_unbound_candidates.csv"

if SAVE_LOCALLY:
    OUTPUT_CSV_PATH = FILENAME
else:
    OUTPUT_CSV_DIR = "outputs_specialized/cat1_extremes"
    OUTPUT_CSV_PATH = os.path.join(OUTPUT_CSV_DIR, FILENAME)

def run_sage_sweep(max_size="inf", save_path=None):
    """Runs the Sage script, optionally saves the data, and returns the number of valid parameter sets."""
    cmd = [
        "sage", "slhdsa-2to40.sage",
        "--ots", "wots-tw",
        "--fts", "fors",
        "--max-size", str(max_size),
        "--max-keygen-ratio", "inf",
        "--max-sign-ratio", "inf",
        "--max-verify-ratio", "inf",
        "--max-c-per-byte", "inf"
    ]
    
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL)
    if res.returncode != 0 or not os.path.exists("candidates.csv"):
        return 0
    
    df = pd.read_csv("candidates.csv")
    os.remove("candidates.csv")  # Clean up the temporary Sage output
    
    # Remove duplicates to get the true unique parameter space
    df_unique = df.drop_duplicates(subset=['h', 'd', 'k', 'a', 'w'])
    
    # If a save_path is provided, export the dataframe
    if save_path:
        out_dir = os.path.dirname(save_path)
        if out_dir:  # Only create directories if out_dir is not empty
            os.makedirs(out_dir, exist_ok=True)
        df_unique.to_csv(save_path, index=False)
        print(f"      [v] Saved unconstrained candidate data to: {save_path}")

    return len(df_unique)

def evaluate_reduction():
    print("============================================================")
    print(" Evaluating SLH-DSA Parameter Search Space Reduction")
    print("============================================================")
    
    # 1. Unconstrained Space (Only 128-bit security applies)
    print("[1/2] Sweeping total unconstrained 128-bit secure grid...")
    # Using a massive max-size effectively disables the size constraint.
    # We pass the OUTPUT_CSV_PATH here so it saves this specific run.
    total_space_count = run_sage_sweep(max_size="99999999", save_path=OUTPUT_CSV_PATH) 
    print(f"      -> Total Unconstrained Candidates: {total_space_count}")
    
    if total_space_count == 0:
        print("\n[!] Error: Unconstrained sweep returned 0 candidates. Check Sage script.")
        return

    # 2. Constrained Space (128-bit security + Size <= 7856)
    print(f"\n[2/2] Sweeping constrained space (Size <= {STD_SIZE} B)...")
    constrained_count = run_sage_sweep(max_size=STD_SIZE)
    print(f"      -> Total Constrained Candidates: {constrained_count}")

    # 3. Calculate Reduction
    pruned_count = total_space_count - constrained_count
    reduction_percentage = (pruned_count / total_space_count) * 100

    print("\n============================================================")
    print(" RESULTS")
    print("============================================================")
    print(f" Total Valid 128-bit Sets: {total_space_count}")
    print(f" Sets Surviving Size Cap:  {constrained_count}")
    print(f" Sets Pruned by Size Cap:  {pruned_count}")
    print(f" Search Space Reduction:   {reduction_percentage:.2f}%")
    print("============================================================")

if __name__ == "__main__":
    evaluate_reduction()