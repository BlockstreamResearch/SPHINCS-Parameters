#!/usr/bin/env python3
"""
Evaluates the search space reduction achieved by applying the 
Standard Baseline signature size constraint (<= 7856 Bytes) 
to the 128-bit security parameter grid.
"""

import subprocess
import os
import pandas as pd

STD_SIZE = 7856

def run_sage_sweep(max_size="inf"):
    """Runs the Sage script and returns the number of valid parameter sets."""
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
    os.remove("candidates.csv")
    
    # Remove duplicates to get the true unique parameter space
    df_unique = df.drop_duplicates(subset=['h', 'd', 'k', 'a', 'w'])
    return len(df_unique)

def evaluate_reduction():
    print("============================================================")
    print(" Evaluating SLH-DSA Parameter Search Space Reduction")
    print("============================================================")
    
    # 1. Unconstrained Space (Only 128-bit security applies)
    print("[1/2] Sweeping total unconstrained 128-bit secure grid...")
    # Using a massive max-size effectively disables the size constraint
    total_space_count = run_sage_sweep(max_size="99999999") 
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