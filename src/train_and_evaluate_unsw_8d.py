#!/usr/bin/env python3
"""
SPECTRA Module 4 - UNSW-NB15 8-Dimensional Training & Benchmark
Trains Isolation Forest on the 8-feature vector extracted from the real
UNSW-NB15 dataset and benchmarks detection performance against 82,332 test samples.

The 8-Feature Vector Mapping (UNSW-NB15 -> SPECTRA):
  1. smean       -> packet_size        (Bytes)
  2. rate        -> request_rate       (Packets / second)
  3. ct_srv_src  -> connection_count   (Count)
  4. sinpkt      -> inter_arrival_time (Milliseconds, ms)
  5. sttl        -> sttl               (Hops / integer)
  6. sjit        -> sjit               (Milliseconds, ms)
  7. dmean       -> dmean              (Bytes)
  8. synack      -> synack             (Milliseconds, ms)
"""

import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    classification_report
)

TRAIN_PATH = "data/UNSW_NB15_training-set.csv"
TEST_PATH = "data/UNSW_NB15_testing-set.csv"
RESULTS_DIR = "results"
MODEL_PATH = "results/isolation_forest.pkl"
CALIBRATION_PATH = "results/risk_calibration.npz"
RESULTS_TXT = "results/UNSW_NB15_8D_results.txt"

FEATURES_8D = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time",
    "sttl",
    "sjit",
    "dmean",
    "synack"
]

UNSW_COLUMNS = {
    "smean": "packet_size",
    "rate": "request_rate",
    "ct_srv_src": "connection_count",
    "sinpkt": "inter_arrival_time",
    "sttl": "sttl",
    "sjit": "sjit",
    "dmean": "dmean",
    "synack": "synack"
}

def load_and_preprocess(filepath):
    print(f"[+] Loading {filepath}...")
    df = pd.read_csv(filepath, encoding="utf-8-sig")
    
    # Verify required columns exist
    required = list(UNSW_COLUMNS.keys()) + ["label"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in {filepath}: {missing}")

    mapped = df.rename(columns=UNSW_COLUMNS).copy()
    
    # Unit Normalization:
    # In UNSW-NB15:
    # synack is in seconds (e.g., 0.012s) -> scale to milliseconds (* 1000.0)
    # sinpkt and sjit are already in milliseconds (mSec)
    if mapped["synack"].dropna().mean() < 1.0:
        mapped["synack"] = mapped["synack"] * 1000.0
    
    # Fill any NaNs or infinities with clean baseline medians
    for f in FEATURES_8D:
        mapped[f] = mapped[f].fillna(0.0).clip(lower=0.0)
        
    return mapped

def main():
    start_time = time.time()
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 70)
    print("  SPECTRA M4: 8-DIMENSIONAL UNSW-NB15 TRAINING & BENCHMARK")
    print("=" * 70)

    # 1. Load Training Dataset
    train_df = load_and_preprocess(TRAIN_PATH)
    
    # Zero-Trust Unsupervised Constraint: Train ONLY on normal traffic (label == 0)
    normal_train = train_df[train_df["label"] == 0].copy()
    print(f"[+] Total training records       : {len(train_df):,}")
    print(f"[+] Normal training records (y=0): {len(normal_train):,}")

    X_normal = normal_train[FEATURES_8D]

    # 80/20 Train / Calibration Split
    X_fit, X_calib = train_test_split(
        X_normal,
        test_size=0.20,
        random_state=42,
        shuffle=True
    )
    print(f"[+] Model fitting samples (80%) : {len(X_fit):,}")
    print(f"[+] Calibration samples (20%)   : {len(X_calib):,}")
    print(f"[+] Feature count               : 8 dimensions")

    # 2. Train Isolation Forest
    print("[+] Fitting 8D Isolation Forest model (n_estimators=150, contamination=0.03)...")
    model = IsolationForest(
        n_estimators=150,
        contamination=0.03,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_fit)

    # 3. Empirical Percentile Calibration
    print("[+] Calibrating empirical percentiles against held-out normal traffic...")
    calib_scores = -model.decision_function(X_calib)
    sorted_calib_scores = np.sort(calib_scores.astype(float))

    MFA_THRESHOLD = 0.970
    DROP_THRESHOLD = 0.995

    # Save model and calibration
    joblib.dump(model, MODEL_PATH)
    np.savez(
        CALIBRATION_PATH,
        anomaly_scores=sorted_calib_scores,
        mfa_threshold=MFA_THRESHOLD,
        drop_threshold=DROP_THRESHOLD
    )
    print(f"[+] Saved model to {MODEL_PATH}")
    print(f"[+] Saved calibration to {CALIBRATION_PATH}")

    # 4. Load Testing Dataset & Evaluate
    test_df = load_and_preprocess(TEST_PATH)
    X_test = test_df[FEATURES_8D]
    y_true = test_df["label"].values # 0 = Normal, 1 = Attack

    print(f"\n[+] Evaluating on {len(test_df):,} test samples ({sum(y_true==0):,} Normal, {sum(y_true==1):,} Attack)...")
    
    # Calculate inference latency
    infer_start = time.perf_counter()
    raw_scores = model.decision_function(X_test)
    infer_total_ms = (time.perf_counter() - infer_start) * 1000.0
    latency_per_sample_us = (infer_total_ms / len(X_test)) * 1000.0

    # Calculate empirical risk percentiles
    test_anomaly_scores = -raw_scores
    positions = np.searchsorted(sorted_calib_scores, test_anomaly_scores, side="right")
    risk_scores = np.clip(positions / len(sorted_calib_scores), 0.0, 1.0)

    # Flag anomaly if risk >= MFA_THRESHOLD (0.970)
    y_pred = np.where(risk_scores >= MFA_THRESHOLD, 1, 0)

    # Metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_true, risk_scores)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn)

    # Per-Attack Category Recall
    cat_recalls = {}
    if "attack_cat" in test_df.columns:
        for cat in test_df["attack_cat"].dropna().unique():
            cat_mask = (test_df["attack_cat"] == cat)
            cat_total = sum(cat_mask)
            if cat_total > 0:
                cat_caught = sum(y_pred[cat_mask] == 1)
                cat_recalls[cat] = (cat_caught / cat_total) * 100.0

    # 5. Output Summary & Comparison with 4D Baseline
    report = []
    report.append("=" * 70)
    report.append("  SPECTRA M4: 8-DIMENSIONAL REAL UNSW-NB15 BENCHMARK REPORT")
    report.append("=" * 70)
    report.append(f"Recorded Date        : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Model Architecture   : Isolation Forest (Unsupervised, fit on 44,800 normal samples)")
    report.append(f"Dimensions (8)       : {FEATURES_8D}")
    report.append(f"Calibration Method   : Empirical Percentile on 11,200 held-out normal traffic")
    report.append(f"Thresholds           : MFA >= {MFA_THRESHOLD:.3f} | DROP >= {DROP_THRESHOLD:.3f}")
    report.append(f"Inference Latency    : {latency_per_sample_us:.2f} µs / sample ({infer_total_ms:.1f} ms total)")
    report.append("-" * 70)
    report.append("OVERALL BENCHMARK METRICS (82,332 REAL TEST SAMPLES):")
    report.append(f"  • Precision        : {precision*100:.2f}%")
    report.append(f"  • Recall (TPR)     : {recall*100:.2f}%")
    report.append(f"  • F1-Score         : {f1*100:.2f}%")
    report.append(f"  • False-Alarm (FPR): {fpr*100:.2f}%")
    report.append(f"  • ROC-AUC Score    : {roc_auc:.4f}")
    report.append("-" * 70)
    report.append("CONFUSION MATRIX:")
    report.append(f"  True Negatives (Normal passed)    : {tn:,} / {tn+fp:,}")
    report.append(f"  False Positives (Normal challenged): {fp:,} ({fpr*100:.2f}% FPR)")
    report.append(f"  False Negatives (Missed attacks)  : {fn:,}")
    report.append(f"  True Positives (Attacks caught)   : {tp:,} / {tp+fn:,}")
    report.append("-" * 70)
    report.append("PER-ATTACK CATEGORY DETECTION RECALL:")
    for cat, r_val in sorted(cat_recalls.items()):
        report.append(f"  • {cat:<18}: {r_val:>6.2f}%")
    report.append("=" * 70)
    report.append("\nHEAD-TO-HEAD COMPARISON: 4-FEATURE BASELINE vs. 8-FEATURE UPGRADE:")
    report.append("-" * 70)
    report.append(f"{'Metric':<25} | {'4-Feature Baseline':<20} | {'8-Feature Upgrade (Ours)':<20}")
    report.append("-" * 70)
    report.append(f"{'Feature Set':<25} | {'4 request features':<20} | {'8 bidirectional features':<20}")
    report.append(f"{'Total Features':<25} | {'4':<20} | {'8':<20}")
    report.append(f"{'Recall (Attacks Caught)':<25} | {'17.78%':<20} | {f'{recall*100:.2f}%':<20}")
    report.append(f"{'F1-Score':<25} | {'29.29%':<20} | {f'{f1*100:.2f}%':<20}")
    report.append(f"{'FPR (False Alarm Rate)':<25} | {'4.42%':<20} | {f'{fpr*100:.2f}%':<20}")
    report.append(f"{'ROC-AUC':<25} | {'0.7570':<20} | {f'{roc_auc:.4f}':<20}")
    report.append(f"{'Attacks Missed (FN)':<25} | {'37,272':<20} | {f'{fn:,}':<20}")
    report.append("=" * 70)

    report_str = "\n".join(report)
    print(report_str)

    with open(RESULTS_TXT, "w") as f:
        f.write(report_str)
    print(f"\n[+] Full report saved to: {RESULTS_TXT}")
    print(f"[+] Total execution time: {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
