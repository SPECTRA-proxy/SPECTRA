#!/usr/bin/env python3
"""
SPECTRA M4: Publication-ready Visualization for 8-Dimensional UNSW-NB15 Model
Generates:
  1. results/unsw_nb15_8d_attack_recall.png
  2. results/unsw_nb15_8d_roc_confusion.png
  3. results/unsw_nb15_head_to_head_comparison.png
"""

import os
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import confusion_matrix, roc_curve, roc_auc_score

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = "results/isolation_forest.pkl"
CALIBRATION_PATH = "results/risk_calibration.npz"
TEST_PATH = "data/UNSW_NB15_testing-set.csv"

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

def generate_visualizations():
    print("[+] Loading test data and trained 8D model...")
    test_df = pd.read_csv(TEST_PATH, encoding="utf-8-sig")
    mapped = test_df.rename(columns=UNSW_COLUMNS).copy()
    if mapped["synack"].dropna().mean() < 1.0:
        mapped["synack"] = mapped["synack"] * 1000.0
    for f in FEATURES_8D:
        mapped[f] = mapped[f].fillna(0.0)

    model = joblib.load(MODEL_PATH)
    calib = np.load(CALIBRATION_PATH)
    ref_scores = calib["anomaly_scores"]
    MFA_THRESHOLD = float(calib["mfa_threshold"])

    X_test = mapped[FEATURES_8D]
    y_true = mapped["label"].values

    raw_scores = model.decision_function(X_test)
    test_anomaly_scores = -raw_scores
    positions = np.searchsorted(ref_scores, test_anomaly_scores, side="right")
    risk_scores = np.clip(positions / len(ref_scores), 0.0, 1.0)
    y_pred = (risk_scores >= MFA_THRESHOLD).astype(int)

    # -------------------------------------------------------------
    # 1. Attack Recall by Category
    # -------------------------------------------------------------
    cat_recalls = {}
    for cat in test_df["attack_cat"].dropna().unique():
        if cat == "Normal":
            continue
        mask = (test_df["attack_cat"] == cat).values
        if sum(mask) > 0:
            rec = np.sum(y_pred[mask] == 1) / sum(mask)
            cat_recalls[cat] = rec * 100.0

    sorted_cats = sorted(cat_recalls.items(), key=lambda x: x[1])
    categories = [k for k, v in sorted_cats]
    recalls = [v for k, v in sorted_cats]

    plt.figure(figsize=(10, 6))
    bars = plt.barh(categories, recalls, color="#008080", edgecolor="#004d40", height=0.6)
    plt.xlim(0, 35)
    plt.xlabel("Detection Recall (%)", fontsize=11, fontweight="bold")
    plt.title(
        "SPECTRA M4 8-DIMENSIONAL UPGRADE — Attack Category Recall\n"
        "(8 Features: smean, rate, ct_srv_src, sinpkt, sttl, sjit, dmean, synack)",
        fontsize=12,
        fontweight="bold",
        pad=15,
    )
    plt.grid(axis="x", linestyle="--", alpha=0.6)

    for bar, val in zip(bars, recalls):
        plt.text(
            val + 0.4,
            bar.get_y() + bar.get_height() / 2.0,
            f"{val:.2f}%",
            va="center",
            ha="left",
            fontsize=10,
            fontweight="bold",
        )

    out_path1 = RESULTS_DIR / "unsw_nb15_8d_attack_recall.png"
    plt.tight_layout()
    plt.savefig(out_path1, dpi=300)
    plt.close()
    print(f"[+] Saved: {out_path1}")

    # -------------------------------------------------------------
    # 2. ROC Curve and Confusion Matrix
    # -------------------------------------------------------------
    fpr_curve, tpr_curve, _ = roc_curve(y_true, risk_scores)
    auc_val = roc_auc_score(y_true, risk_scores)

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr_point = fp / (tn + fp)
    tpr_point = tp / (fn + tp)

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Left: ROC Curve
    ax_roc = axes[0]
    ax_roc.plot(fpr_curve, tpr_curve, color="#008080", lw=2.5, label=f"8D Model (AUC = {auc_val:.4f})")
    ax_roc.plot([0, 1], [0, 1], color="gray", linestyle="--", lw=1.2, label="Random Baseline (AUC = 0.50)")
    ax_roc.scatter(
        [fpr_point],
        [tpr_point],
        color="crimson",
        s=100,
        zorder=5,
        label=f"MFA Decision Point (risk ≥ {MFA_THRESHOLD:.3f})\nFPR = {fpr_point*100:.2f}%, Recall = {tpr_point*100:.2f}%",
    )
    ax_roc.set_xlim([-0.02, 1.02])
    ax_roc.set_ylim([-0.02, 1.02])
    ax_roc.set_xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
    ax_roc.set_ylabel("True Positive Rate (Recall)", fontsize=11, fontweight="bold")
    ax_roc.set_title("ROC Curve (Continuous Risk Scores)", fontsize=12, fontweight="bold")
    ax_roc.legend(loc="lower right", fontsize=10)
    ax_roc.grid(True, linestyle="--", alpha=0.5)

    # Right: Confusion Matrix Heatmap
    ax_cm = axes[1]
    cax = ax_cm.imshow(cm, interpolation="nearest", cmap="BuGn")
    fig.colorbar(cax, ax=ax_cm, fraction=0.046, pad=0.04)
    ax_cm.set_xticks([0, 1])
    ax_cm.set_yticks([0, 1])
    ax_cm.set_xticklabels(["Pred Normal", "Pred Attack"], fontsize=10, fontweight="bold")
    ax_cm.set_yticklabels(["True Normal", "True Attack"], fontsize=10, fontweight="bold")
    ax_cm.set_title("Confusion Matrix (Test N = 82,332)", fontsize=12, fontweight="bold")

    cell_labels = [
        [f"TN\n{tn:,}\n({tn/(tn+fp)*100:.1f}%)", f"FP\n{fp:,}\n({fp/(tn+fp)*100:.1f}%)"],
        [f"FN\n{fn:,}\n({fn/(fn+tp)*100:.1f}%)", f"TP\n{tp:,}\n({tp/(fn+tp)*100:.1f}%)"],
    ]
    for i in range(2):
        for j in range(2):
            color = "white" if cm[i, j] > cm.max() / 2 else "black"
            ax_cm.text(j, i, cell_labels[i][j], ha="center", va="center", color=color, fontsize=11, fontweight="bold")

    fig.suptitle(
        "SPECTRA M4 8-DIMENSIONAL MODEL — UNSW-NB15 Benchmark Evaluation",
        fontsize=14,
        fontweight="bold",
        y=1.02,
    )

    out_path2 = RESULTS_DIR / "unsw_nb15_8d_roc_confusion.png"
    plt.tight_layout()
    plt.savefig(out_path2, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {out_path2}")

    # -------------------------------------------------------------
    # 3. Head-to-Head Comparison Chart (4D vs 8D)
    # -------------------------------------------------------------
    metrics = ["ROC-AUC", "Feature Dimensions", "Inference Latency (µs/pkt)"]
    baseline_vals = [0.7570, 4, 5720.0] # 5.72ms = 5720us
    upgrade_vals = [auc_val, 8, 3.02]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    # Subplot 1: ROC-AUC Comparison
    x = np.arange(1)
    width = 0.35
    ax1.bar(x - width/2, [0.7570], width, label="4D Baseline (Teammate)", color="#4682b4")
    ax1.bar(x + width/2, [auc_val], width, label="8D Upgrade (Ours)", color="#2e8b57")
    ax1.set_ylabel("ROC-AUC Score", fontsize=11, fontweight="bold")
    ax1.set_title("Overall Discrimination Ability (ROC-AUC)", fontsize=12, fontweight="bold")
    ax1.set_ylim([0.65, 0.85])
    ax1.set_xticks(x)
    ax1.set_xticklabels(["UNSW-NB15 Test (82,332 samples)"], fontweight="bold")
    ax1.grid(axis="y", linestyle="--", alpha=0.5)
    ax1.legend(loc="lower right")
    ax1.text(-width/2, 0.7570 + 0.005, "0.7570", ha="center", fontweight="bold")
    ax1.text(+width/2, auc_val + 0.005, f"{auc_val:.4f}", ha="center", fontweight="bold")

    # Subplot 2: Feature Coverage & Vector Completeness
    feature_labels = [
        "Packet Size\n(smean)",
        "Rate\n(rate)",
        "Flow Count\n(ct_srv_src)",
        "Inter-Arrival\n(sinpkt)",
        "TTL Hops\n(sttl)",
        "Jitter\n(sjit)",
        "Resp Size\n(dmean)",
        "SYN-ACK Latency\n(synack)"
    ]
    baseline_has = [1, 1, 1, 1, 0, 0, 0, 0]
    upgrade_has =  [1, 1, 1, 1, 1, 1, 1, 1]

    y_pos = np.arange(len(feature_labels))
    ax2.barh(y_pos - 0.2, baseline_has, height=0.35, label="4D Baseline", color="#4682b4")
    ax2.barh(y_pos + 0.2, upgrade_has, height=0.35, label="8D Upgrade (Ours)", color="#2e8b57")
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(feature_labels, fontsize=9)
    ax2.set_xticks([0, 1])
    ax2.set_xticklabels(["Missing (Blind)", "Covered (Monitored)"], fontweight="bold")
    ax2.set_title("Feature Vector Telemetry Coverage", fontsize=12, fontweight="bold")
    ax2.legend(loc="lower right")
    ax2.grid(axis="x", linestyle="--", alpha=0.5)

    fig.suptitle(
        "SPECTRA Review 2: 4-Feature Baseline vs. 8-Feature Upgrade Comparison",
        fontsize=14,
        fontweight="bold",
        y=1.02
    )
    out_path3 = RESULTS_DIR / "unsw_nb15_head_to_head_comparison.png"
    plt.tight_layout()
    plt.savefig(out_path3, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {out_path3}")

if __name__ == "__main__":
    generate_visualizations()
