"""Generate publication-ready figures for the real UNSW-NB15 M4 evaluation.

Produces:
  1. results/unsw_nb15_attack_recall.png
  2. results/unsw_nb15_roc_confusion.png
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, roc_curve, roc_auc_score
from sklearn.model_selection import train_test_split

from evaluate_unsw_nb15 import (
    FEATURES,
    MFA_THRESHOLD,
    RANDOM_STATE,
    load_and_map,
    calibrate,
    percentile_risk,
)
from paths import DATA_DIR, RESULTS_DIR


def plot_attack_recall():
    """Figure 1: Horizontal bar chart of recall across attack categories."""
    categories = [
        "Generic",
        "Fuzzers",
        "Backdoor",
        "Analysis",
        "Worms",
        "Shellcode",
        "DoS",
        "Reconnaissance",
        "Exploits",
    ]
    recalls = [37.78, 8.43, 5.32, 4.87, 4.55, 4.50, 2.74, 1.60, 1.52]

    # Invert to display highest detection rate at the top
    categories = categories[::-1]
    recalls = recalls[::-1]

    plt.figure(figsize=(10, 6))
    bars = plt.barh(categories, recalls, color="#1f77b4", edgecolor="#0d47a1", height=0.6)
    plt.xlim(0, 45)
    plt.xlabel("Detection Recall (%)", fontsize=11, fontweight="bold")
    plt.title(
        "REAL UNSW-NB15 M4 BASELINE — Attack Category Recall\n"
        "(4 Flow Features: packet_size, request_rate, connection_count, inter_arrival_time)",
        fontsize=12,
        fontweight="bold",
        pad=15,
    )
    plt.grid(axis="x", linestyle="--", alpha=0.6)

    for bar, val in zip(bars, recalls):
        plt.text(
            val + 0.6,
            bar.get_y() + bar.get_height() / 2.0,
            f"{val:.2f}%",
            va="center",
            ha="left",
            fontsize=10,
            fontweight="bold",
        )

    out_path = RESULTS_DIR / "unsw_nb15_attack_recall.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved: {out_path}")


def plot_roc_and_confusion():
    """Figure 2: Real ROC curve from continuous risk scores & Confusion Matrix."""
    train_path = DATA_DIR / "UNSW_NB15_training-set.csv"
    test_path = DATA_DIR / "UNSW_NB15_testing-set.csv"

    train = load_and_map(train_path)
    test = load_and_map(test_path)

    normal_train = train[train["label"] == 0].copy()
    normal_fit, normal_calibration = train_test_split(
        normal_train,
        test_size=0.20,
        random_state=RANDOM_STATE,
    )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=RANDOM_STATE,
    )
    model.fit(normal_fit[FEATURES])
    ref = calibrate(model, normal_calibration)

    risk = percentile_risk(model, ref, test)
    y_true = test["label"].astype(int).to_numpy()
    y_pred = (risk >= MFA_THRESHOLD).astype(int)

    fpr_curve, tpr_curve, _ = roc_curve(y_true, risk)
    auc_val = roc_auc_score(y_true, risk)
    print(f"Computed ROC-AUC: {auc_val:.4f}")

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr_point = fp / (tn + fp)
    tpr_point = tp / (fn + tp)

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Left: ROC Curve
    ax_roc = axes[0]
    ax_roc.plot(fpr_curve, tpr_curve, color="#2ca02c", lw=2, label=f"ROC Curve (AUC = {auc_val:.4f})")
    ax_roc.plot([0, 1], [0, 1], color="gray", linestyle="--", lw=1.2, label="Random Chance")
    ax_roc.scatter(
        [fpr_point],
        [tpr_point],
        color="crimson",
        s=90,
        zorder=5,
        label=f"MFA Threshold (risk ≥ 0.970)\nFPR = {fpr_point*100:.2f}%, Recall = {tpr_point*100:.2f}%",
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
    cax = ax_cm.imshow(cm, interpolation="nearest", cmap="Blues")
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

    # Metrics annotation box
    metrics_text = (
        "REAL UNSW-NB15 METRICS:\n"
        "• Precision : 83.12%\n"
        "• Recall    : 17.78%\n"
        "• F1-Score  : 29.29%\n"
        "• FPR       : 4.42%\n"
        "• ROC-AUC   : 0.7570\n"
        "• Med. Latency: 5.720 ms\n"
        "• P95 Latency : 8.439 ms"
    )
    fig.text(
        0.50,
        -0.08,
        metrics_text,
        ha="center",
        fontsize=10,
        fontfamily="monospace",
        bbox=dict(boxstyle="round,pad=0.6", facecolor="#f8f9fa", edgecolor="#ced4da"),
    )

    fig.suptitle(
        "REAL UNSW-NB15 M4 BASELINE — Detection & Latency Performance",
        fontsize=14,
        fontweight="bold",
        y=1.02,
    )

    out_path = RESULTS_DIR / "unsw_nb15_roc_confusion.png"
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    plot_attack_recall()
    plot_roc_and_confusion()
