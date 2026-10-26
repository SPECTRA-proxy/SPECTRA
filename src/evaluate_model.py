"""Synthetic sanity evaluation for the M4 prototype.

This is deliberately labeled synthetic. It is not a real-world performance
claim. Use evaluate_unsw_nb15.py for the real-dataset evaluation.
"""

import time
import numpy as np
import pandas as pd

from m4_interface import (
    FEATURES,
    MFA_THRESHOLD,
    REFERENCE_ANOMALY_SCORES,
    calculate_risk,
    model,
)
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

RANDOM_STATE = 100
rng = np.random.default_rng(RANDOM_STATE)


def generate_normal(n):
    return pd.DataFrame({
        "packet_size": rng.normal(500, 80, n),
        "request_rate": rng.normal(5, 1.5, n),
        "connection_count": rng.normal(3, 1, n),
        "inter_arrival_time": rng.normal(0.2, 0.05, n),
    }).clip(lower=0.001)


def generate_anomaly(n):
    return pd.DataFrame({
        "packet_size": rng.uniform(5000, 15000, n),
        "request_rate": rng.uniform(100, 500, n),
        "connection_count": rng.uniform(30, 100, n),
        "inter_arrival_time": rng.uniform(0.001, 0.01, n),
    })


def main():
    n_normal = 200
    n_anomaly = 50

    normal = generate_normal(n_normal)
    anomaly = generate_anomaly(n_anomaly)
    data = pd.concat([normal, anomaly], ignore_index=True)
    y_true = np.array([0] * n_normal + [1] * n_anomaly)

    scores = model.decision_function(data[FEATURES])
    risk = np.array([calculate_risk(score) for score in scores])
    y_pred = (risk >= MFA_THRESHOLD).astype(int)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, risk)
    cm = confusion_matrix(y_true, y_pred)
    fpr = cm[0, 1] / (cm[0, 0] + cm[0, 1]) if cm[0].sum() else 0.0

    # Warm-up before timing to avoid measuring first-call overhead.
    for _ in range(20):
        model.decision_function(data[FEATURES].iloc[[0]])

    timings = []
    for _ in range(100):
        start = time.perf_counter()
        model.decision_function(data[FEATURES].iloc[[0]])
        timings.append((time.perf_counter() - start) * 1000)

    print("========================================")
    print("     SPECTRA M4 SYNTHETIC SANITY TEST")
    print("========================================")
    print(f"Normal samples    : {n_normal}")
    print(f"Anomaly samples   : {n_anomaly}")
    print("\nNOTE: Synthetic result only; not a real-world benchmark.")
    print("\n----------------------------------------")
    print("Metrics")
    print("----------------------------------------")
    print(f"Precision         : {precision:.4f}")
    print(f"Recall            : {recall:.4f}")
    print(f"F1-score          : {f1:.4f}")
    print(f"ROC-AUC           : {auc:.4f}")
    print(f"False-positive rate: {fpr:.4f}")
    print(f"Median inference  : {np.median(timings):.3f} ms")
    print(f"P95 inference     : {np.percentile(timings, 95):.3f} ms")
    print("\nConfusion matrix:")
    print(cm)


if __name__ == "__main__":
    main()
