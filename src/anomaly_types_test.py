"""Synthetic anomaly-type sanity checks.

These results are for debugging/demo purposes only. They must not be presented
as real-world detection performance.
"""

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

from m4_interface import FEATURES, MFA_THRESHOLD, model, calculate_risk

rng = np.random.default_rng(200)


def generate_normal(n):
    return pd.DataFrame({
        "packet_size": rng.normal(500, 80, n),
        "request_rate": rng.normal(5, 1.5, n),
        "connection_count": rng.normal(3, 1, n),
        "inter_arrival_time": rng.normal(0.2, 0.05, n),
    }).clip(lower=0.001)


def generate_anomaly(anomaly_type, n):
    data = generate_normal(n)

    if anomaly_type == "high_request_rate":
        data["request_rate"] = rng.uniform(100, 300, n)
    elif anomaly_type == "large_packet":
        data["packet_size"] = rng.uniform(5000, 10000, n)
    elif anomaly_type == "high_connections":
        data["connection_count"] = rng.uniform(30, 80, n)
    elif anomaly_type == "combined":
        data["packet_size"] = rng.uniform(5000, 10000, n)
        data["request_rate"] = rng.uniform(100, 300, n)
        data["connection_count"] = rng.uniform(30, 80, n)
        data["inter_arrival_time"] = rng.uniform(0.001, 0.01, n)

    return data


print("========================================")
print(" SPECTRA M4 SYNTHETIC ANOMALY ANALYSIS")
print("========================================")

for anomaly_type in [
    "high_request_rate",
    "large_packet",
    "high_connections",
    "combined",
]:
    n = 50
    normal = generate_normal(n)
    anomaly = generate_anomaly(anomaly_type, n)
    test_data = pd.concat([normal, anomaly], ignore_index=True)
    y_true = np.array([0] * n + [1] * n)

    model_scores = model.decision_function(test_data[FEATURES])
    risks = np.array([calculate_risk(score) for score in model_scores])
    y_pred = (risks >= MFA_THRESHOLD).astype(int)

    print("\n----------------------------------------")
    print(f"Anomaly type: {anomaly_type}")
    print(f"Precision    : {precision_score(y_true, y_pred, zero_division=0):.2f}")
    print(f"Recall       : {recall_score(y_true, y_pred, zero_division=0):.2f}")
    print(f"F1-score     : {f1_score(y_true, y_pred, zero_division=0):.2f}")

print("\nSynthetic analysis completed.")
