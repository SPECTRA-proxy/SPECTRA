#!/usr/bin/env python3
"""
SPECTRA Module 4 - Multi-Anomaly Type Analysis
Tests Isolation Forest detection sensitivity across individual telemetry dimensions
using canonical units (ms, bytes, count, pkts/sec):
  1. High request rate (L7 volumetric flood)
  2. Large packet size (Oversized payload / buffer overflow)
  3. High connection count (SYN flood / resource exhaustion)
  4. TTL divergence (IP spoofing / suspicious routing)
  5. High jitter (Tor / network tunneling)
  6. High handshake latency (Slowloris / SYN scanning)
  7. Combined multi-vector anomaly
"""

import numpy as np
import pandas as pd
import joblib

from sklearn.metrics import precision_score, recall_score, f1_score

np.random.seed(200)

MODEL_PATH = "results/isolation_forest.pkl"
model = joblib.load(MODEL_PATH)

FEATURES = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time",
    "sttl",
    "sjit",
    "dmean",
    "synack"
]

def generate_normal(n):
    return pd.DataFrame({
        "packet_size": np.clip(np.random.normal(500, 80, n), 64, 1500),
        "request_rate": np.clip(np.random.normal(5.0, 1.5, n), 0.1, 20.0),
        "connection_count": np.clip(np.round(np.random.normal(3.0, 1.0, n)), 1, 8),
        "inter_arrival_time": np.clip(np.random.normal(50.0, 15.0, n), 5.0, 500.0), # ms
        "sttl": np.clip(64 + np.random.choice([0, -1, -2], size=n, p=[0.85, 0.12, 0.03]), 50, 64),
        "sjit": np.clip(np.random.normal(3.0, 1.0, n), 0.1, 20.0),                  # ms
        "dmean": np.clip(np.random.normal(1250, 120, n), 200, 1500),
        "synack": np.clip(np.random.normal(12.0, 3.0, n), 2.0, 50.0)                # ms
    })

def generate_anomaly(anomaly_type, n):
    data = generate_normal(n)

    if anomaly_type == "high_request_rate":
        data["request_rate"] = np.random.uniform(150, 450, n)
        data["inter_arrival_time"] = np.random.uniform(1.0, 5.0, n)

    elif anomaly_type == "large_packet":
        data["packet_size"] = np.random.uniform(4000, 15000, n)

    elif anomaly_type == "high_connections":
        data["connection_count"] = np.random.uniform(30, 90, n)

    elif anomaly_type == "ttl_spoofing":
        data["sttl"] = np.random.choice([128, 255, 32, 10], size=n)

    elif anomaly_type == "high_jitter":
        data["sjit"] = np.random.uniform(80.0, 400.0, n) # ms

    elif anomaly_type == "handshake_delay":
        data["synack"] = np.random.uniform(90.0, 500.0, n) # ms

    elif anomaly_type == "combined":
        data["packet_size"] = np.random.uniform(4000, 12000, n)
        data["request_rate"] = np.random.uniform(150, 400, n)
        data["connection_count"] = np.random.uniform(30, 90, n)
        data["inter_arrival_time"] = np.random.uniform(1.0, 5.0, n)
        data["sttl"] = np.random.choice([128, 255], size=n)
        data["sjit"] = np.random.uniform(80.0, 300.0, n)
        data["dmean"] = np.random.uniform(50, 200, n)
        data["synack"] = np.random.uniform(80.0, 300.0, n)

    return data

n = 100
anomaly_types = [
    "high_request_rate",
    "large_packet",
    "high_connections",
    "ttl_spoofing",
    "high_jitter",
    "handshake_delay",
    "combined"
]

print("=" * 60)
print("      SPECTRA M4: 8-DIMENSION ANOMALY ANALYSIS (UNITS: ms, bytes)")
print("=" * 60)

for atype in anomaly_types:
    normal = generate_normal(n)
    anomaly = generate_anomaly(atype, n)
    test_data = pd.concat([normal, anomaly], ignore_index=True)

    y_true = np.array([0] * n + [1] * n)
    preds = model.predict(test_data[FEATURES])
    y_pred = np.where(preds == -1, 1, 0)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print(f"\nAnomaly Type: {atype:<20}")
    print(f"  Precision : {precision:.2f}")
    print(f"  Recall    : {recall:.2f}")
    print(f"  F1-Score  : {f1:.2f}")

print("\n" + "=" * 60)
print("Analysis completed successfully.")
print("=" * 60)