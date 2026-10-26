#!/usr/bin/env python3
"""
SPECTRA Module 4 - Model Evaluation Script
Evaluates the trained 8-feature Isolation Forest against normal and anomalous
network traffic test distributions using the canonical units contract:
  - packet_size, dmean: Bytes
  - request_rate: Packets / second
  - connection_count: Active TCP flows
  - inter_arrival_time, sjit, synack: Milliseconds (ms)
  - sttl: Hops (integer)
"""

import numpy as np
import pandas as pd
import joblib

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

np.random.seed(100)

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

# -----------------------------------------------------------------------------
# 1. Generate NORMAL test data (500 samples in canonical units)
# -----------------------------------------------------------------------------
n_normal = 500

normal_test = pd.DataFrame({
    "packet_size": np.clip(np.random.normal(500, 80, n_normal), 64, 1500),
    "request_rate": np.clip(np.random.normal(5.0, 1.5, n_normal), 0.1, 20.0),
    "connection_count": np.clip(np.round(np.random.normal(3.0, 1.0, n_normal)), 1, 8),
    "inter_arrival_time": np.clip(np.random.normal(50.0, 15.0, n_normal), 5.0, 500.0), # ms
    "sttl": np.clip(64 + np.random.choice([0, -1, -2], size=n_normal, p=[0.85, 0.12, 0.03]), 50, 64),
    "sjit": np.clip(np.random.normal(3.0, 1.0, n_normal), 0.1, 20.0),                  # ms
    "dmean": np.clip(np.random.normal(1250, 120, n_normal), 200, 1500),
    "synack": np.clip(np.random.normal(12.0, 3.0, n_normal), 2.0, 50.0)                # ms
})

# -----------------------------------------------------------------------------
# 2. Generate ANOMALOUS test data (100 samples across multiple attack vectors)
# -----------------------------------------------------------------------------
n_anomaly = 100

anomaly_test = pd.DataFrame({
    "packet_size": np.random.uniform(3000, 12000, n_anomaly),
    "request_rate": np.random.uniform(80, 500, n_anomaly),
    "connection_count": np.random.uniform(20, 100, n_anomaly),
    "inter_arrival_time": np.random.uniform(0.5, 5.0, n_anomaly),     # micro-burst ms
    "sttl": np.random.choice([128, 255, 32, 10], size=n_anomaly),
    "sjit": np.random.uniform(50.0, 300.0, n_anomaly),                # high jitter ms
    "dmean": np.random.uniform(20, 150, n_anomaly),
    "synack": np.random.uniform(80.0, 500.0, n_anomaly)               # slow handshake ms
})

# Combine test data
test_data = pd.concat([normal_test, anomaly_test], ignore_index=True)

# Ground truth: 0 = Normal, 1 = Anomaly
y_true = np.array([0] * n_normal + [1] * n_anomaly)

# Predictions: Isolation Forest (+1 = Normal, -1 = Anomaly)
predictions = model.predict(test_data[FEATURES])
y_pred = np.where(predictions == -1, 1, 0)

precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)
cm = confusion_matrix(y_true, y_pred)

print("=" * 60)
print("       SPECTRA M4: 8-FEATURE MODEL EVALUATION")
print("=" * 60)
print(f"Normal test samples   : {n_normal}")
print(f"Anomalous test samples: {n_anomaly}")
print(f"Total test samples    : {len(test_data)}")
print("-" * 60)
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1-score  : {f1:.4f}")
print("-" * 60)
print("Confusion Matrix [TN, FP; FN, TP]:")
print(cm)
print("-" * 60)
print("Classification Report:")
print(classification_report(y_true, y_pred, target_names=["Normal", "Anomaly"], zero_division=0))