#!/usr/bin/env python3
"""
SPECTRA Module 4 - Visualization Script
Plots 2D behavioral distributions comparing normal vs anomalous telemetry
in canonical units (ms, bytes, count, pkts/sec).
"""

import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

np.random.seed(300)

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

# Generate normal samples
n_normal = 200
normal = pd.DataFrame({
    "packet_size": np.clip(np.random.normal(500, 80, n_normal), 64, 1500),
    "request_rate": np.clip(np.random.normal(5.0, 1.5, n_normal), 0.1, 20.0),
    "connection_count": np.clip(np.round(np.random.normal(3.0, 1.0, n_normal)), 1, 8),
    "inter_arrival_time": np.clip(np.random.normal(50.0, 15.0, n_normal), 5.0, 500.0), # ms
    "sttl": np.clip(64 + np.random.choice([0, -1, -2], size=n_normal, p=[0.85, 0.12, 0.03]), 50, 64),
    "sjit": np.clip(np.random.normal(3.0, 1.0, n_normal), 0.1, 20.0),                  # ms
    "dmean": np.clip(np.random.normal(1250, 120, n_normal), 200, 1500),
    "synack": np.clip(np.random.normal(12.0, 3.0, n_normal), 2.0, 50.0)                # ms
})

# Generate anomalous samples
n_anomaly = 50
anomaly = pd.DataFrame({
    "packet_size": np.random.uniform(3000, 10000, n_anomaly),
    "request_rate": np.random.uniform(100, 350, n_anomaly),
    "connection_count": np.random.uniform(30, 80, n_anomaly),
    "inter_arrival_time": np.random.uniform(1.0, 10.0, n_anomaly),                      # ms
    "sttl": np.random.choice([128, 255], size=n_anomaly),
    "sjit": np.random.uniform(50.0, 250.0, n_anomaly),                                  # ms
    "dmean": np.random.uniform(100, 400, n_anomaly),
    "synack": np.random.uniform(80.0, 350.0, n_anomaly)                                 # ms
})

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Packet Size vs Request Rate
ax1.scatter(normal["packet_size"], normal["request_rate"], color="dodgerblue", alpha=0.7, label="Normal Telemetry")
ax1.scatter(anomaly["packet_size"], anomaly["request_rate"], color="crimson", alpha=0.8, marker="^", label="Anomalous Probe")
ax1.set_xlabel("Packet Size (Bytes)")
ax1.set_ylabel("Request Rate (pkts/sec)")
ax1.set_title("SPECTRA M4: Volumetric Behavior (Size vs Rate)")
ax1.grid(True, linestyle="--", alpha=0.6)
ax1.legend()

# Plot 2: Source Jitter vs Handshake Latency
ax2.scatter(normal["sjit"], normal["synack"], color="dodgerblue", alpha=0.7, label="Normal Telemetry")
ax2.scatter(anomaly["sjit"], anomaly["synack"], color="crimson", alpha=0.8, marker="^", label="Anomalous Probe")
ax2.set_xlabel("Source Jitter (ms)")
ax2.set_ylabel("Handshake Latency / synack (ms)")
ax2.set_title("SPECTRA M4: Timing Jitter & TCP Latency (ms)")
ax2.grid(True, linestyle="--", alpha=0.6)
ax2.legend()

plt.tight_layout()
os.makedirs("results", exist_ok=True)
output_path = "results/network_behavior.png"
plt.savefig(output_path, dpi=300)
plt.close()

print(f"Visualization saved successfully to: {output_path}")