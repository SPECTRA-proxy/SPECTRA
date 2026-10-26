#!/usr/bin/env python3
"""
SPECTRA Module 4 - Model Unit Test Script
Evaluates concrete test cases across the 8-feature telemetry vector using canonical units:
  - packet_size, dmean: Bytes
  - request_rate: Packets / second
  - connection_count: Active TCP flows
  - inter_arrival_time, sjit, synack: Milliseconds (ms)
  - sttl: Hops
"""

import pandas as pd
import joblib

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

test_cases = [
    {
        "name": "Benign TLS / HTTP Request",
        "telemetry": {
            "packet_size": 520,
            "request_rate": 4.8,
            "connection_count": 2,
            "inter_arrival_time": 48.0,  # ms
            "sttl": 64,
            "sjit": 2.8,                 # ms
            "dmean": 1280,
            "synack": 11.5               # ms
        }
    },
    {
        "name": "L7 DoS / Request Flood",
        "telemetry": {
            "packet_size": 520,
            "request_rate": 350.0,
            "connection_count": 60,
            "inter_arrival_time": 1.0,   # ms
            "sttl": 64,
            "sjit": 0.5,                 # ms
            "dmean": 400,
            "synack": 12.0               # ms
        }
    },
    {
        "name": "Oversized Payload / Exfiltration",
        "telemetry": {
            "packet_size": 9800,
            "request_rate": 6.0,
            "connection_count": 2,
            "inter_arrival_time": 45.0,  # ms
            "sttl": 64,
            "sjit": 3.0,                 # ms
            "dmean": 1250,
            "synack": 12.0               # ms
        }
    },
    {
        "name": "TTL Spoofing & High Jitter Drift",
        "telemetry": {
            "packet_size": 520,
            "request_rate": 5.0,
            "connection_count": 2,
            "inter_arrival_time": 50.0,  # ms
            "sttl": 255,
            "sjit": 250.0,               # ms
            "dmean": 1250,
            "synack": 90.0               # ms
        }
    }
]

df = pd.DataFrame([tc["telemetry"] for tc in test_cases])[FEATURES]
predictions = model.predict(df)
scores = model.decision_function(df)

print("=" * 60)
print("       SPECTRA M4: 8-FEATURE UNIT TESTS (UNITS: ms, bytes)")
print("=" * 60)

for i, tc in enumerate(test_cases):
    pred = predictions[i]
    score = scores[i]
    is_anomaly = (pred == -1)

    print(f"\nTest Case {i+1}: {tc['name']}")
    print("-" * 40)
    for k, v in tc["telemetry"].items():
        print(f"  {k:<20}: {v}")
    print(f"  Isolation Score     : {score:.4f}")
    print(f"  Anomaly Detected    : {'TRUE' if is_anomaly else 'FALSE'}")