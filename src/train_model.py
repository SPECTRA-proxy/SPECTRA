#!/usr/bin/env python3
"""
SPECTRA Module 4 - Isolation Forest Model Training
Trains an Isolation Forest anomaly detector on 10,000 normal baseline samples
across the 8 UNSW-NB15 aligned telemetries:
  - packet_size (smean)
  - request_rate (rate)
  - connection_count (ct_srv_src)
  - inter_arrival_time (sinpkt)
  - sttl
  - sjit
  - dmean
  - synack
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

# Define canonical 8-feature vector
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

def train_isolation_forest():
    data_path = "data/normal_telemetry.csv"
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Training dataset not found at {data_path}. Run generate_dataset.py first.")

    data = pd.read_csv(data_path)
    X = data[FEATURES]

    print("=" * 60)
    print("      SPECTRA M4: TRAINING 8-FEATURE ISOLATION FOREST")
    print("=" * 60)
    print(f"Training samples : {len(X):,}")
    print(f"Feature count    : {len(FEATURES)}")
    print(f"Features         : {FEATURES}")

    # Isolation Forest configuration
    # contamination=0.03 aligns with ~3% false positive tolerance in Zero-Trust networks
    model = IsolationForest(
        n_estimators=150,
        contamination=0.03,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X)

    os.makedirs("results", exist_ok=True)
    model_path = "results/isolation_forest.pkl"
    joblib.dump(model, model_path)

    print("\nTraining completed successfully.")
    print(f"Model saved to   : {model_path}")

if __name__ == "__main__":
    train_isolation_forest()