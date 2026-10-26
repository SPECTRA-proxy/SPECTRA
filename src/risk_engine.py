#!/usr/bin/env python3
"""
SPECTRA Module 4 - Interactive AI Risk Engine
Evaluates network telemetry across the 8-feature vector and outputs
the risk score and Zero-Trust policy enforcement decision.
Canonical units:
  - packet_size, dmean: Bytes
  - request_rate: Packets / second
  - connection_count: Active TCP flows
  - inter_arrival_time, sjit, synack: Milliseconds (ms)
  - sttl: Hops
"""

import sys
import math
import joblib
import pandas as pd

MODEL_PATH = "results/isolation_forest.pkl"

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

def calculate_risk(model_score):
    return 1.0 / (1.0 + math.exp(model_score / 0.1))

def get_action(risk):
    if risk < 0.30:
        return "ALLOW"
    elif risk < 0.70:
        return "MFA / MONITOR"
    else:
        return "DROP"

def main():
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"[!] Error loading model from {MODEL_PATH}: {e}")
        print("[!] Please run `python3 src/train_model.py` first.")
        sys.exit(1)

    print("=" * 60)
    print("        SPECTRA AI RISK ENGINE (8-FEATURE, CANONICAL UNITS)")
    print("=" * 60)
    print("\nEnter network telemetry:")

    def get_input(prompt, default):
        val = input(f"{prompt} [default {default}]: ").strip()
        return float(val) if val else default

    packet_size = get_input("1. Packet size (Bytes)", 512.0)
    request_rate = get_input("2. Request rate (pkts/sec)", 5.0)
    connection_count = get_input("3. Connection count (flows)", 2.0)
    inter_arrival_time = get_input("4. Inter-arrival time (Milliseconds, ms)", 45.0)
    sttl = get_input("5. Source TTL (sttl, hops)", 64.0)
    sjit = get_input("6. Source jitter (Milliseconds, ms)", 3.0)
    dmean = get_input("7. Destination mean size (Bytes)", 1250.0)
    synack = get_input("8. Handshake RTT / synack (Milliseconds, ms)", 12.0)

    # Auto-scale if user typed seconds (< 1.0)
    if 0.0 < inter_arrival_time < 1.0:
        inter_arrival_time *= 1000.0
    if 0.0 < sjit < 1.0:
        sjit *= 1000.0
    if 0.0 < synack < 1.0:
        synack *= 1000.0

    telemetry = pd.DataFrame([{
        "packet_size": packet_size,
        "request_rate": request_rate,
        "connection_count": connection_count,
        "inter_arrival_time": inter_arrival_time,
        "sttl": sttl,
        "sjit": sjit,
        "dmean": dmean,
        "synack": synack
    }])[FEATURES]

    prediction = model.predict(telemetry)[0]
    model_score = model.decision_function(telemetry)[0]
    risk = calculate_risk(model_score)
    action = get_action(risk)

    print("\n" + "=" * 60)
    print("             ANALYSIS RESULT")
    print("=" * 60)
    print(f"Packet Size (smean)  : {packet_size:.0f} B")
    print(f"Request Rate         : {request_rate:.1f} pkts/s")
    print(f"Connection Count     : {connection_count:.0f} flows")
    print(f"Inter-arrival (sinpkt: {inter_arrival_time:.2f} ms")
    print(f"Source TTL (sttl)    : {sttl:.0f}")
    print(f"Source Jitter (sjit) : {sjit:.2f} ms")
    print(f"Destination Mean     : {dmean:.0f} B")
    print(f"Handshake RTT        : {synack:.2f} ms")
    print("-" * 60)
    print(f"Isolation Score      : {model_score:.4f}")
    print(f"Anomaly Detected     : {'TRUE' if prediction == -1 else 'FALSE'}")
    print(f"Risk Score           : {risk:.2f}")
    print(f"Decision             : {action}")
    print("=" * 60)

if __name__ == "__main__":
    main()