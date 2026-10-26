#!/usr/bin/env python3
"""
SPECTRA Module 4 - M3 -> M4 Runtime Interface
Ingests the 8-feature telemetry vector from eBPF/IDS and evaluates it
using the trained Isolation Forest model.

Canonical Unit Contract (UNSW-NB15 Aligned):
  1. packet_size        : Bytes (smean)
  2. request_rate       : Packets / second
  3. connection_count   : Count (active TCP flows)
  4. inter_arrival_time : Milliseconds (sinpkt, ms)
  5. sttl               : Hops (integer, ~64)
  6. sjit               : Milliseconds (sjit, ms)
  7. dmean              : Bytes (proxy response mean)
  8. synack             : Milliseconds (synack / tcprtt, ms)
"""

import os
import math
import joblib
import pandas as pd

MODEL_PATH = "results/isolation_forest.pkl"
_model = None

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

# Alias map for UNSW-NB15 column names and alternate spellings
FEATURE_ALIASES = {
    "smean": "packet_size",
    "rate": "request_rate",
    "ct_srv_src": "connection_count",
    "sinpkt": "inter_arrival_time",
    "tcprtt": "synack",
}

def get_model():
    """Lazy load singleton trained Isolation Forest model."""
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file '{MODEL_PATH}' not found. Run train_model.py first.")
        _model = joblib.load(MODEL_PATH)
    return _model

def calculate_risk(model_score):
    """
    Converts Isolation Forest decision_function anomaly score
    into a calibrated Zero-Trust risk score between 0.0 and 1.0.
    Normal scores are positive (e.g., +0.10 -> risk ~0.12).
    Anomalous scores are negative (e.g., -0.15 -> risk ~0.80).
    """
    return 1.0 / (1.0 + math.exp(model_score / 0.1))

def get_decision(risk_score):
    """
    Maps continuous risk score to 3-tier Zero-Trust policy decision:
      - ALLOW:       < 0.30 (Benign traffic)
      - MFA/MONITOR: 0.30 - 0.69 (Moderate behavioral drift / IP roaming)
      - DROP:        >= 0.70 (Severe anomaly / exploit probe)
    """
    if risk_score < 0.30:
        return "ALLOW"
    elif risk_score < 0.70:
        return "MFA / MONITOR"
    else:
        return "DROP"

def analyze_telemetry(
    packet_size=512.0,
    request_rate=5.0,
    connection_count=2,
    inter_arrival_time=45.0,
    sttl=64,
    sjit=3.0,
    dmean=1250.0,
    synack=12.0,
    **kwargs
):
    """
    Main M3 -> M4 interface function.
    Accepts the 8 telemetries (or a telemetry dictionary/kwargs with aliases).
    Automatically validates and normalizes units (auto-detects seconds < 1.0 and scales to ms).
    """
    raw_data = {
        "packet_size": float(packet_size),
        "request_rate": float(request_rate),
        "connection_count": float(connection_count),
        "inter_arrival_time": float(inter_arrival_time),
        "sttl": float(sttl),
        "sjit": float(sjit),
        "dmean": float(dmean),
        "synack": float(synack)
    }

    # Resolve any UNSW-NB15 aliases from kwargs
    for k, v in kwargs.items():
        canonical_k = FEATURE_ALIASES.get(k, k)
        if canonical_k in raw_data:
            raw_data[canonical_k] = float(v)

    # Smart Unit Auto-Detection:
    # If caller accidentally passes timings in seconds (< 1.0s), scale up to canonical milliseconds (ms)
    for timing_key in ["inter_arrival_time", "sjit", "synack"]:
        val = raw_data[timing_key]
        if 0.0 < val < 1.0:
            raw_data[timing_key] = val * 1000.0

    telemetry_df = pd.DataFrame([raw_data])[FEATURES]

    model = get_model()

    # Isolation Forest prediction: +1 = Normal, -1 = Anomaly
    prediction = model.predict(telemetry_df)[0]
    model_score = model.decision_function(telemetry_df)[0]

    risk_score = calculate_risk(model_score)
    decision = get_decision(risk_score)

    return {
        "anomaly": bool(prediction == -1),
        "isolation_score": round(float(model_score), 4),
        "risk_score": round(float(risk_score), 2),
        "decision": decision,
        "features": raw_data
    }

# -----------------------------------------------------------------------------
# Standalone Test
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("   SPECTRA M3 -> M4 INTERFACE (CANONICAL UNITS: ms, bytes)")
    print("=" * 60)

    test_vectors = [
        {
            "name": "Benign Client Request (in milliseconds)",
            "telemetry": {
                "packet_size": 512,
                "request_rate": 4.5,
                "connection_count": 2,
                "inter_arrival_time": 45.0, # ms
                "sttl": 64,
                "sjit": 2.8,                # ms
                "dmean": 1280,
                "synack": 11.8              # ms
            }
        },
        {
            "name": "Benign Client Request (in seconds - testing auto-scaling)",
            "telemetry": {
                "packet_size": 512,
                "request_rate": 4.5,
                "connection_count": 2,
                "inter_arrival_time": 0.045, # seconds -> auto-scaled to 45.0ms
                "sttl": 64,
                "sjit": 0.0028,             # seconds -> auto-scaled to 2.8ms
                "dmean": 1280,
                "synack": 0.0118            # seconds -> auto-scaled to 11.8ms
            }
        },
        {
            "name": "Multi-Vector Anomaly / Probe",
            "telemetry": {
                "packet_size": 9500,
                "request_rate": 350.0,
                "connection_count": 80,
                "inter_arrival_time": 1.0,  # 1ms burst
                "sttl": 128,
                "sjit": 85.0,               # 85ms jitter
                "dmean": 150,
                "synack": 95.0              # 95ms handshake delay
            }
        }
    ]

    for tv in test_vectors:
        print(f"\nEvaluating: {tv['name']}")
        res = analyze_telemetry(**tv["telemetry"])
        print(f"  Anomaly Detected : {res['anomaly']}")
        print(f"  Isolation Score  : {res['isolation_score']}")
        print(f"  Risk Score       : {res['risk_score']}")
        print(f"  Decision         : {res['decision']}")
        print(f"  Ingested Vector  : {res['features']}")