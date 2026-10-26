from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd

from paths import CALIBRATION_PATH, MODEL_PATH

FEATURES = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time",
]

# Policy thresholds are learned/calibrated from held-out normal traffic.
_DEFAULT_MFA_THRESHOLD = 0.97
_DEFAULT_DROP_THRESHOLD = 0.995


# Load the model and calibration once when the module starts.
model = joblib.load(MODEL_PATH)
calibration = np.load(CALIBRATION_PATH)
REFERENCE_ANOMALY_SCORES = np.asarray(calibration["anomaly_scores"], dtype=float)
MFA_THRESHOLD = float(calibration.get("mfa_threshold", _DEFAULT_MFA_THRESHOLD))
DROP_THRESHOLD = float(calibration.get("drop_threshold", _DEFAULT_DROP_THRESHOLD))

if REFERENCE_ANOMALY_SCORES.size == 0:
    raise ValueError("Risk calibration contains no reference scores.")


def calculate_risk(model_score: float) -> float:
    """Convert an Isolation Forest score to an empirical 0-1 risk percentile.

    A risk of 0.97 means the observation is more anomalous than approximately
    97% of the held-out normal calibration traffic.
    """
    anomaly_score = -float(model_score)
    position = np.searchsorted(
        REFERENCE_ANOMALY_SCORES,
        anomaly_score,
        side="right",
    )
    risk = position / len(REFERENCE_ANOMALY_SCORES)
    return float(np.clip(risk, 0.0, 1.0))


def get_decision(risk_score: float) -> str:
    """Map calibrated risk to the SPECTRA policy action."""
    if risk_score < MFA_THRESHOLD:
        return "ALLOW"
    if risk_score < DROP_THRESHOLD:
        return "MFA / MONITOR"
    return "DROP"


def analyze_telemetry(
    packet_size: float,
    request_rate: float,
    connection_count: float,
    inter_arrival_time: float,
):
    """Analyze one telemetry vector and return the M4 policy result."""
    telemetry = pd.DataFrame([{
        "packet_size": packet_size,
        "request_rate": request_rate,
        "connection_count": connection_count,
        "inter_arrival_time": inter_arrival_time,
    }])

    # One decision_function call is enough. Avoid model.predict(), which would
    # apply Isolation Forest's training contamination threshold separately.
    start = time.perf_counter()
    model_score = float(model.decision_function(telemetry[FEATURES])[0])
    latency_ms = (time.perf_counter() - start) * 1000.0

    risk_score = calculate_risk(model_score)
    decision = get_decision(risk_score)

    return {
        "anomaly": risk_score >= MFA_THRESHOLD,
        "isolation_score": round(model_score, 4),
        "risk_score": round(risk_score, 4),
        "risk_percentile": round(risk_score * 100, 2),
        "decision": decision,
        "latency_ms": round(latency_ms, 3),
    }


if __name__ == "__main__":
    telemetry = {
        "packet_size": 9500,
        "request_rate": 300,
        "connection_count": 80,
        "inter_arrival_time": 0.002,
    }

    print("========================================")
    print("       SPECTRA M3 -> M4 INTERFACE")
    print("========================================")
    print("\nTelemetry received from M3:")
    print(telemetry)
    print("\nM4 Analysis:")
    print(analyze_telemetry(**telemetry))
