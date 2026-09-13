import pandas as pd
import joblib
import math

# Load trained model
model = joblib.load("results/isolation_forest.pkl")

FEATURES = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time"
]


def calculate_risk(model_score):
    """
    Convert Isolation Forest score
    into a normalized prototype risk score.
    """

    return 1 / (1 + math.exp(model_score / 0.1))


def get_decision(risk_score):
    """
    Convert risk score into a prototype
    security decision.
    """

    if risk_score < 0.30:
        return "ALLOW"

    elif risk_score < 0.70:
        return "MFA / MONITOR"

    else:
        return "DROP"


def analyze_telemetry(
    packet_size,
    request_rate,
    connection_count,
    inter_arrival_time
):
    """
    Main M3 -> M4 interface.

    M3 provides telemetry.
    M4 analyzes it and returns the security result.
    """

    telemetry = pd.DataFrame([{
        "packet_size": packet_size,
        "request_rate": request_rate,
        "connection_count": connection_count,
        "inter_arrival_time": inter_arrival_time
    }])

    # Isolation Forest prediction
    prediction = model.predict(
        telemetry[FEATURES]
    )[0]

    # Model anomaly score
    model_score = model.decision_function(
        telemetry[FEATURES]
    )[0]

    # Convert to risk score
    risk_score = calculate_risk(model_score)

    # Determine policy decision
    decision = get_decision(risk_score)

    return {
        "anomaly": prediction == -1,
        "isolation_score": round(float(model_score), 4),
        "risk_score": round(float(risk_score), 2),
        "decision": decision
    }


# --------------------------------------------------
# Standalone interface test
# --------------------------------------------------

if __name__ == "__main__":

    print("========================================")
    print("       SPECTRA M3 -> M4 INTERFACE")
    print("========================================")

    telemetry = {
        "packet_size": 9500,
        "request_rate": 300,
        "connection_count": 80,
        "inter_arrival_time": 0.002
    }

    print("\nTelemetry received from M3:")
    print(telemetry)

    result = analyze_telemetry(
        telemetry["packet_size"],
        telemetry["request_rate"],
        telemetry["connection_count"],
        telemetry["inter_arrival_time"]
    )

    print("\nM4 Analysis:")
    print(result)