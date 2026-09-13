import pandas as pd
import joblib
import math

# Load trained model
model = joblib.load("results/isolation_forest.pkl")

features = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time"
]


def calculate_risk(model_score):
    """
    Convert Isolation Forest anomaly score
    into a prototype SPECTRA risk score from 0 to 1.
    """

    risk = 1 / (1 + math.exp(model_score / 0.1))

    return risk


def get_action(risk):
    """
    Convert risk score into a security decision.
    """

    if risk < 0.30:
        return "ALLOW"

    elif risk < 0.70:
        return "MFA / MONITOR"

    else:
        return "DROP"


# --------------------------------------------------
# SPECTRA AI RISK ENGINE
# --------------------------------------------------

print("========================================")
print("        SPECTRA AI RISK ENGINE")
print("========================================")

print("\nEnter network telemetry:")

packet_size = float(input("Packet size (bytes): "))
request_rate = float(input("Request rate (requests/sec): "))
connection_count = float(input("Connection count: "))
inter_arrival_time = float(input("Inter-arrival time (seconds): "))


# Create telemetry vector
telemetry = pd.DataFrame([{
    "packet_size": packet_size,
    "request_rate": request_rate,
    "connection_count": connection_count,
    "inter_arrival_time": inter_arrival_time
}])


# --------------------------------------------------
# MODEL ANALYSIS
# --------------------------------------------------

prediction = model.predict(telemetry[features])[0]

model_score = model.decision_function(
    telemetry[features]
)[0]


# Convert anomaly score to risk
risk = calculate_risk(model_score)

# Determine security action
action = get_action(risk)


# --------------------------------------------------
# DISPLAY RESULT
# --------------------------------------------------

print("\n========================================")
print("             ANALYSIS RESULT")
print("========================================")

print(f"\nPacket Size       : {packet_size}")
print(f"Request Rate      : {request_rate}")
print(f"Connection Count  : {connection_count}")
print(f"Inter-arrival     : {inter_arrival_time}")

print("\n----------------------------------------")

print(f"Isolation Score   : {model_score:.4f}")
print(f"Anomaly           : {'TRUE' if prediction == -1 else 'FALSE'}")
print(f"Risk Score        : {risk:.2f}")
print(f"Decision          : {action}")

print("\n========================================")