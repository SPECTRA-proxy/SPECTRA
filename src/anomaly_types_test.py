import numpy as np
import pandas as pd
import joblib

from sklearn.metrics import precision_score, recall_score, f1_score

# Reproducibility
np.random.seed(200)

# Load trained model
model = joblib.load("results/isolation_forest.pkl")

features = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time"
]


def generate_normal(n):
    return pd.DataFrame({
        "packet_size": np.random.normal(500, 80, n),
        "request_rate": np.random.normal(5, 1.5, n),
        "connection_count": np.random.normal(3, 1, n),
        "inter_arrival_time": np.random.normal(0.2, 0.05, n)
    }).clip(lower=0.001)


def generate_anomaly(anomaly_type, n):
    data = generate_normal(n)

    if anomaly_type == "high_request_rate":
        data["request_rate"] = np.random.uniform(100, 300, n)

    elif anomaly_type == "large_packet":
        data["packet_size"] = np.random.uniform(5000, 10000, n)

    elif anomaly_type == "high_connections":
        data["connection_count"] = np.random.uniform(30, 80, n)

    elif anomaly_type == "combined":
        data["packet_size"] = np.random.uniform(5000, 10000, n)
        data["request_rate"] = np.random.uniform(100, 300, n)
        data["connection_count"] = np.random.uniform(30, 80, n)
        data["inter_arrival_time"] = np.random.uniform(0.001, 0.01, n)

    return data


# Number of samples per test
n = 50

anomaly_types = [
    "high_request_rate",
    "large_packet",
    "high_connections",
    "combined"
]

print("========================================")
print("      SPECTRA M4 ANOMALY ANALYSIS")
print("========================================")

for anomaly_type in anomaly_types:

    # Generate normal and anomaly samples
    normal = generate_normal(n)
    anomaly = generate_anomaly(anomaly_type, n)

    test_data = pd.concat(
        [normal, anomaly],
        ignore_index=True
    )

    # Ground truth
    # 0 = normal
    # 1 = anomaly
    y_true = np.array([0] * n + [1] * n)

    # Model prediction
    prediction = model.predict(test_data[features])

    # Convert Isolation Forest output
    y_pred = np.where(prediction == -1, 1, 0)

    # Metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print("\n----------------------------------------")
    print(f"Anomaly Type: {anomaly_type}")
    print("----------------------------------------")

    print(f"Precision : {precision:.2f}")
    print(f"Recall    : {recall:.2f}")
    print(f"F1-score  : {f1:.2f}")

print("\n========================================")
print("Analysis completed.")
print("========================================")