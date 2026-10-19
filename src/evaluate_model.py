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

# Reproducibility
np.random.seed(100)

# Load trained Isolation Forest
model = joblib.load("results/isolation_forest.pkl")

features = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time"
]

# --------------------------------------------------
# 1. Generate NORMAL test data
# --------------------------------------------------

n_normal = 200

normal_test = pd.DataFrame({
    "packet_size": np.random.normal(500, 80, n_normal),
    "request_rate": np.random.normal(5, 1.5, n_normal),
    "connection_count": np.random.normal(3, 1, n_normal),
    "inter_arrival_time": np.random.normal(0.2, 0.05, n_normal)
})

normal_test["packet_size"] = normal_test["packet_size"].clip(lower=50)
normal_test["request_rate"] = normal_test["request_rate"].clip(lower=0.1)
normal_test["connection_count"] = normal_test["connection_count"].clip(lower=1)
normal_test["inter_arrival_time"] = normal_test["inter_arrival_time"].clip(lower=0.01)


# --------------------------------------------------
# 2. Generate ANOMALOUS test data
# --------------------------------------------------

n_anomaly = 50

anomaly_test = pd.DataFrame({
    "packet_size": np.random.uniform(5000, 15000, n_anomaly),
    "request_rate": np.random.uniform(100, 500, n_anomaly),
    "connection_count": np.random.uniform(30, 100, n_anomaly),
    "inter_arrival_time": np.random.uniform(0.001, 0.01, n_anomaly)
})


# --------------------------------------------------
# 3. Combine test data
# --------------------------------------------------

test_data = pd.concat(
    [normal_test, anomaly_test],
    ignore_index=True
)

# Actual ground truth:
# 0 = normal
# 1 = anomaly

y_true = np.array(
    [0] * n_normal +
    [1] * n_anomaly
)


# --------------------------------------------------
# 4. Make predictions
# --------------------------------------------------

predictions = model.predict(test_data[features])

# Isolation Forest:
# +1 = normal
# -1 = anomaly

# Convert to our labels:
# 0 = normal
# 1 = anomaly

y_pred = np.where(predictions == -1, 1, 0)


# --------------------------------------------------
# 5. Calculate evaluation metrics
# --------------------------------------------------

precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)

cm = confusion_matrix(y_true, y_pred)


# --------------------------------------------------
# 6. Display results
# --------------------------------------------------

print("========================================")
print("       SPECTRA M4 MODEL EVALUATION")
print("========================================")

print(f"\nNormal test samples   : {n_normal}")
print(f"Anomalous test samples: {n_anomaly}")
print(f"Total test samples    : {len(test_data)}")

print("\n----------------------------------------")
print("Evaluation Metrics")
print("----------------------------------------")

print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1-score  : {f1:.4f}")

print("\n----------------------------------------")
print("Confusion Matrix")
print("----------------------------------------")

print(cm)

print("\n----------------------------------------")
print("Classification Report")
print("----------------------------------------")

print(
    classification_report(
        y_true,
        y_pred,
        target_names=["Normal", "Anomaly"],
        zero_division=0
    )
)