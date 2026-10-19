import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load normal telemetry data
data = pd.read_csv("data/normal_telemetry.csv")

# Select the features used by the model
features = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time"
]

X = data[features]

# Create the Isolation Forest model
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

# Train only on normal telemetry
model.fit(X)

# Save the trained model
joblib.dump(model, "results/isolation_forest.pkl")

print("================================")
print("   SPECTRA AI RISK ENGINE")
print("================================")
print()
print("Model: Isolation Forest")
print(f"Training samples: {len(X)}")
print(f"Features: {len(features)}")
print()
print("Training completed successfully.")
print("Model saved to: results/isolation_forest.pkl")