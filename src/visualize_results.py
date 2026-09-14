import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

# Reproducibility
np.random.seed(300)

# Load trained model
model = joblib.load("results/isolation_forest.pkl")

features = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time"
]

# Generate normal samples
normal = pd.DataFrame({
    "packet_size": np.random.normal(500, 80, 100),
    "request_rate": np.random.normal(5, 1.5, 100),
    "connection_count": np.random.normal(3, 1, 100),
    "inter_arrival_time": np.random.normal(0.2, 0.05, 100)
})

# Generate anomalous samples
anomaly = pd.DataFrame({
    "packet_size": np.random.uniform(5000, 10000, 30),
    "request_rate": np.random.uniform(100, 300, 30),
    "connection_count": np.random.uniform(30, 80, 30),
    "inter_arrival_time": np.random.uniform(0.001, 0.01, 30)
})

# Combine data
data = pd.concat([normal, anomaly], ignore_index=True)

# Model prediction
predictions = model.predict(data[features])

# Use packet size and request rate for visualization
plt.figure(figsize=(9, 6))

plt.scatter(
    normal["packet_size"],
    normal["request_rate"],
    label="Normal"
)

plt.scatter(
    anomaly["packet_size"],
    anomaly["request_rate"],
    label="Synthetic Anomaly"
)

plt.xlabel("Packet Size (bytes)")
plt.ylabel("Request Rate (requests/sec)")
plt.title("SPECTRA M4: Network Behaviour Distribution")
plt.legend()
plt.grid(True)

plt.savefig("results/network_behavior.png", dpi=300)

plt.show()

print("Visualization saved to:")
print("results/network_behavior.png")