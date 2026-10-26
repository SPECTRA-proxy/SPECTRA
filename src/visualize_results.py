import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from m4_interface import FEATURES, MFA_THRESHOLD, model, calculate_risk

rng = np.random.default_rng(300)

normal = pd.DataFrame({
    "packet_size": rng.normal(500, 80, 100),
    "request_rate": rng.normal(5, 1.5, 100),
    "connection_count": rng.normal(3, 1, 100),
    "inter_arrival_time": rng.normal(0.2, 0.05, 100),
}).clip(lower=0.001)

anomaly = pd.DataFrame({
    "packet_size": rng.uniform(5000, 10000, 30),
    "request_rate": rng.uniform(100, 300, 30),
    "connection_count": rng.uniform(30, 80, 30),
    "inter_arrival_time": rng.uniform(0.001, 0.01, 30),
})

normal_scores = model.decision_function(normal[FEATURES])
anomaly_scores = model.decision_function(anomaly[FEATURES])
normal_risk = [calculate_risk(score) for score in normal_scores]
anomaly_risk = [calculate_risk(score) for score in anomaly_scores]

plt.figure(figsize=(9, 6))
plt.scatter(normal["packet_size"], normal["request_rate"], label="Normal")
plt.scatter(anomaly["packet_size"], anomaly["request_rate"], label="Synthetic Anomaly")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Request Rate (requests/sec)")
plt.title("SPECTRA M4: Network Behaviour Distribution")
plt.legend()
plt.grid(True)
plt.savefig("results/network_behavior.png", dpi=300, bbox_inches="tight")
plt.show()

print("Normal samples with risk >= MFA threshold:",
      sum(r >= MFA_THRESHOLD for r in normal_risk), "/", len(normal_risk))
print("Synthetic anomalies with risk >= MFA threshold:",
      sum(r >= MFA_THRESHOLD for r in anomaly_risk), "/", len(anomaly_risk))
print("Visualization saved to results/network_behavior.png")
