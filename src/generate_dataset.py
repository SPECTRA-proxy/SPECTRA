import numpy as np
import pandas as pd

np.random.seed(42)

# Number of normal samples
n_normal = 1000

# Generate normal network telemetry
normal_data = pd.DataFrame({
    "packet_size": np.random.normal(500, 80, n_normal),
    "request_rate": np.random.normal(5, 1.5, n_normal),
    "connection_count": np.random.normal(3, 1, n_normal),
    "inter_arrival_time": np.random.normal(0.2, 0.05, n_normal)
})

# Prevent unrealistic negative values
normal_data["packet_size"] = normal_data["packet_size"].clip(lower=50)
normal_data["request_rate"] = normal_data["request_rate"].clip(lower=0.1)
normal_data["connection_count"] = normal_data["connection_count"].clip(lower=1)
normal_data["inter_arrival_time"] = normal_data["inter_arrival_time"].clip(lower=0.01)

# Save normal training data
normal_data.to_csv("data/normal_telemetry.csv", index=False)

print("Dataset generated successfully.")
print(f"Normal samples: {len(normal_data)}")
print("\nFirst 5 samples:")
print(normal_data.head())