from pathlib import Path
import numpy as np
import pandas as pd

from paths import NORMAL_DATA_PATH

np.random.seed(42)

# Synthetic normal baseline used for the standalone prototype/demo.
n_normal = 1000

normal_data = pd.DataFrame({
    "packet_size": np.random.normal(500, 80, n_normal),
    "request_rate": np.random.normal(5, 1.5, n_normal),
    "connection_count": np.random.normal(3, 1, n_normal),
    "inter_arrival_time": np.random.normal(0.2, 0.05, n_normal)
})

# Prevent unrealistic negative values.
normal_data["packet_size"] = normal_data["packet_size"].clip(lower=50)
normal_data["request_rate"] = normal_data["request_rate"].clip(lower=0.1)
normal_data["connection_count"] = normal_data["connection_count"].clip(lower=1)
normal_data["inter_arrival_time"] = normal_data["inter_arrival_time"].clip(lower=0.01)

NORMAL_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
normal_data.to_csv(NORMAL_DATA_PATH, index=False)

print("Dataset generated successfully.")
print(f"Normal samples: {len(normal_data)}")
print(f"Saved to: {NORMAL_DATA_PATH}")
print("\nFirst 5 samples:")
print(normal_data.head())
