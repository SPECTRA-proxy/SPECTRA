#!/usr/bin/env python3
"""
SPECTRA Module 4 - Baseline Dataset Generator
Generates 10,000 normal network telemetry samples across the 8 UNSW-NB15 aligned features.

Canonical Unit Contract:
  1. packet_size        (smean - Inbound client packet size in Bytes)
  2. request_rate       (rate - Inbound request rate in Packets / second)
  3. connection_count   (ct_srv_src - Active concurrent TCP flows)
  4. inter_arrival_time (sinpkt - Inter-packet arrival delta in Milliseconds, ms)
  5. sttl               (Source IPv4 Time-To-Live in Hops / integer, ~64)
  6. sjit               (Source Jitter in Milliseconds, ms)
  7. dmean              (Destination Mean Packet Size in Bytes)
  8. synack             (TCP 3-way handshake RTT / latency in Milliseconds, ms)
"""

import numpy as np
import pandas as pd
import os

np.random.seed(42)

# Number of normal samples for dense 8D tree partitioning
n_normal = 10000

# 1. packet_size (Bytes): Normal client requests around 500B
packet_size = np.clip(np.random.normal(500, 80, n_normal), 64, 1500)

# 2. request_rate (pkts/sec): Typical user browsing rate ~5 pkts/sec
request_rate = np.clip(np.random.normal(5.0, 1.5, n_normal), 0.1, 20.0)

# 3. connection_count (flows): Standard concurrent HTTP/TLS connections ~3
connection_count = np.clip(np.round(np.random.normal(3.0, 1.0, n_normal)), 1, 8)

# 4. inter_arrival_time (Milliseconds, ms): Inter-packet delay ~50ms
inter_arrival_time = np.clip(np.random.normal(50.0, 15.0, n_normal), 5.0, 500.0)

# 5. sttl (integer hops): Source TTL centered at 64 (Linux baseline with router hop jitter)
ttl_jitter = np.random.choice([0, -1, -2], size=n_normal, p=[0.85, 0.12, 0.03])
sttl = np.clip(64 + ttl_jitter, 50, 64)

# 6. sjit (Milliseconds, ms): Source jitter ~3.0ms
sjit = np.clip(np.random.normal(3.0, 1.0, n_normal), 0.1, 20.0)

# 7. dmean (Bytes): Average outbound proxy response size ~1250 bytes
dmean = np.clip(np.random.normal(1250, 120, n_normal), 200, 1500)

# 8. synack (Milliseconds, ms): Handshake RTT ~12.0ms
synack = np.clip(np.random.normal(12.0, 3.0, n_normal), 2.0, 50.0)

normal_data = pd.DataFrame({
    "packet_size": packet_size,
    "request_rate": request_rate,
    "connection_count": connection_count,
    "inter_arrival_time": inter_arrival_time,
    "sttl": sttl,
    "sjit": sjit,
    "dmean": dmean,
    "synack": synack
})

# Save normal training data
os.makedirs("data", exist_ok=True)
normal_data.to_csv("data/normal_telemetry.csv", index=False)

print("=" * 60)
print("      SPECTRA M4: 8-FEATURE DATASET GENERATED")
print("=" * 60)
print(f"Generated normal samples : {len(normal_data):,}")
print(f"Number of features       : {len(normal_data.columns)}")
print(f"Feature vector           : {list(normal_data.columns)}")
print("\nUnits:")
print("  - packet_size        : Bytes")
print("  - request_rate       : Packets / second")
print("  - connection_count   : Count")
print("  - inter_arrival_time : Milliseconds (ms)")
print("  - sttl               : Hops (integer)")
print("  - sjit               : Milliseconds (ms)")
print("  - dmean              : Bytes")
print("  - synack             : Milliseconds (ms)")
print("\nFirst 5 Baseline Samples:")
print(normal_data.head())
print("\nDataset saved to: data/normal_telemetry.csv")