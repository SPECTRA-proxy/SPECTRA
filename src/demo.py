#!/usr/bin/env python3
"""
SPECTRA Module 4 - Demo Script
Evaluates live telemetry against the 8-feature Isolation Forest engine
using canonical units (ms, bytes, count, pkts/sec).
"""

from m4_interface import analyze_telemetry

print("=" * 60)
print("       SPECTRA M4 AI RISK ENGINE (8-FEATURE DEMO)")
print("=" * 60)

def prompt_float(prompt, default):
    try:
        val = input(f"{prompt} [default {default}]: ").strip()
        return float(val) if val else default
    except (EOFError, KeyboardInterrupt):
        return default

packet_size = prompt_float("1. Packet Size (Bytes)", 512.0)
request_rate = prompt_float("2. Request Rate (pkts/sec)", 5.0)
connection_count = prompt_float("3. Connection Count (flows)", 2.0)
inter_arrival_time = prompt_float("4. Inter-Arrival Time (Milliseconds, ms)", 45.0)
sttl = prompt_float("5. Source TTL (sttl, hops)", 64.0)
sjit = prompt_float("6. Source Jitter (Milliseconds, ms)", 3.0)
dmean = prompt_float("7. Destination Mean (Bytes)", 1250.0)
synack = prompt_float("8. Handshake RTT / synack (Milliseconds, ms)", 12.0)

result = analyze_telemetry(
    packet_size=packet_size,
    request_rate=request_rate,
    connection_count=connection_count,
    inter_arrival_time=inter_arrival_time,
    sttl=int(sttl),
    sjit=sjit,
    dmean=dmean,
    synack=synack
)

print("\n" + "=" * 60)
print("            M4 ANALYSIS RESULT")
print("=" * 60)
print(f"Anomaly Detected : {result['anomaly']}")
print(f"Isolation Score  : {result['isolation_score']}")
print(f"Risk Score       : {result['risk_score']}")
print(f"Decision         : {result['decision']}")
print(f"Ingested Vector  : {result['features']}")
print("=" * 60)