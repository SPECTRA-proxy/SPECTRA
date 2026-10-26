from m4_interface import analyze_telemetry, MFA_THRESHOLD, DROP_THRESHOLD

print("========================================")
print("       SPECTRA M4 AI RISK ENGINE")
print("========================================")
print(f"MFA threshold  : risk >= {MFA_THRESHOLD:.3f}")
print(f"DROP threshold : risk >= {DROP_THRESHOLD:.3f}")
print("\nRisk is an empirical percentile of held-out normal traffic.")
print("Example: 0.97 means more anomalous than ~97% of normal reference traffic.")
print("\nEnter network telemetry:")

packet_size = float(input("Packet size (bytes): "))
request_rate = float(input("Request rate (requests/sec): "))
connection_count = float(input("Connection count: "))
inter_arrival_time = float(input("Inter-arrival time (seconds): "))

result = analyze_telemetry(
    packet_size,
    request_rate,
    connection_count,
    inter_arrival_time,
)

print("\n========================================")
print("            ANALYSIS RESULT")
print("========================================")
print(f"Packet Size      : {packet_size}")
print(f"Request Rate     : {request_rate}")
print(f"Connections      : {connection_count}")
print(f"Inter-arrival    : {inter_arrival_time}")
print("----------------------------------------")
print(f"Anomaly          : {result['anomaly']}")
print(f"Isolation Score  : {result['isolation_score']}")
print(f"Risk Score       : {result['risk_score']}")
print(f"Risk Percentile  : {result['risk_percentile']}%")
print(f"Decision         : {result['decision']}")
print(f"Inference Time   : {result['latency_ms']} ms")
print("========================================")
