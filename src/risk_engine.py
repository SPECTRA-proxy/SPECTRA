"""Backward-compatible CLI wrapper for the M4 risk engine."""

from m4_interface import analyze_telemetry, MFA_THRESHOLD, DROP_THRESHOLD


print("========================================")
print("        SPECTRA AI RISK ENGINE")
print("========================================")
print(f"MFA threshold  : risk >= {MFA_THRESHOLD:.3f}")
print(f"DROP threshold : risk >= {DROP_THRESHOLD:.3f}")
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
print("             ANALYSIS RESULT")
print("========================================")
print(f"\nPacket Size       : {packet_size}")
print(f"Request Rate      : {request_rate}")
print(f"Connection Count  : {connection_count}")
print(f"Inter-arrival     : {inter_arrival_time}")
print("\n----------------------------------------")
print(f"Isolation Score   : {result['isolation_score']:.4f}")
print(f"Anomaly           : {'TRUE' if result['anomaly'] else 'FALSE'}")
print(f"Risk Score        : {result['risk_score']:.4f}")
print(f"Risk Percentile   : {result['risk_percentile']:.2f}%")
print(f"Decision          : {result['decision']}")
print(f"Inference Time    : {result['latency_ms']:.3f} ms")
print("========================================")
