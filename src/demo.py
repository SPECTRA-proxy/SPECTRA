from m4_interface import analyze_telemetry

print("========================================")
print("       SPECTRA M4 AI RISK ENGINE")
print("========================================")

print("\nEnter network telemetry:")

packet_size = float(input("Packet size (bytes): "))
request_rate = float(input("Request rate (requests/sec): "))
connection_count = float(input("Connection count: "))
inter_arrival_time = float(
    input("Inter-arrival time (seconds): ")
)

# Send telemetry to M4
result = analyze_telemetry(
    packet_size,
    request_rate,
    connection_count,
    inter_arrival_time
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
print(f"Decision         : {result['decision']}")

print("========================================")