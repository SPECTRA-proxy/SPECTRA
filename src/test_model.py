from m4_interface import analyze_telemetry

TEST_CASES = [
    {
        "packet_size": 520,
        "request_rate": 6,
        "connection_count": 3,
        "inter_arrival_time": 0.18,
    },
    {
        "packet_size": 9500,
        "request_rate": 300,
        "connection_count": 80,
        "inter_arrival_time": 0.002,
    },
]

for i, telemetry in enumerate(TEST_CASES, start=1):
    result = analyze_telemetry(**telemetry)

    print("\n-----------------------------")
    print(f"Test Case {i}")
    print("-----------------------------")
    for key, value in telemetry.items():
        print(f"{key:20}: {value}")
    print(f"Anomaly Detected    : {result['anomaly']}")
    print(f"Model Score         : {result['isolation_score']:.4f}")
    print(f"Risk Score          : {result['risk_score']:.4f}")
    print(f"Decision            : {result['decision']}")
