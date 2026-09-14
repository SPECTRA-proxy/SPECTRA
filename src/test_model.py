import pandas as pd
import joblib

# Load trained model
model = joblib.load("results/isolation_forest.pkl")

features = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time"
]

# Test cases
test_data = pd.DataFrame([
    {
        "packet_size": 520,
        "request_rate": 6,
        "connection_count": 3,
        "inter_arrival_time": 0.18
    },
    {
        "packet_size": 9500,
        "request_rate": 300,
        "connection_count": 80,
        "inter_arrival_time": 0.002
    }
])

predictions = model.predict(test_data[features])
scores = model.decision_function(test_data[features])

for i, (prediction, score) in enumerate(zip(predictions, scores)):

    print("\n-----------------------------")
    print(f"Test Case {i + 1}")
    print("-----------------------------")

    print(f"Packet Size       : {test_data.iloc[i]['packet_size']}")
    print(f"Request Rate      : {test_data.iloc[i]['request_rate']}")
    print(f"Connection Count  : {test_data.iloc[i]['connection_count']}")
    print(f"Inter-arrival     : {test_data.iloc[i]['inter_arrival_time']}")

    if prediction == 1:
        print("Anomaly Detected  : FALSE")
    else:
        print("Anomaly Detected  : TRUE")

    print(f"Model Score       : {score:.4f}")