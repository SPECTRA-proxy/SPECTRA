from flask import Flask, request, jsonify
from m4_interface import analyze_telemetry
app = Flask(__name__)

@app.post("/score")
def score():
    d = request.get_json()
    r = analyze_telemetry(d["packet_size"], d["request_rate"],
                          d["connection_count"], d["inter_arrival_time"])
    r["anomaly"] = bool(r["anomaly"])   # numpy bool is not JSON-safe
    return jsonify(r)

app.run(host="127.0.0.1", port=7000)
