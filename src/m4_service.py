#!/usr/bin/env python3
"""
SPECTRA Module 4 - Flask Microservice
Provides asynchronous HTTP scoring endpoint for eBPF and SPECTRA Reverse Proxy.
Listens on http://127.0.0.1:7000/score
"""

import sys
import os

# Ensure src directory is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from m4_interface import analyze_telemetry

app = Flask(__name__)

@app.post("/score")
def score():
    d = request.get_json(force=True, silent=True) or {}
    r = analyze_telemetry(**d)
    r["anomaly"] = bool(r["anomaly"])
    return jsonify(r)

@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "SPECTRA Module 4 AI Risk Engine",
        "features": 8
    })

if __name__ == "__main__":
    print("[+] Starting SPECTRA M4 AI Risk Engine on http://127.0.0.1:7000...")
    app.run(host="127.0.0.1", port=7000)
