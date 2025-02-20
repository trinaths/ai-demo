#!/usr/bin/env python3
"""
app.py

Flask application for the Model Service.
Exposes two endpoints:
  - /predict: Returns a prediction based on incoming TS logs.
  - /retrain: Retrains (or fine-tunes) models using accumulated new logs.
"""
import json
import os
import pickle
import numpy as np
from flask import Flask, request, jsonify
from train_model import load_data, train_models

app = Flask(__name__)

MODEL_PATH = "/app/models/trained_models.pkl"
ORIGINAL_TRAINING_DATA = "/app/models/synthetic_ts_logs.jsonl"
NEW_TRAINING_DATA = "/app/training_data/accumulated_ts_logs.jsonl"

def load_models():
    with open(MODEL_PATH, "rb") as f:
        models = pickle.load(f)
    return models

models = load_models()

def discretize_state(data):
    return (round(data.get("throughputPerformance", 0), 1),
            1 if data.get("asmAttackSignatures", "None") != "None" else 0)

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON payload received"}), 400
        module = data.get("module")
        if module not in models:
            return jsonify({"error": f"Unknown module '{module}'"}), 400
        if module == "ASM":
            state = discretize_state(data)
            q_table = models["ASM"]
            prediction = max(q_table.get(state, {"no_change": 0}), key=q_table.get(state, {"no_change": 0}).get)
        elif module == "APM":
            feature = data.get("system.connectionsPerformance", 0)
            X = np.array([feature]).reshape(1, -1)
            prediction = models[module].predict(X)[0]
        elif module == "LTM":
            features = [data.get("cryptoLoad", 0), data.get("throughputPerformance", 0),
                        data.get("latency", 0), data.get("jitter", 0), data.get("packetLoss", 0)]
            X = np.array(features).reshape(1, -1)
            prediction = models[module].predict(X)[0]
        elif module == "SYSTEM":
            features = [data.get("tmmCpu", 0), data.get("throughputPerformance", 0)]
            X = np.array(features).reshape(1, -1)
            prediction = models[module].predict(X)[0]
        elif module == "AFM":
            feature = data.get("afmThreatScore", 0)
            X = np.array([feature]).reshape(1, -1)
            prediction = models[module].predict(X)[0]
        else:
            prediction = "no_change"
        return jsonify({"prediction": prediction})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/retrain", methods=["POST"])
def retrain():
    try:
        data = load_data(ORIGINAL_TRAINING_DATA)
        if os.path.exists(NEW_TRAINING_DATA):
            with open(NEW_TRAINING_DATA, "r") as f:
                for line in f:
                    record = json.loads(line)
                    module = record.get("module")
                    if module in data:
                        data[module].append(record)
                    else:
                        data[module] = [record]
        new_models = train_models(data)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(new_models, f)
        global models
        models = new_models
        # Clear new training data after retraining.
        open(NEW_TRAINING_DATA, "w").close()
        return jsonify({"status": "success", "message": "Models retrained successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)