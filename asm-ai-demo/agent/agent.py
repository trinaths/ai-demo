import requests
import joblib
import pandas as pd
from flask import Flask, request, jsonify
import yaml
from kubernetes import client, config
import os
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# Define paths
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"
DATA_STORAGE_PATH = "/data/collected_traffic.csv"

# Ensure the directory exists
os.makedirs("/data", exist_ok=True)

# Load the trained model and encoders
if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH):
    print("Loading existing model and encoders...")
    model = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)
else:
    print("Error: No model found. Run initial training first!")
    exit(1)

app = Flask(__name__)

# Function to update the ConfigMap with malicious IP in Kubernetes
def update_configmap_in_k8s(ip):
    config.load_incluster_config()  # Automatically loads from the service account when inside Kubernetes

    namespace = "ai-workloads"
    configmap_name = "ai-traffic-control"

    v1 = client.CoreV1Api()

    try:
        configmap = v1.read_namespaced_config_map(configmap_name, namespace)
        records = configmap.data["declaration"]["Shared"]["WAF_Security"]["malicious_ip_data_group"]["records"]

        if ip not in [r["name"] for r in records]:
            records.append({"name": ip, "value": "AI-Blacklisted"})

        configmap.data["declaration"]["Shared"]["WAF_Security"]["malicious_ip_data_group"]["records"] = records
        v1.replace_namespaced_config_map(configmap_name, namespace, configmap)

        print(f"ConfigMap updated successfully: IP {ip} added to blacklist.")
    except client.exceptions.ApiException as e:
        print(f"Error updating ConfigMap: {e}")

# Function to preprocess data
def preprocess_data(data):
    features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]

    df_input = pd.DataFrame([data])

    for col in ["ip_reputation", "bot_signature", "violation"]:
        df_input[col] = encoders[col].transform(df_input[col].astype(str))

    return df_input[features]

# Function to store data and trigger retraining
def store_data_and_retrain(data, prediction):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    data["timestamp"] = timestamp
    data["prediction"] = prediction
    data["severity"] = data.get("severity", "Unknown")
    data["user_agent"] = data.get("user_agent", "Unknown")

    required_columns = ["timestamp", "src_ip", "request", "violation", "response_code", "bytes_sent", "bytes_received", "request_rate", "bot_signature", "severity", "user_agent", "ip_reputation", "label", "prediction"]

    for col in required_columns:
        if col not in data:
            data[col] = None

    df = pd.DataFrame([data])

    if not os.path.exists(DATA_STORAGE_PATH):
        df.to_csv(DATA_STORAGE_PATH, mode='w', index=False, header=True)
    else:
        df.to_csv(DATA_STORAGE_PATH, mode='a', index=False, header=False)

    retrain_model()

# Function to retrain the model dynamically
def retrain_model():
    print("Retraining model...")
    df = pd.read_csv(DATA_STORAGE_PATH)

    label_encoders = {}
    for col in ["ip_reputation", "bot_signature", "violation"]:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le

    X = df[["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]]
    y = df["prediction"]

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)

    print("Model retrained and updated.")

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    df_input = preprocess_data(data)
    prediction = model.predict(df_input)[0]
    
    store_data_and_retrain(data, prediction)

    if prediction == 1:
        update_configmap_in_k8s(data["src_ip"])
        return jsonify({"status": "malicious", "message": "IP added to ConfigMap", "src_ip": data["src_ip"]})

    return jsonify({"status": "normal", "message": "Traffic is not malicious"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)