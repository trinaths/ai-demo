import requests
import joblib
import json
import pandas as pd
from flask import Flask, request, jsonify
import yaml
from kubernetes import client, config
import os
import logging
import numpy as np
from datetime import datetime, timezone
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Define paths
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"
DATA_STORAGE_PATH = "/data/collected_traffic.csv"

# Ensure the directory exists
os.makedirs("/data", exist_ok=True)

# Load the trained model and encoders
if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH):
    logger.info("Loading existing model and encoders...")
    model = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)
else:
    logger.error("Error: No model found. Run initial training first!")
    exit(1)

app = Flask(__name__)

# Function to update the ConfigMap with malicious IP in Kubernetes
def update_configmap_in_k8s(ip):
    try:
        config.load_incluster_config()
        namespace = "ai-workloads"
        configmap_name = "ai-traffic-control"

        v1 = client.CoreV1Api()
        configmap = v1.read_namespaced_config_map(configmap_name, namespace)

        # Ensure the "template" key exists
        if "template" not in configmap.data:
            raise KeyError("ConfigMap does not contain 'template' field.")

        # Load AS3 JSON from the "template" key
        as3_declaration = json.loads(configmap.data["template"])  # Deserialize JSON

        # Validate AS3 structure
        waf_security = as3_declaration.get("declaration", {}).get("Shared", {}).get("WAF_Security", {})
        if "malicious_ip_data_group" not in waf_security:
            raise KeyError("Missing 'malicious_ip_data_group' in AS3 declaration.")

        # Get the existing records
        records = waf_security["malicious_ip_data_group"].get("records", [])

        # Check if the IP is already present
        if not any(entry["name"] == ip for entry in records):
            records.append({"name": ip, "value": "AI-Blacklisted"})
            waf_security["malicious_ip_data_group"]["records"] = records

            # Convert back to JSON and update ConfigMap
            configmap.data["template"] = json.dumps(as3_declaration, indent=4)

            # Apply the updated ConfigMap
            v1.replace_namespaced_config_map(configmap_name, namespace, configmap)
            logger.info(f"✅ ConfigMap updated: IP {ip} added to 'malicious_ip_data_group'.")
        else:
            logger.info(f"ℹ️ IP {ip} already exists in the 'malicious_ip_data_group'.")

    except KeyError as e:
        logger.error(f"❌ KeyError: {e}. Ensure AS3 JSON is correctly structured in the ConfigMap.")
    except json.JSONDecodeError:
        logger.error("❌ JSON Decode Error: ConfigMap does not contain valid JSON.")
    except client.exceptions.ApiException as e:
        logger.error(f"❌ Kubernetes API Error: {e.reason} - {e.body}")

# Function to preprocess data
def preprocess_data(data):
    features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
    df_input = pd.DataFrame([data])

    # Handle missing values
    for col in ["ip_reputation", "bot_signature", "violation"]:
        df_input[col] = df_input[col].fillna("Unknown").astype(str)

        # Ensure all categories are available before transforming
        unseen_labels = set(df_input[col]) - set(encoders[col].classes_)
        if unseen_labels:
            logger.warning(f"Unseen labels detected in {col}: {unseen_labels}. Adjusting encoding.")
            encoders[col].classes_ = np.append(encoders[col].classes_, list(unseen_labels))

        # Transform using LabelEncoder
        df_input[col] = encoders[col].transform(df_input[col])

    return df_input[features]

# Function to store data and trigger retraining
def store_data_and_retrain(data, prediction):
    timestamp = datetime.now(timezone.utc).isoformat()

    # Define the correct column order
    required_columns = [
        "timestamp", "src_ip", "request", "violation", "response_code", 
        "bytes_sent", "bytes_received", "request_rate", "bot_signature", 
        "severity", "user_agent", "ip_reputation", "prediction"
    ]

    # Ensure correct data structure
    row_data = {
        "timestamp": timestamp,
        "src_ip": data.get("src_ip", "Unknown"),
        "request": data.get("request", "Unknown"),
        "violation": data.get("violation", "None"),
        "response_code": data.get("response_code", 0),
        "bytes_sent": data.get("bytes_sent", 0),
        "bytes_received": data.get("bytes_received", 0),
        "request_rate": data.get("request_rate", 0),
        "bot_signature": data.get("bot_signature", "Unknown"),
        "severity": data.get("severity", "Unknown"),
        "user_agent": data.get("user_agent", "Unknown"),
        "ip_reputation": data.get("ip_reputation", "Unknown"),
        "prediction": prediction
    }

    df = pd.DataFrame([row_data], columns=required_columns)

    # Append to CSV with correct format
    if not os.path.exists(DATA_STORAGE_PATH):
        df.to_csv(DATA_STORAGE_PATH, mode='w', index=False, header=True)
    else:
        df.to_csv(DATA_STORAGE_PATH, mode='a', index=False, header=False)

    retrain_model()

# Function to retrain the model dynamically
def retrain_model():
    logger.info("Retraining model...")

    try:
        df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines='skip')

        # Ensure 'prediction' column exists
        if "prediction" not in df.columns:
            raise ValueError("Missing 'prediction' column in collected_traffic.csv")

        label_encoders = {}
        for col in ["ip_reputation", "bot_signature", "violation"]:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le

        X = df[["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]]
        y = df["prediction"]

        model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
        model.fit(X, y)

        joblib.dump(model, MODEL_PATH)
        joblib.dump(label_encoders, ENCODERS_PATH)

        logger.info("✅ Model retrained successfully.")

    except Exception as e:
        logger.error(f"❌ Error during model retraining: {e}")

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