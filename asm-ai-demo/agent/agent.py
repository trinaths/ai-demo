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

# **🛠 Set up Logging**
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# **📍 Paths**
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"
SCALER_PATH = "/data/scaler.pkl"
DATA_STORAGE_PATH = "/data/collected_traffic.csv"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load trained model, encoders, and scaler**
if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH) and os.path.exists(SCALER_PATH):
    logger.info("📥 Loading trained model, encoders, and scaler...")
    model = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)
    scaler = joblib.load(SCALER_PATH)  # ✅ Load StandardScaler
else:
    logger.error("❌ No trained model found. Run initial training first!")
    exit(1)

app = Flask(__name__)

# **🛡️ Update AI-WAF ConfigMap**
def update_configmap_in_k8s(ip):
    try:
        config.load_incluster_config()
        namespace = "ai-workloads"
        configmap_name = "ai-traffic-control"

        v1 = client.CoreV1Api()
        configmap = v1.read_namespaced_config_map(configmap_name, namespace)

        # **Extract AS3 JSON from the "template" key**
        as3_declaration = json.loads(configmap.data["template"])

        # **Ensure correct AS3 structure**
        waf_security = as3_declaration.get("declaration", {}).get("Shared", {}).get("WAF_Security", {})
        if "malicious_ip_data_group" not in waf_security:
            raise KeyError("❌ Missing 'malicious_ip_data_group' in AS3 declaration.")

        # **Check if the IP is already blacklisted**
        records = waf_security["malicious_ip_data_group"].get("records", [])
        if not any(entry["key"] == ip for entry in records):
            records.append({"key": ip, "value": "AI-Blacklisted"})
            waf_security["malicious_ip_data_group"]["records"] = records

            # **Update ConfigMap**
            configmap.data["template"] = json.dumps(as3_declaration, indent=4)
            v1.replace_namespaced_config_map(configmap_name, namespace, configmap)
            logger.info(f"✅ ConfigMap updated: IP {ip} added to AI-WAF.")
        else:
            logger.info(f"ℹ️ IP {ip} already blacklisted.")

    except Exception as e:
        logger.error(f"❌ Error updating ConfigMap: {e}")

# **🔍 Preprocess data before prediction**
def preprocess_data(data):
    features = ["bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
    df_input = pd.DataFrame([data])

    # **Handle categorical variables**
    for col in ["ip_reputation", "bot_signature", "violation"]:
        df_input[col] = df_input[col].fillna("Unknown").astype(str)
        df_input[col] = encoders[col].transform(df_input[col])

    # **Apply StandardScaler to numeric features**
    df_input[["bytes_sent", "bytes_received", "request_rate"]] = scaler.transform(
        df_input[["bytes_sent", "bytes_received", "request_rate"]]
    )

    return df_input[features]

# **📊 Store data & trigger retraining**
def store_data_and_retrain(data, prediction):
    timestamp = datetime.now(timezone.utc).isoformat()
    data["timestamp"] = timestamp
    data["prediction"] = prediction

    df = pd.DataFrame([data])

    if not os.path.exists(DATA_STORAGE_PATH):
        df.to_csv(DATA_STORAGE_PATH, mode="w", index=False, header=True)
    else:
        df.to_csv(DATA_STORAGE_PATH, mode="a", index=False, header=False)

    # **Trigger retraining dynamically**
    retrain_model()

# **🧠 Retrain Model Dynamically**
def retrain_model():
    try:
        df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines='skip')

        # **Ensure 'prediction' column exists**
        if "prediction" not in df.columns:
            raise ValueError("Missing 'prediction' column in collected_traffic.csv")

        label_encoders = {}
        for col in ["ip_reputation", "bot_signature", "violation"]:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le

        X = df[["bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]]
        y = df["prediction"]

        # **Retrain model**
        model.fit(X, y)

        # **Save updated model & encoders**
        joblib.dump(model, MODEL_PATH)
        joblib.dump(label_encoders, ENCODERS_PATH)
        logger.info("✅ Model retrained successfully!")

    except Exception as e:
        logger.error(f"❌ Error during model retraining: {e}")

# **🛡️ Adjust malicious classification threshold**
MALICIOUS_THRESHOLD = 0.8  # ✅ Probability threshold

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    df_input = preprocess_data(data)

    # **Use probability-based prediction**
    probabilities = model.predict_proba(df_input)[0]
    predicted_class = np.argmax(probabilities)
    confidence = probabilities[predicted_class]

    logger.info(f"🔍 Predicted class: {predicted_class} with confidence {confidence:.4f}")

    # **Only block if probability is above threshold**
    if predicted_class == 1 and confidence >= MALICIOUS_THRESHOLD:
        logger.info(f"🚨 High-confidence blacklist: {data['src_ip']} ({confidence:.4f})")
        update_configmap_in_k8s(data["src_ip"])
        return jsonify({"status": "malicious", "message": "IP added to AI-WAF", "src_ip": data["src_ip"], "confidence": confidence})

    return jsonify({"status": "normal", "message": "Traffic is not malicious", "confidence": confidence})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)