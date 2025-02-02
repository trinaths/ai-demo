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
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# **🛠 Set up Logging**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📍 Paths**
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"
DATA_STORAGE_PATH = "/data/collected_traffic.csv"

# **📂 Ensure required directories exist**
os.makedirs("/data", exist_ok=True)

app = Flask(__name__)

# **📥 Load or Initialize Model**
if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH):
    logger.info("📥 Loading trained model and encoders...")
    model = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)
else:
    logger.warning("⚠️ No model found. Initializing a new model...")
    model = RandomForestClassifier(n_estimators=150, random_state=42)
    encoders = {col: LabelEncoder() for col in ["ip_reputation", "bot_signature", "violation"]}

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
    features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
    df_input = pd.DataFrame([data])

    # **Handle unseen categories**
    for col in ["ip_reputation", "bot_signature", "violation"]:
        df_input[col] = df_input[col].fillna("Unknown").astype(str)

        unseen_labels = set(df_input[col]) - set(encoders[col].classes_)
        if unseen_labels:
            logger.warning(f"🔍 New labels in {col}: {unseen_labels}. Expanding encoder.")
            encoders[col].classes_ = np.append(encoders[col].classes_, list(unseen_labels))

        df_input[col] = encoders[col].transform(df_input[col])

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

        X = df[["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]]
        y = df["prediction"]

        # **Split data for training/testing**
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # **Retrain model**
        model.fit(X_train, y_train)

        # **Evaluate model performance**
        y_pred = model.predict(X_test)
        logger.info("📊 Model Evaluation:\n" + classification_report(y_test, y_pred))

        # **Save updated model & encoders**
        joblib.dump(model, MODEL_PATH)
        joblib.dump(label_encoders, ENCODERS_PATH)
        logger.info("✅ Model retrained successfully!")

    except Exception as e:
        logger.error(f"❌ Error during model retraining: {e}")

# **🛡️ Adjust malicious classification threshold**
MALICIOUS_THRESHOLD = 0.75

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    df_input = preprocess_data(data)

    # **Use probability instead of direct classification**
    probability = model.predict_proba(df_input)[0][1]  # Probability of malicious

    logger.info(f"🔍 Predicted malicious probability: {probability:.4f}")

    # **Only block if probability is very high**
    if probability >= 0.9:
        logger.info(f"🚨 High-confidence blacklist: {data['src_ip']} ({probability:.4f})")
        update_configmap_in_k8s(data["src_ip"])
        return jsonify({"status": "malicious", "message": "IP added to AI-WAF", "src_ip": data["src_ip"]})

    return jsonify({"status": "normal", "message": "Traffic is not malicious", "confidence": probability})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)