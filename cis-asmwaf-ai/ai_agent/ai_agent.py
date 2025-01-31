import json
import logging
import requests
import threading
import numpy as np
import joblib
import xgboost as xgb
import socket
from kubernetes import client, config
from flask import Flask, request, jsonify

# Load Kubernetes Config
config.load_incluster_config()
v1 = client.CoreV1Api()

# Load Best AI Model (XGBoost or Random Forest)
try:
    model = xgb.XGBClassifier()
    model.load_model("models/anomaly_model_xgb.json")
    logging.info("Loaded XGBoost AI Model.")
except:
    model = joblib.load("models/anomaly_model_rf.pkl")
    logging.info("Loaded Random Forest AI Model.")

# Constants
CONFIGMAP_NAME = "ai-traffic-control"
NAMESPACE = "ai-workloads"
TELEMETRY_PORT = 514  # UDP syslog port

app = Flask(__name__)

# Function to Update AS3 ConfigMap
def update_as3_configmap(malicious_ips):
    """ Updates AS3 ConfigMap in ai-tenant to block malicious IPs """
    try:
        configmap = v1.read_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE)
        as3_declaration = json.loads(configmap.data["template"])

        ip_records = as3_declaration["declaration"]["ai-tenant"]["application"]["malicious_ip_data_group"]["records"]
        existing_ips = {record["key"]: record["value"] for record in ip_records}
        new_entries = {ip: "AI-Enforced" for ip in malicious_ips if ip not in existing_ips}

        if not new_entries:
            logging.info("No new malicious IPs detected.")
            return

        updated_records = [{"key": k, "value": v} for k, v in {**existing_ips, **new_entries}.items()]
        as3_declaration["declaration"]["ai-tenant"]["application"]["malicious_ip_data_group"]["records"] = updated_records

        configmap.data["template"] = json.dumps(as3_declaration, indent=4)
        v1.replace_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE, configmap)

        logging.info(f"AS3 ConfigMap updated with {len(new_entries)} new malicious IP(s).")
    except Exception as e:
        logging.error(f"Failed to update AS3 ConfigMap: {str(e)}", exc_info=True)

# Function to Process Incoming Traffic
def process_request(source_ip, request_rate, bytes_sent, bytes_received, violation):
    """ Runs AI model prediction and updates AS3 if IP is malicious """
    input_data = np.array([[request_rate, bytes_sent, bytes_received, violation]])
    prediction = model.predict(input_data)[0]

    logging.info(f"🔍 AI Prediction Score: {prediction}")

    if prediction == 1:  # Malicious
        logging.warning(f"Malicious activity detected from {source_ip}. Blocking...")
        update_as3_configmap([source_ip])
    else:
        logging.info(f"{source_ip} is normal.")

# Function to Listen for Telemetry Streaming (Syslog)
def telemetry_listener():
    """ Listens for ASM logs over syslog and triggers AI analysis """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", TELEMETRY_PORT))
    logging.info("Listening for Telemetry Streaming on port 514...")

    while True:
        data, addr = sock.recvfrom(4096)
        log_entry = data.decode("utf-8").strip()
        logging.info(f"Received Telemetry Log: {log_entry}")

        try:
            log_data = json.loads(log_entry)
            source_ip = log_data.get("src_ip", "unknown")
            request_rate = float(log_data.get("request_rate", 0))
            bytes_sent = float(log_data.get("bytes_sent", 0))
            bytes_received = float(log_data.get("bytes_received", 0))
            violation = float(log_data.get("violation", 0))

            process_request(source_ip, request_rate, bytes_sent, bytes_received, violation)
        except json.JSONDecodeError:
            logging.warning("⚠️ Invalid log format. Skipping.")

# Start telemetry listener in a separate thread
telemetry_thread = threading.Thread(target=telemetry_listener, daemon=True)
telemetry_thread.start()

# Flask API for manual testing
@app.route('/analyze_traffic', methods=['POST'])
def analyze_traffic():
    log_data = request.get_json()
    threading.Thread(target=process_request, args=(
        log_data["source_ip"], log_data["request_rate"], log_data["bytes_sent"], log_data["bytes_received"], log_data["violation"]
    )).start()
    return jsonify({"status": "processing"}), 202

if __name__ == '__main__':
    logging.info(" AI Agent running with Telemetry Streaming on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=True)