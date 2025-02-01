import os
import json
import logging
import threading
import time
import requests
from flask import Flask, request, jsonify
from kubernetes import client, config

# Logging Configuration
logging.basicConfig(
    level=logging.DEBUG,  # Capture detailed logs
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logging.info("CIS demo AI Agent for CIS is starting...")

# Load Kubernetes Config (Supports Secret-based Kubeconfig)
try:
    kubeconfig_path = "/root/.kube/kubeconfig"
    if os.path.exists(kubeconfig_path):
        config.load_kube_config(config_file=kubeconfig_path)  # ✅ Load from Secret
        logging.info("Using Secret-based Kubernetes configuration")
    elif "KUBERNETES_SERVICE_HOST" in os.environ:
        config.load_incluster_config()
        logging.info("Using in-cluster Kubernetes configuration")
    else:
        config.load_kube_config()  # Fallback to local
        logging.info("Using local kubeconfig")
except Exception as e:
    logging.critical(f"Kubernetes configuration error: {str(e)}", exc_info=True)

# Kubernetes API Client
v1 = client.CoreV1Api()

# AI Model URL
MODEL_URL = "http://ai-inference.ai-workloads.svc.cluster.local:8501/v1/models/anomaly_model"
logging.info(f" F5 AI Model URL set to {MODEL_URL}")

# Kubernetes ConfigMap Name and Namespace
CONFIGMAP_NAME = "ai-traffic-control"
NAMESPACE = "ai-workloads"

# Flask App
app = Flask(__name__)

# Function to Validate AI Model URL
def validate_model_url():
    try:
        response = requests.get(f"{MODEL_URL}/metadata", timeout=5)
        if response.status_code == 200:
            logging.info("CIS demo AI Model is accessible.")
            return True
    except requests.exceptions.RequestException as e:
        logging.warning(f" F5 AI Model is unreachable: {str(e)}")
    logging.error("IS demo AI Model URL is NOT accessible.")
    return False

# Function to Fetch AI Model Version
def get_model_version():
    return "1"

# Function to Read AS3 ConfigMap
def read_as3_configmap():
    try:
        logging.debug("Fetching AS3 ConfigMap...")
        configmap = v1.read_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE)
        as3_data = json.loads(configmap.data["template"])
        logging.debug("Successfully retrieved AS3 ConfigMap.")
        return as3_data
    except Exception as e:
        logging.error(f"Failed to read AS3 ConfigMap: {str(e)}", exc_info=True)
        return None


# Function to Update AS3 ConfigMap with Malicious IPs
def update_as3_configmap(malicious_ips, model_version=1):
    try:
        logging.debug("Fetching existing AS3 ConfigMap for update...")
        configmap = v1.read_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE)
        as3_declaration = json.loads(configmap.data["template"])

        # Extract existing records in malicious_ip_data_group
        ip_records = as3_declaration["declaration"]["ai-tenant"]["application"]["malicious_ip_data_group"].get("records", [])

        # Convert existing records to a dictionary for fast lookup
        existing_ips = {record["key"]: record["value"] for record in ip_records}

        # New malicious IPs to be added
        new_entries = {ip: "auto-detected" for ip in malicious_ips if ip not in existing_ips}

        if not new_entries:
            logging.info("No new malicious IPs detected. Skipping AS3 update.")
            return

        # Extend AS3 data group with new entries
        updated_records = [{"key": k, "value": v} for k, v in {**existing_ips, **new_entries}.items()]
        as3_declaration["declaration"]["ai-tenant"]["application"]["malicious_ip_data_group"]["records"] = updated_records

        # Update the ConfigMap
        configmap.data["template"] = json.dumps(as3_declaration, indent=4)
        v1.replace_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE, configmap)

        logging.info(f"AS3 ConfigMap updated with {len(new_entries)} new malicious IP(s).")

    except Exception as e:
        logging.error(f"Failed to update AS3 ConfigMap: {str(e)}", exc_info=True)

# Function to Periodically Check AI Model Status & Improve AS3 ConfigMap
def periodic_model_check():
    while True:
        logging.info("Checking CIS demo AI Model status...")
        if validate_model_url():
            model_version = get_model_version()
            logging.info("Updating AS3 ConfigMap with latest model version...")
            update_as3_configmap([], model_version=1)  # No malicious IPs, just update metadata
        else:
            logging.warning("CIS demo AI Model unavailable. Skipping AS3 update.")
        time.sleep(600)  # Check every 10 minutes

# Function to Process Traffic Request
def process_request(log_data):
    source_ip = log_data["source_ip"]
    request_rate = float(log_data["request_rate"])
    bytes_transferred = float(log_data["bytes_transferred"])

    logging.debug(f"Received traffic log: IP={source_ip}, Request Rate={request_rate}, Bytes={bytes_transferred}")

    payload = {"instances": [[request_rate, bytes_transferred]]}

    try:
        logging.debug("Sending data to F5 AI Model for prediction...")
        response = requests.post(f"{MODEL_URL}:predict", json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()

        logging.debug(f"CIS demo AI Model Response: {result}")

        if "predictions" not in result or not result["predictions"]:
            logging.warning("Invalid F5 AI model response. Skipping processing.")
            return

        prediction = result["predictions"][0][0]
        logging.info(f"CIS demo AI Model Prediction Score: {prediction}")

        # Change threshold to detect all malicious traffic
        if prediction > 0.5:  # Lowering threshold ensures all anomalies are captured
            logging.warning(f"Malicious activity detected from {source_ip}. Updating AS3 ConfigMap...")
            update_as3_configmap([source_ip], model_version=1)
        else:
            logging.info(f"{source_ip} traffic is normal. No action needed.")

    except requests.exceptions.RequestException as e:
        logging.error(f"CIS demo AI Model request failed: {str(e)}", exc_info=True)

@app.route('/analyze_traffic', methods=['POST'])
def analyze_traffic():
    log_data = request.get_json()
    
    logging.info(f"analyze_traffic triggered - Received request: {log_data}")
    
    if not log_data:
        logging.error("Error: No data received!")
        return jsonify({"status": "error", "message": "No data received"}), 400

    request_thread = threading.Thread(target=process_request, args=(log_data,))
    request_thread.start()
    
    return jsonify({"status": "processing", "message": "AI analysis started..."}), 202

if __name__ == '__main__':
    logging.info("CIS demo AI Agent for CIS is now running on port 5000")

    # Start periodic AI Model health check in a separate thread
    model_check_thread = threading.Thread(target=periodic_model_check, daemon=True)
    model_check_thread.start()

    app.run(host='0.0.0.0', port=5000, debug=True)
