import os
import json
import logging
import requests
import threading
import tensorflow as tf
import numpy as np
from flask import Flask, request, jsonify
from kubernetes import client, config

# ✅ Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logging.info("🚀 AI Agent is starting...")

# ✅ Load Kubernetes Config (Supports Secret-based Kubeconfig)
try:
    kubeconfig_path = "/root/.kube/kubeconfig"
    if os.path.exists(kubeconfig_path):
        config.load_kube_config(config_file=kubeconfig_path)  # ✅ Load from Secret
        logging.info("✅ Using Secret-based Kubernetes configuration")
    elif "KUBERNETES_SERVICE_HOST" in os.environ:
        config.load_incluster_config()
        logging.info("✅ Using in-cluster Kubernetes configuration")
    else:
        config.load_kube_config()  # Fallback to local
        logging.info("✅ Using local kubeconfig")
except Exception as e:
    logging.critical(f"❌ Kubernetes configuration error: {str(e)}", exc_info=True)

# ✅ Kubernetes API Client
v1 = client.CoreV1Api()

# ✅ AI Model URL (TensorFlow Serving)
MODEL_URL = "http://ai-inference.ai-workloads.svc.cluster.local:8501/v1/models/anomaly_model_tf:predict"
logging.info(f"🧠 AI Model URL set to {MODEL_URL}")

# ✅ Kubernetes ConfigMap Details
CONFIGMAP_NAME = "ai-traffic-control"
NAMESPACE = "ai-workloads"

# ✅ Flask App
app = Flask(__name__)

# ✅ Function: Read AS3 ConfigMap
def read_as3_configmap():
    try:
        configmap = v1.read_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE)
        as3_data = json.loads(configmap.data["template"])
        return as3_data
    except Exception as e:
        logging.error(f"❌ Failed to read AS3 ConfigMap: {str(e)}", exc_info=True)
        return None

# ✅ Function: Update AS3 ConfigMap
def update_as3_configmap(malicious_ips):
    try:
        configmap = v1.read_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE)
        as3_declaration = json.loads(configmap.data["template"])

        # ✅ Get existing malicious IPs
        ip_records = as3_declaration["declaration"]["Shared"]["WAF_Security"]["malicious_ip_data_group"]["records"]
        existing_ips = {record["key"] for record in ip_records}

        # ✅ Add only new malicious IPs
        new_ips = [{"key": ip, "value": "AI-Detected Threat"} for ip in malicious_ips if ip not in existing_ips]
        if not new_ips:
            logging.info("✅ No new malicious IPs detected. Skipping AS3 update.")
            return

        ip_records.extend(new_ips)
        configmap.data["template"] = json.dumps(as3_declaration, indent=4)

        # ✅ Update ConfigMap in Kubernetes
        v1.replace_namespaced_config_map(CONFIGMAP_NAME, NAMESPACE, configmap)
        logging.info(f"✅ AS3 ConfigMap updated with {len(new_ips)} new malicious IP(s).")
    except Exception as e:
        logging.error(f"❌ Failed to update AS3 ConfigMap: {str(e)}", exc_info=True)

# ✅ Function: Process WAF Telemetry Data
def process_telemetry(data):
    try:
        source_ip = data.get("ip")
        attack_type = data.get("attack_type")
        
        logging.info(f"🚀 Received WAF Log: IP={source_ip}, Attack={attack_type}")

        # ✅ Prepare AI Model Input
        input_data = np.array([[1]])  # Dummy data (Replace with actual WAF features)

        # ✅ Send Data to AI Model
        response = requests.post(MODEL_URL, json={"instances": input_data.tolist()}, timeout=5)
        response.raise_for_status()
        result = response.json()

        prediction = result["predictions"][0][0]  # Extract prediction score
        logging.info(f"🧠 AI Model Prediction Score: {prediction}")

        # ✅ Decision Threshold: If AI flags it, block the IP
        if prediction > 0.5:
            logging.warning(f"🚨 Malicious activity detected from {source_ip}. Updating AS3 ConfigMap...")
            update_as3_configmap([source_ip])
        else:
            logging.info(f"✅ Traffic from {source_ip} is normal. No action needed.")

    except requests.exceptions.RequestException as e:
        logging.error(f"❌ AI Model request failed: {str(e)}", exc_info=True)
    except Exception as e:
        logging.error(f"❌ Failed to process telemetry data: {str(e)}", exc_info=True)

# ✅ Flask Route: Receive BIG-IP WAF Telemetry
@app.route('/analyze_traffic', methods=['POST'])
def analyze_traffic():
    log_data = request.get_json()

    logging.info(f"🔔 Received Telemetry Data: {log_data}")

    if not log_data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    request_thread = threading.Thread(target=process_telemetry, args=(log_data,))
    request_thread.start()

    return jsonify({"status": "processing", "message": "AI analysis started"}), 202

# ✅ Run Flask API Server
if __name__ == '__main__':
    logging.info("🚀 AI Agent is now running on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=True)