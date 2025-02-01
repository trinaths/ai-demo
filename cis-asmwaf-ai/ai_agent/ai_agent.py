import os
import json
import logging
import requests
import threading
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

# ✅ AI Model URL (Flask API)
MODEL_URL = "http://ai-model-container:5000/predict"  # Update with your API endpoint

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

# ✅ Function: Process Traffic Data
def process_traffic(data):
    try:
        # Extract relevant features from the traffic data
        ip_address = data.get("ip_address", "")
        http_method = data.get("http_method", "")
        uri = data.get("uri", "")
        status_code = data.get("status_code", 200)
        user_agent = data.get("user_agent", "")
        malicious = data.get("malicious", False)

        # Logging the extracted data
        logging.info(f"🚀 Processing traffic data: IP={ip_address}, Method={http_method}, URI={uri}, Status={status_code}, Malicious={malicious}")

        # Encode categorical features (like HTTP method and user_agent)
        method_mapping = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
        method_encoded = method_mapping.get(http_method, -1)  # Default to -1 if method is unknown

        uri_encoded = len(uri)  # Use the length of the URI as a feature

        # Create the feature vector
        input_data = np.array([[status_code, method_encoded, uri_encoded, malicious]])

        # Send the data to the AI model
        response = requests.post(MODEL_URL, json={"instances": input_data.tolist()}, timeout=5)
        response.raise_for_status()

        # Get the prediction result
        result = response.json()
        prediction = result["predictions"][0][0]  # Assuming single value prediction

        logging.info(f"🧠 AI Model Prediction Score: {prediction}")

        # Apply threshold for determining if the traffic is malicious
        if prediction > 0.5:
            logging.warning(f"🚨 Malicious activity detected. Updating ConfigMap...")
            update_as3_configmap([ip_address])  # You can update the ConfigMap with the IP address
        else:
            logging.info(f"✅ Traffic is normal. No action needed.")

    except requests.exceptions.RequestException as e:
        logging.error(f"❌ AI Model request failed: {str(e)}", exc_info=True)
    except Exception as e:
        logging.error(f"❌ Failed to process traffic data: {str(e)}", exc_info=True)

# ✅ Flask Route: Receive Traffic Data
@app.route('/analyze_traffic', methods=['POST'])
def analyze_traffic():
    log_data = request.get_json()

    logging.info(f"🔔 Received Traffic Data: {log_data}")

    if not log_data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    # Start processing the traffic data in a separate thread
    request_thread = threading.Thread(target=process_traffic, args=(log_data,))
    request_thread.start()

    return jsonify({"status": "processing", "message": "AI analysis started"}), 202

# ✅ Run Flask API Server
if __name__ == '__main__':
    logging.info("🚀 AI Agent is now running on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=True)