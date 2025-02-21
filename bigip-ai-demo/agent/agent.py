#!/usr/bin/env python3
"""
agent.py

Agent Service that:
1. Receives synthetic TS logs via /process-log.
2. Forwards the log to the Model Service (unified) for a prediction.
3. Retrieves dynamic endpoints from the target Kubernetes Service.
4. Generates a usecase-specific AS3 JSON declaration:
   • Uses a static virtual IP (per usecase) for BIG‑IP virtualAddresses.
   • Uses dynamic backend endpoints (IP-only) for pool members.
5. Updates a Kubernetes ConfigMap (monitored by F5 CIS) with the AS3 declaration.
6. Scales the target deployment based on the prediction.
7. Appends the processed log for future retraining.
"""

import json
import os
import requests
from flask import Flask, request, jsonify
from kubernetes import client, config
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------------------------
# Load Kubernetes configuration (in-cluster or from kubeconfig)
# ------------------------------------------------------------------------------
try:
    config.load_incluster_config()
    logging.info("Loaded in-cluster Kubernetes config.")
except Exception as e:
    config.load_kube_config()
    logging.info("Loaded kubeconfig.")

# ------------------------------------------------------------------------------
# Configuration Variables
# ------------------------------------------------------------------------------
MODEL_SERVICE_URL = "http://10.4.1.115:30000/predict"  # Unified Model Service endpoint
TARGET_NAMESPACE = os.getenv("TARGET_NAMESPACE", "bigip-demo")
AS3_CONFIGMAP = os.getenv("AS3_CONFIGMAP", "as3-config")
TRAINING_DATA_PATH = "/app/models/accumulated_ts_logs.jsonl"

# Mapping of usecases to deployments and services.
USECASE_DEPLOYMENT_MAP = {
    1: {"deployment": "ai-cluster", "service": "ai-cluster-service"},
    2: {"deployment": "eastwest-app", "service": "eastwest-service"},
    3: {"deployment": "storage-service", "service": "storage-service"},
    4: {"deployment": "multicluster-service", "service": "multicluster-service"},
    5: {"deployment": "lowlatency-app", "service": "lowlatency-service"},
    6: {"deployment": "api-gateway", "service": "api-gateway-service"},
    7: {"deployment": "fraud-detection", "service": "fraud-detection-service"},
    8: {"deployment": "traffic-monitor", "service": "traffic-monitor-service"},
}

# Mapping of usecase to static virtual IP addresses for BIG‑IP configuration.
USECASE_VIRTUAL_IPS = {
    1: "192.168.0.101",
    2: "192.168.0.102",
    3: "192.168.0.103",
    4: "192.168.0.104",
    5: "192.168.0.105",
    6: "192.168.0.106",
    7: "192.168.0.107",
    8: "192.168.0.108",
}

# ------------------------------------------------------------------------------
# Kubernetes Helper Functions
# ------------------------------------------------------------------------------
def get_dynamic_endpoints(service_name, namespace):
    """
    Retrieve backend endpoints (IP:port) from the given Kubernetes service,
    and return only the IPs (as a list) for pool members.
    """
    v1 = client.CoreV1Api()
    try:
        endpoints_obj = v1.read_namespaced_endpoints(service_name, namespace)
        addresses = []
        if endpoints_obj.subsets:
            for subset in endpoints_obj.subsets:
                port = subset.ports[0].port
                for address in subset.addresses:
                    # We only need the IP part for pool members.
                    addresses.append(address.ip)
        logging.debug(f"Dynamic endpoints for service '{service_name}': {addresses}")
        return addresses
    except Exception as e:
        logging.error(f"Error fetching endpoints for service '{service_name}': {e}")
        return []

def update_deployment_scale(deployment_name, namespace, prediction):
    """
    Scale the target deployment based on the prediction.
    If the prediction is "scale_up", increase replica count; if "scale_down", decrease.
    """
    api_instance = client.AppsV1Api()
    try:
        scale_obj = api_instance.read_namespaced_deployment_scale(deployment_name, namespace)
        current_replicas = scale_obj.spec.replicas
        new_replicas = current_replicas
        if prediction == "scale_up":
            new_replicas = current_replicas + 1
        elif prediction == "scale_down" and current_replicas > 1:
            new_replicas = current_replicas - 1

        if new_replicas != current_replicas:
            patch = {"spec": {"replicas": new_replicas}}
            api_instance.patch_namespaced_deployment_scale(deployment_name, namespace, patch)
            logging.info(f"Deployment '{deployment_name}' scaled from {current_replicas} to {new_replicas}")
        else:
            logging.info(f"No scaling change for deployment '{deployment_name}' (replicas remain {current_replicas})")
        return new_replicas
    except Exception as e:
        logging.error(f"Error scaling deployment '{deployment_name}': {e}")
        return "error"

def get_base_as3(tenant, timestamp, usecase, dynamic_endpoints):
    """
    Build a base AS3 declaration. For the virtual address, use a static IP based on the usecase.
    For pool members, use the dynamic endpoints (list of IPs) retrieved from Kubernetes.
    """
    # Look up the static virtual IP for the usecase.
    virtual_ip = USECASE_VIRTUAL_IPS.get(usecase, "0.0.0.0")
    return {
        "class": "AS3",
        "action": "deploy",
        "persist": True,
        "declaration": {
            "class": "ADC",
            "schemaVersion": "3.0.0",
            "id": f"{tenant}-{timestamp}",
            "label": f"Update for {tenant}",
            "Common": {
                "class": "Tenant",
                f"{tenant}": {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTP": {
                        "class": "Service_HTTP",
                        "virtualAddresses": [virtual_ip],
                        "pool": "app_pool"
                    },
                    "app_pool": {
                        "class": "Pool",
                        "members": [{"servicePort": 8080, "serverAddresses": dynamic_endpoints}],
                        "remark": "Dynamic routing pool"
                    }
                }
            }
        }
    }

def update_as3_configmap(as3_payload):
    """
    Patch the AS3 ConfigMap (monitored by F5 CIS) with the new declaration.
    """
    v1 = client.CoreV1Api()
    patch_body = {"data": {"as3-declaration": json.dumps(as3_payload)}}
    try:
        v1.patch_namespaced_config_map(name=AS3_CONFIGMAP, namespace=TARGET_NAMESPACE, body=patch_body)
        logging.info(f"ConfigMap '{AS3_CONFIGMAP}' updated with new AS3 declaration.")
    except Exception as e:
        logging.error(f"Error updating ConfigMap '{AS3_CONFIGMAP}': {e}")

def append_training_data(ts_log, prediction):
    """
    Append the processed TS log with its predicted label to a file for future retraining.
    """
    ts_log["predicted_label"] = prediction
    try:
        os.makedirs(os.path.dirname(TRAINING_DATA_PATH), exist_ok=True)
        with open(TRAINING_DATA_PATH, "a") as f:
            f.write(json.dumps(ts_log) + "\n")
        logging.debug("Training data appended successfully.")
    except Exception as e:
        logging.error(f"Error appending training data: {e}")

@app.route("/process-log", methods=["POST"])
def process_log():
    try:
        ts_log = request.get_json()
        if not ts_log:
            logging.error("No JSON payload received.")
            return jsonify({"error": "No JSON payload received"}), 400

        logging.info("Received TS log:\n" + json.dumps(ts_log, indent=2))
        usecase = ts_log.get("usecase")
        if usecase not in USECASE_DEPLOYMENT_MAP:
            error_msg = f"Unsupported usecase: {usecase}"
            logging.error(error_msg)
            return jsonify({"error": error_msg}), 400

        target_info = USECASE_DEPLOYMENT_MAP[usecase]
        deployment_name = target_info["deployment"]
        service_name = target_info["service"]

        # Forward the log to the Model Service for prediction.
        logging.info(f"Querying Model Service at {MODEL_SERVICE_URL} ...")
        response = requests.post(MODEL_SERVICE_URL, json=ts_log, timeout=5)
        if response.status_code != 200:
            error_msg = f"Model service error: {response.text}"
            logging.error(error_msg)
            return jsonify({"error": "Model service error", "details": response.text}), 500

        prediction = response.json().get("prediction", "no_change")
        logging.info(f"Model prediction: {prediction}")

        # Scale the deployment if the prediction indicates scaling.
        if prediction in ["scale_up", "scale_down"]:
            replica_count = update_deployment_scale(deployment_name, TARGET_NAMESPACE, prediction)
        else:
            replica_count = "unchanged"

        # Retrieve dynamic backend endpoints from the target service.
        dynamic_endpoints = get_dynamic_endpoints(service_name, TARGET_NAMESPACE)
        if not dynamic_endpoints:
            error_msg = f"No endpoints found for service '{service_name}' in namespace '{TARGET_NAMESPACE}'."
            logging.error(error_msg)
            return jsonify({"error": error_msg}), 500

        # Build the AS3 payload using a static virtual IP (per usecase) and dynamic endpoints for pool members.
        as3_payload = get_base_as3(ts_log.get("tenant", "Tenant_Default"), ts_log.get("timestamp", ""), usecase, dynamic_endpoints)
        logging.info("Generated AS3 payload:\n" + json.dumps(as3_payload, indent=2))
        update_as3_configmap(as3_payload)

        # Append the log along with its prediction for future retraining.
        append_training_data(ts_log, prediction)

        return jsonify({
            "status": "success",
            "prediction": prediction,
            "scaled_replicas": replica_count,
            "as3": as3_payload
        })
    except Exception as e:
        logging.error("Exception in process_log: " + str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)