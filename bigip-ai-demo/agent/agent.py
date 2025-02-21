#!/usr/bin/env python3
"""
agent.py

Agent Service that:
1. Receives synthetic TS logs via /process-log.
2. Forwards the log to the unified Model Service for prediction.
3. Retrieves dynamic endpoints from a target Kubernetes Service.
4. Generates a usecase-specific AS3 JSON declaration:
   • Uses a static virtual IP (per usecase) for BIG‑IP virtualAddresses.
   • Uses dynamic backend endpoints for pool members.
   • Adds dynamic ASM, AFM, and Endpoint policies if the prediction indicates security actions.
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

# Mapping of usecase to static virtual IP addresses.
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

def get_dynamic_endpoints(service_name, namespace):
    """
    Retrieve backend endpoints (IP addresses) from the given Kubernetes service,
    and return a list of IPs (without ports) for pool members.
    """
    v1 = client.CoreV1Api()
    try:
        endpoints_obj = v1.read_namespaced_endpoints(service_name, namespace)
        addresses = []
        if endpoints_obj.subsets:
            for subset in endpoints_obj.subsets:
                for address in subset.addresses:
                    addresses.append(address.ip)
        logging.debug(f"Dynamic endpoints for service '{service_name}': {addresses}")
        return addresses
    except Exception as e:
        logging.error(f"Error fetching endpoints for service '{service_name}': {e}")
        return []

def update_deployment_scale(deployment_name, namespace, prediction):
    """
    Scale the target deployment based on the prediction.
    If prediction is "scale_up", increase replicas; if "scale_down", decrease.
    """
    api_instance = client.AppsV1Api()
    try:
        scale_obj = api_instance.read_namespaced_deployment_scale(deployment_name, namespace)
        current_replicas = scale_obj.spec.replicas
        logging.debug(f"Current replica count for '{deployment_name}': {current_replicas}")
        new_replicas = current_replicas
        if prediction == "scale_up":
            new_replicas = current_replicas + 1
        elif prediction == "scale_down" and current_replicas > 1:
            new_replicas = current_replicas - 1

        if new_replicas != current_replicas:
            patch = {"spec": {"replicas": new_replicas}}
            logging.debug(f"Patching deployment '{deployment_name}' with: {patch}")
            api_instance.patch_namespaced_deployment_scale(deployment_name, namespace, patch)
            logging.info(f"Deployment '{deployment_name}' scaled from {current_replicas} to {new_replicas}")
        else:
            logging.info(f"No scaling change for deployment '{deployment_name}' (replicas remain {current_replicas})")
        return new_replicas
    except Exception as e:
        logging.error(f"Error scaling deployment '{deployment_name}': {e}")
        return "error"

def get_base_as3(tenant, timestamp, usecase, dynamic_endpoints, prediction):
    """
    Build a base AS3 declaration using the latest schema.
    Uses a static virtual IP (from USECASE_VIRTUAL_IPS) for the virtualAddresses field,
    and dynamic backend endpoints for pool members.
    If the prediction indicates enhanced security actions, dynamic ASM, AFM,
    and Endpoint policies are added.
    """
    virtual_ip = USECASE_VIRTUAL_IPS.get(usecase, "0.0.0.0")
    as3_payload = {
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
                        "members": [
                            {
                                "servicePort": 8080,
                                "serverAddresses": dynamic_endpoints
                            }
                        ],
                        "remark": "Dynamic routing pool"
                    }
                }
            }
        }
    }
    logging.debug("Base AS3 payload created.")

    # If the prediction indicates enhanced security actions, add dynamic policies.
    if prediction in ["block_traffic", "update_waf", "update_endpoint_policy"]:
        extended_signature_groups = [
            "SQL_Injection", "XSS", "DDoS", "Path_Traversal",
            "Remote_File_Inclusion", "CSRF", "Malware", "RCE"
        ]
        asm_policy = {
            "class": "ASM_Policy",
            "policyName": "/Common/asm_policy",
            "enforcementMode": "blocking",
            "signatureGroups": extended_signature_groups,
            "logLevel": "critical",
            "dynamicRules": {
                "blockRate": "high",
                "sensitivity": "high"
            }
        }
        afm_policy = {
            "class": "AFM_Policy",
            "policyName": "/Common/afm_policy",
            "action": "block",
            "ipReputation": "high",
            "dynamicRules": {
                "ipBlockDuration": "600",
                "threshold": "80%"
            }
        }
        endpoint_policy = {
            "class": "EndpointPolicy",
            "policyName": "/Common/endpoint_policy",
            "rules": [
                {
                    "action": "redirect",
                    "criteria": "low_latency",
                    "virtualAddress": virtual_ip
                }
            ]
        }
        logging.debug("Prediction indicates enhanced security; adding ASM, AFM, and Endpoint policies.")
        app_obj = as3_payload["declaration"]["Common"][tenant]
        app_obj["asmPolicy"] = asm_policy
        app_obj["afmPolicy"] = afm_policy
        app_obj["endpointPolicy"] = endpoint_policy
    else:
        logging.debug("No enhanced security policies added based on prediction.")

    logging.debug(f"Final AS3 payload: {json.dumps(as3_payload, indent=2)}")
    return as3_payload

def update_as3_configmap(as3_payload):
    """
    Patch the AS3 ConfigMap (monitored by F5 CIS) with the new AS3 declaration.
    """
    v1 = client.CoreV1Api()
    patch_body = {"data": {"as3-declaration": json.dumps(as3_payload)}}
    try:
        logging.debug(f"Updating ConfigMap '{AS3_CONFIGMAP}' with patch: {patch_body}")
        v1.patch_namespaced_config_map(name=AS3_CONFIGMAP, namespace=TARGET_NAMESPACE, body=patch_body)
        logging.info(f"ConfigMap '{AS3_CONFIGMAP}' updated successfully.")
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
        logging.debug(f"Target deployment: {deployment_name}, service: {service_name} for usecase {usecase}")

        # Forward the log to the Model Service.
        logging.info(f"Querying Model Service at {MODEL_SERVICE_URL} ...")
        response = requests.post(MODEL_SERVICE_URL, json=ts_log, timeout=5)
        logging.debug(f"Model Service response status: {response.status_code}")
        if response.status_code != 200:
            error_msg = f"Model service error: {response.text}"
            logging.error(error_msg)
            return jsonify({"error": "Model service error", "details": response.text}), 500

        prediction = response.json().get("prediction", "no_change")
        logging.info(f"Model prediction: {prediction}")

        # Scale the deployment if scaling is indicated.
        if prediction in ["scale_up", "scale_down"]:
            logging.debug(f"Scaling deployment '{deployment_name}' due to prediction '{prediction}'")
            replica_count = update_deployment_scale(deployment_name, TARGET_NAMESPACE, prediction)
        else:
            replica_count = "unchanged"
            logging.debug(f"No scaling required for deployment '{deployment_name}' with prediction '{prediction}'")

        # Retrieve dynamic backend endpoints.
        dynamic_endpoints = get_dynamic_endpoints(service_name, TARGET_NAMESPACE)
        if not dynamic_endpoints:
            error_msg = f"No endpoints found for service '{service_name}' in namespace '{TARGET_NAMESPACE}'."
            logging.error(error_msg)
            return jsonify({"error": error_msg}), 500

        # Build the AS3 payload using static virtual IP and dynamic endpoints.
        as3_payload = get_base_as3(ts_log.get("tenant", "Tenant_Default"),
                                   ts_log.get("timestamp", ""),
                                   usecase,
                                   dynamic_endpoints,
                                   prediction)
        logging.info("Generated AS3 payload:\n" + json.dumps(as3_payload, indent=2))
        update_as3_configmap(as3_payload)

        # Append log for future retraining.
        append_training_data(ts_log, prediction)
        logging.debug("Finished processing TS log; sending response back to caller.")

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
    logging.debug("Starting Agent Service...")
    app.run(host="0.0.0.0", port=5001, debug=True)