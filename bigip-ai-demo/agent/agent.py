#!/usr/bin/env python3
"""
Improved agent.py with enhanced debug logging.

Agent Service that:
1. Receives synthetic TS logs via /process-log.
2. Queries the Model Service for a prediction.
3. Dynamically retrieves current endpoints from a target Kubernetes Service.
4. Generates a use-case specific AS3 JSON declaration.
5. Updates a Kubernetes ConfigMap (monitored by F5 CIS) with the AS3 declaration.
6. Scales a target deployment if required.
7. Appends processed logs for future retraining.
"""

import json
import os
import requests
import traceback
from flask import Flask, request, jsonify
from kubernetes import client, config

app = Flask(__name__)

# ------------------------------------------------------------------------------
# Load Kubernetes configuration (in-cluster or kubeconfig)
# ------------------------------------------------------------------------------
try:
    config.load_incluster_config()
    print("✅ Loaded in-cluster Kubernetes config.")
except Exception:
    config.load_kube_config()
    print("✅ Loaded kubeconfig.")

# ------------------------------------------------------------------------------
# Configuration variables
# ------------------------------------------------------------------------------
MODEL_SERVICE_URL = "http://10.4.1.115:30000/predict"  # Ensure this is correct!

TARGET_DEPLOYMENT = "sample-deployment"
TARGET_NAMESPACE = os.getenv("TARGET_NAMESPACE", "bigip-demo")

TARGET_SERVICE = os.getenv("TARGET_SERVICE", "ai-cluster-service")
AS3_CONFIGMAP = os.getenv("AS3_CONFIGMAP", "as3-config")

TRAINING_DATA_PATH = "/app/models/accumulated_ts_logs.jsonl"

print(f"ℹ️  Agent Configurations:\n  - MODEL_SERVICE_URL: {MODEL_SERVICE_URL}\n"
      f"  - TARGET_DEPLOYMENT: {TARGET_DEPLOYMENT}\n"
      f"  - TARGET_NAMESPACE: {TARGET_NAMESPACE}\n"
      f"  - TARGET_SERVICE: {TARGET_SERVICE}\n"
      f"  - AS3_CONFIGMAP: {AS3_CONFIGMAP}\n")

# ------------------------------------------------------------------------------
# Kubernetes Functions
# ------------------------------------------------------------------------------
def get_dynamic_endpoints(service_name, namespace):
    """
    Retrieve internal pod IPs from a service.
    """
    v1 = client.CoreV1Api()
    print(f"🔍 Fetching endpoints for service: {service_name} in namespace: {namespace}")

    try:
        endpoints = v1.read_namespaced_endpoints(service_name, namespace)
        addresses = []
        if endpoints.subsets:
            for subset in endpoints.subsets:
                if subset.addresses:
                    for addr in subset.addresses:
                        addresses.append(addr.ip)
        print(f"✅ Retrieved endpoints: {addresses}")
        return addresses
    except Exception as e:
        print(f"❌ Error fetching service endpoints: {e}")
        return []

def update_deployment_scale(prediction):
    """
    Scale the target deployment based on the AI model's prediction.
    """
    api_instance = client.AppsV1Api()
    print(f"🔄 Scaling Deployment '{TARGET_DEPLOYMENT}' in '{TARGET_NAMESPACE}' based on prediction: {prediction}")

    try:
        scale_obj = api_instance.read_namespaced_deployment_scale(TARGET_DEPLOYMENT, TARGET_NAMESPACE)
        current_replicas = scale_obj.status.replicas
        new_replicas = max(1, current_replicas + (1 if prediction == "scale_up" else -1))

        patch = {"spec": {"replicas": new_replicas}}
        api_instance.patch_namespaced_deployment_scale(TARGET_DEPLOYMENT, TARGET_NAMESPACE, patch)
        print(f"✅ Deployment scaled: {current_replicas} ➡ {new_replicas}")
        return new_replicas
    except Exception as e:
        print(f"❌ Error scaling deployment: {e}")
        return "error"

def update_as3_configmap(as3_payload):
    """
    Patch AS3 ConfigMap with a new declaration.
    """
    v1 = client.CoreV1Api()
    print(f"📝 Updating AS3 ConfigMap '{AS3_CONFIGMAP}' in namespace '{TARGET_NAMESPACE}'.")

    patch_body = {"data": {"as3-declaration": json.dumps(as3_payload, indent=2)}}

    try:
        v1.patch_namespaced_config_map(name=AS3_CONFIGMAP, namespace=TARGET_NAMESPACE, body=patch_body)
        print(f"✅ AS3 ConfigMap '{AS3_CONFIGMAP}' updated successfully.")
    except Exception as e:
        print(f"❌ Error updating AS3 ConfigMap: {e}")
        raise

# ------------------------------------------------------------------------------
# AS3 Payload Generation
# ------------------------------------------------------------------------------
def get_base_as3(tenant, timestamp, endpoints):
    """
    Build a base AS3 payload.
    """
    return {
        "class": "AS3",
        "action": "deploy",
        "persist": True,
        "declaration": {
            "class": "ADC",
            "schemaVersion": "3.0.0",
            "id": f"{tenant}-{timestamp}",
            "label": "",
            "Common": {
                "class": "Tenant",
                tenant: {
                    "class": "Application",
                    "template": "generic"
                }
            }
        }
    }

def generate_as3_payload(ts_log, prediction, replica_count):
    """
    Generate an AS3 declaration based on the AI model's prediction.
    """
    usecase = ts_log.get("usecase", "unknown")
    tenant = ts_log.get("tenant", "Tenant_Default")
    timestamp = ts_log.get("timestamp", "")

    print(f"🔧 Generating AS3 payload for usecase {usecase}...")

    endpoints = get_dynamic_endpoints(TARGET_SERVICE, TARGET_NAMESPACE)
    if not endpoints:
        raise RuntimeError(f"❌ No endpoints found for {TARGET_SERVICE} in {TARGET_NAMESPACE}.")

    payload = get_base_as3(tenant, timestamp, endpoints)
    payload["declaration"]["Common"][tenant].update({
        "serviceHTTP": {
            "class": "Service_HTTP",
            "virtualAddresses": endpoints,
            "pool": "dynamic_pool"
        },
        "dynamic_pool": {
            "class": "Pool",
            "members": [{"servicePort": 80, "serverAddresses": endpoints}],
            "remark": f"Use case {usecase} routing"
        }
    })

    print(f"✅ AS3 payload generated:\n{json.dumps(payload, indent=2)}")
    return payload

# ------------------------------------------------------------------------------
# Flask Endpoints
# ------------------------------------------------------------------------------
@app.route("/process-log", methods=["POST"])
def process_log():
    try:
        ts_log = request.get_json()
        if not ts_log:
            print("❌ Received empty JSON payload.")
            return jsonify({"error": "No JSON payload received"}), 400

        print(f"📥 Received TS Log:\n{json.dumps(ts_log, indent=2)}")

        # Query Model Service
        try:
            response = requests.post(MODEL_SERVICE_URL, json=ts_log, timeout=5)
            response.raise_for_status()
            prediction = response.json().get("prediction", "no_change")
            print(f"✅ Model prediction received: {prediction}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Model Service Error: {e}")
            prediction = "no_change"

        # Scale Deployment
        replica_count = update_deployment_scale(prediction) if prediction in ["scale_up", "scale_down"] else "unchanged"

        # Generate AS3 Payload
        as3_payload = generate_as3_payload(ts_log, prediction, replica_count)

        # Update AS3 ConfigMap
        update_as3_configmap(as3_payload)

        return jsonify({"status": "success", "prediction": prediction, "as3": as3_payload})

    except Exception as e:
        print(f"❌ ERROR processing log: {e}")
        print(traceback.format_exc())  # Print full stack trace for debugging
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------------------------------------
# Run Flask App
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)