#!/usr/bin/env python3
"""
agent.py

Agent Service that:
1. Receives synthetic TS logs via /process-log.
2. Queries the Model Service for a prediction.
3. Dynamically retrieves current endpoints from a target Kubernetes Service.
4. Generates a usecase-specific AS3 JSON declaration.
5. Updates a Kubernetes ConfigMap (monitored by F5 CIS) with the AS3 declaration.
6. Scales a target deployment if required.
7. Appends processed logs for future retraining.
"""

import json
import os
import requests
from flask import Flask, request, jsonify
from kubernetes import client, config

app = Flask(__name__)

# ------------------------------------------------------------------------------
# Load Kubernetes configuration (in-cluster or kubeconfig)
# ------------------------------------------------------------------------------
try:
    config.load_incluster_config()
    print("Loaded in-cluster Kubernetes config.")
except Exception:
    config.load_kube_config()
    print("Loaded kubeconfig.")

# ------------------------------------------------------------------------------
# Helper functions to retrieve endpoints
# ------------------------------------------------------------------------------

def get_nodeport_endpoint(service_name, namespace):
    """
    Retrieve the external endpoint for a NodePort service.
    Returns a list of strings in the format "NODE_IP:NodePort".
    """
    v1 = client.CoreV1Api()
    service = v1.read_namespaced_service(service_name, namespace)
    node_port = service.spec.ports[0].node_port  # Assumes first port is used.
    nodes = v1.list_node()
    endpoints = []
    for node in nodes.items:
        for address in node.status.addresses:
            if address.type == "ExternalIP":
                endpoints.append(f"{address.address}:{node_port}")
    return endpoints

def get_dynamic_endpoints(service_name, namespace):
    """
    Retrieve current pod IPs (internal endpoints) from the specified service.
    """
    v1 = client.CoreV1Api()
    endpoints_obj = v1.read_namespaced_endpoints(service_name, namespace)
    addresses = []
    if endpoints_obj.subsets:
        for subset in endpoints_obj.subsets:
            if subset.addresses:
                for addr in subset.addresses:
                    addresses.append(addr.ip)
    return addresses

# ------------------------------------------------------------------------------
# Configuration variables
# ------------------------------------------------------------------------------

# Dynamically obtain the Model Service external endpoint.
model_ep = get_nodeport_endpoint("model-service", "bigip-demo")
if not model_ep:
    raise RuntimeError("No external endpoints found for 'model-service' in 'bigip-demo' namespace.")
MODEL_SERVICE_URL = f"http://10.4.1.115:3000/predict"  # e.g., "http://<node_ip>:<nodeport>/predict"

# Deployment and namespace for scaling.
TARGET_DEPLOYMENT = "sample-deployment"
TARGET_NAMESPACE = os.getenv("TARGET_NAMESPACE", "bigip-demo")

# TARGET_SERVICE is set as an environment variable in the deployment YAML.
TARGET_SERVICE = os.getenv("TARGET_SERVICE")
if not TARGET_SERVICE:
    raise ValueError("TARGET_SERVICE environment variable must be set.")

# ConfigMap name for AS3 declarations (monitored by F5 CIS).
AS3_CONFIGMAP = os.getenv("AS3_CONFIGMAP", "as3-config")

# Path for accumulating training data.
TRAINING_DATA_PATH = "/app/models/accumulated_ts_logs.jsonl"

# ------------------------------------------------------------------------------
# Deployment Scaling and AS3 Payload Functions
# ------------------------------------------------------------------------------

def update_deployment_scale(prediction):
    """
    Scale the target deployment based on the prediction.
    """
    api_instance = client.AppsV1Api()
    scale_obj = api_instance.read_namespaced_deployment_scale(TARGET_DEPLOYMENT, TARGET_NAMESPACE)
    current_replicas = scale_obj.status.replicas
    new_replicas = current_replicas
    if prediction == "scale_up":
        new_replicas = current_replicas + 1
    elif prediction == "scale_down" and current_replicas > 1:
        new_replicas = current_replicas - 1
    patch = {"spec": {"replicas": new_replicas}}
    api_instance.patch_namespaced_deployment_scale(TARGET_DEPLOYMENT, TARGET_NAMESPACE, patch)
    print(f"Deployment '{TARGET_DEPLOYMENT}' scaled from {current_replicas} to {new_replicas}")
    return new_replicas

def get_base_as3(tenant, timestamp, dynamic_endpoints):
    """
    Build a base AS3 payload common to all usecases.
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
    Generate a usecase-specific AS3 payload based on the 'usecase' field.
    
    Usecases supported:
      1. Traffic Management across AI Clusters  
      2. AI East-West and RAG Workflows  
      3. Data Storage Traffic Management  
      4. Multi-Cluster Networking  
      5. Low Latency & High Throughput
    """
    usecase = ts_log.get("usecase")
    tenant = ts_log.get("tenant", "Tenant_Default")
    timestamp = ts_log.get("timestamp", "")
    
    # Retrieve internal endpoints from the target service.
    dynamic_endpoints = get_dynamic_endpoints(TARGET_SERVICE, TARGET_NAMESPACE)
    if not dynamic_endpoints:
        raise RuntimeError(f"No endpoints found for service '{TARGET_SERVICE}' in namespace '{TARGET_NAMESPACE}'.")
    
    payload = get_base_as3(tenant, timestamp, dynamic_endpoints)
    
    if usecase == 1:
        payload["declaration"]["id"] = f"{tenant}-traffic-mgmt-{timestamp}"
        payload["declaration"]["label"] = "Traffic Management across AI Clusters"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTPS": {
                "class": "Service_HTTPS",
                "virtualAddresses": dynamic_endpoints,
                "pool": "ai_clusters_pool",
                "sslProfileClient": "clientSSL"
            },
            "clientSSL": {
                "class": "SSL_Profile_Client",
                "context": "clients",
                "cert": "/Common/client.crt",
                "key": "/Common/client.key"
            },
            "ai_clusters_pool": {
                "class": "Pool",
                "members": [{"servicePort": 443, "serverAddresses": dynamic_endpoints}],
                "remark": "Routing traffic across AI clusters"
            }
        })
    elif usecase == 2:
        payload["declaration"]["id"] = f"{tenant}-eastwest-{timestamp}"
        payload["declaration"]["label"] = "AI East-West & RAG Workflows"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTP": {
                "class": "Service_HTTP",
                "virtualAddresses": dynamic_endpoints,
                "pool": "eastwest_pool"
            },
            "eastwest_pool": {
                "class": "Pool",
                "members": [{"servicePort": 80, "serverAddresses": dynamic_endpoints}],
                "remark": "Routing internal AI and RAG traffic"
            }
        })
    elif usecase == 3:
        payload["declaration"]["id"] = f"{tenant}-storage-{timestamp}"
        payload["declaration"]["label"] = "Data Storage Traffic Management"
        payload["declaration"]["Common"][tenant].update({
            "serviceTCP": {
                "class": "Service_TCP",
                "virtualAddresses": dynamic_endpoints,
                "pool": "storage_pool"
            },
            "storage_pool": {
                "class": "Pool",
                "members": [{"servicePort": 8080, "serverAddresses": dynamic_endpoints}],
                "remark": "Optimized routing to data storage endpoints"
            }
        })
    elif usecase == 4:
        payload["declaration"]["id"] = f"{tenant}-multicluster-{timestamp}"
        payload["declaration"]["label"] = "Multi Cluster Networking"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTPS": {
                "class": "Service_HTTPS",
                "virtualAddresses": dynamic_endpoints,
                "pool": "multicluster_pool",
                "sslProfileClient": "clientSSL"
            },
            "clientSSL": {
                "class": "SSL_Profile_Client",
                "context": "clients",
                "cert": "/Common/client.crt",
                "key": "/Common/client.key"
            },
            "multicluster_pool": {
                "class": "Pool",
                "members": [{"servicePort": 443, "serverAddresses": dynamic_endpoints}],
                "remark": "Global load balancing across clusters"
            }
        })
    elif usecase == 5:
        payload["declaration"]["id"] = f"{tenant}-lowlatency-{timestamp}"
        payload["declaration"]["label"] = "Low Latency & High Throughput"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTPS": {
                "class": "Service_HTTPS",
                "virtualAddresses": dynamic_endpoints,
                "pool": "lowlatency_pool",
                "sslProfileClient": "clientSSL"
            },
            "clientSSL": {
                "class": "SSL_Profile_Client",
                "context": "clients",
                "cert": "/Common/client.crt",
                "key": "/Common/client.key"
            },
            "lowlatency_pool": {
                "class": "Pool",
                "members": [{"servicePort": 443, "serverAddresses": dynamic_endpoints}],
                "remark": "Optimized for low latency and high throughput"
            }
        })
    else:
        payload = {"error": "No AS3 payload defined for this usecase"}
    
    return payload

def update_as3_configmap(as3_payload):
    """
    Patch the AS3 ConfigMap (AS3_CONFIGMAP) in TARGET_NAMESPACE with the new AS3 declaration.
    F5 CIS monitors this ConfigMap and pushes the configuration to BIG-IP.
    """
    v1 = client.CoreV1Api()
    patch_body = {"data": {"as3-declaration": json.dumps(as3_payload)}}
    try:
        v1.patch_namespaced_config_map(name=AS3_CONFIGMAP, namespace=TARGET_NAMESPACE, body=patch_body)
        print(f"ConfigMap '{AS3_CONFIGMAP}' updated with new AS3 declaration.")
    except Exception as e:
        print(f"Error updating ConfigMap '{AS3_CONFIGMAP}': {e}")
        raise

def append_training_data(ts_log, prediction):
    """
    Append the processed TS log (with its predicted label) to the training data file.
    """
    ts_log["predicted_label"] = prediction
    try:
        os.makedirs(os.path.dirname(TRAINING_DATA_PATH), exist_ok=True)
        with open(TRAINING_DATA_PATH, "a") as f:
            f.write(json.dumps(ts_log) + "\n")
    except Exception as e:
        print(f"Error appending training data: {e}")

@app.route("/process-log", methods=["POST"])
def process_log():
    try:
        ts_log = request.get_json()
        if not ts_log:
            return jsonify({"error": "No JSON payload received"}), 400

        # Query the Model Service for a prediction.
        response = requests.post(MODEL_SERVICE_URL, json=ts_log)
        if response.status_code != 200:
            return jsonify({"error": "Model service error", "details": response.json()}), 500

        prediction = response.json().get("prediction", "no_change")
        print(f"Model prediction: {prediction}")

        # Scale the deployment if needed.
        if prediction in ["scale_up", "scale_down"]:
            replica_count = update_deployment_scale(prediction)
        else:
            replica_count = "unchanged"

        # Generate the AS3 payload based on the usecase.
        as3_payload = generate_as3_payload(ts_log, prediction, replica_count)
        print("Generated AS3 payload:")
        print(json.dumps(as3_payload, indent=2))

        # Update the AS3 ConfigMap so that F5 CIS pushes the new configuration to BIG-IP.
        update_as3_configmap(as3_payload)

        # Append processed log for future retraining.
        append_training_data(ts_log, prediction)

        return jsonify({"status": "success", "prediction": prediction, "as3": as3_payload})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)