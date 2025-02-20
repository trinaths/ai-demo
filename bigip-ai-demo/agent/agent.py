#!/usr/bin/env python3
import json
import os
import requests
from flask import Flask, request, jsonify
from kubernetes import client, config

app = Flask(__name__)

# Model Service URL
MODEL_SERVICE_URL = "http://localhost:5000/predict"

# Target deployment & namespace for scaling
TARGET_DEPLOYMENT = "sample-deployment"
TARGET_NAMESPACE = os.getenv("TARGET_NAMESPACE", "bigip-demo")

# Environment variable for dynamic service endpoints
TARGET_SERVICE = os.getenv("TARGET_SERVICE")
if not TARGET_SERVICE:
    raise ValueError("TARGET_SERVICE environment variable must be set to a valid Kubernetes service name.")

# Training data storage (shared PVC)
TRAINING_DATA_PATH = "/app/training_data/accumulated_ts_logs.jsonl"

# Load Kubernetes config
try:
    config.load_incluster_config()
except Exception:
    config.load_kube_config()

def get_dynamic_endpoints(service_name, namespace):
    """
    Query Kubernetes API to retrieve dynamic endpoints (pod IPs) for the target service.
    """
    v1 = client.CoreV1Api()
    endpoints = v1.read_namespaced_endpoints(service_name, namespace)
    addresses = []
    if endpoints.subsets:
        for subset in endpoints.subsets:
            if subset.addresses:
                for addr in subset.addresses:
                    addresses.append(addr.ip)
    return addresses

def update_deployment_scale(prediction):
    """
    Use Kubernetes API to update the replica count of the target deployment based on the prediction.
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

def generate_base_as3(tenant, timestamp, dynamic_endpoints):
    """
    Returns the base AS3 payload structure that is common across use cases.
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
    Consolidates AS3 payload creation using the usecase field.
    Updates the base payload with usecase-specific keys and values.
    
    For each usecase, the payload is updated as follows:
    
    - Usecase 1 (Crypto Offload):  
      Uses a HTTPS service configuration with a "crypto_pool" and clientSSL settings to offload crypto operations.
      
    - Usecase 2 (Traffic Steering):  
      Uses an HTTP service for steering traffic based on APM metrics.
      
    - Usecase 3 (SLA Enforcement):  
      Similar to usecase 2 with a different label, enforcing SLAs.
      
    - Usecase 4 (Routing Update):  
      Uses a HTTPS service with a "routing_pool" to update ingress/egress routing dynamically.
      
    - Usecase 5 (Auto-scale Services):  
      Uses an HTTP service (ASM) to update service configuration when scaling is needed.
      
    - Usecase 6 (Service Discovery):  
      Uses an HTTP service (ASM) with a pool remark indicating service discovery update.
      
    - Usecase 7 (Cluster Maintenance):  
      Uses an HTTP service (ASM) for cluster maintenance updates.
      
    - Usecase 8 (Multi-layer Security Enforcement):  
      Configures an AFM policy payload to block malicious traffic if the aggregated security index is high.
    """
    usecase = ts_log.get("usecase")
    tenant = ts_log.get("tenant", "Tenant_Default")
    timestamp = ts_log.get("timestamp", "")
    
    # Retrieve dynamic endpoints from the target service.
    dynamic_endpoints = get_dynamic_endpoints(TARGET_SERVICE, TARGET_NAMESPACE)
    if not dynamic_endpoints:
        raise RuntimeError(f"No endpoints found for service {TARGET_SERVICE} in namespace {TARGET_NAMESPACE}")
    
    # Create base AS3 payload.
    payload = generate_base_as3(tenant, timestamp, dynamic_endpoints)
    
    # Usecase-specific adjustments:
    if usecase == 1:
        # Usecase 1: Dynamic Crypto Offload
        payload["declaration"]["id"] = f"{tenant}-crypto-{timestamp}"
        payload["declaration"]["label"] = "Dynamic Crypto Offload"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTPS": {
                "class": "Service_HTTPS",
                "virtualAddresses": dynamic_endpoints,
                "pool": "crypto_pool",
                "sslProfileClient": "clientSSL"
            },
            "clientSSL": {
                "class": "SSL_Profile_Client",
                "context": "clients",
                "cert": "/Common/client.crt",
                "key": "/Common/client.key"
            },
            "crypto_pool": {
                "class": "Pool",
                "members": [{"servicePort": 443, "serverAddresses": dynamic_endpoints}],
                "remark": "Crypto offload applied based on high load"
            }
        })
    elif usecase == 2:
        # Usecase 2: Traffic Steering (APM)
        payload["declaration"]["id"] = f"{tenant}-traffic-{timestamp}"
        payload["declaration"]["label"] = "Traffic Steering Update"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTP": {
                "class": "Service_HTTP",
                "virtualAddresses": dynamic_endpoints,
                "pool": "apm_pool"
            },
            "apm_pool": {
                "class": "Pool",
                "members": [{"servicePort": 80, "serverAddresses": dynamic_endpoints}],
                "remark": "Traffic steered based on load"
            }
        })
    elif usecase == 3:
        # Usecase 3: SLA Enforcement (APM)
        payload["declaration"]["id"] = f"{tenant}-sla-{timestamp}"
        payload["declaration"]["label"] = "SLA Enforcement Update"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTP": {
                "class": "Service_HTTP",
                "virtualAddresses": dynamic_endpoints,
                "pool": "apm_pool"
            },
            "apm_pool": {
                "class": "Pool",
                "members": [{"servicePort": 80, "serverAddresses": dynamic_endpoints}],
                "remark": "SLA enforced based on connection performance"
            }
        })
    elif usecase == 4:
        # Usecase 4: Dynamic Routing Update (LTM/System)
        payload["declaration"]["id"] = f"{tenant}-routing-{timestamp}"
        payload["declaration"]["label"] = "Dynamic Routing Update"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTPS": {
                "class": "Service_HTTPS",
                "virtualAddresses": dynamic_endpoints,
                "pool": "routing_pool",
                "sslProfileClient": "clientSSL"
            },
            "clientSSL": {
                "class": "SSL_Profile_Client",
                "context": "clients",
                "cert": "/Common/client.crt",
                "key": "/Common/client.key"
            },
            "routing_pool": {
                "class": "Pool",
                "members": [{"servicePort": 443, "serverAddresses": dynamic_endpoints}],
                "remark": "Routing update applied for optimal ingress/egress"
            }
        })
    elif usecase == 5:
        # Usecase 5: Auto-scale Services (ASM)
        payload["declaration"]["id"] = f"{tenant}-autoscale-{timestamp}"
        payload["declaration"]["label"] = "Auto-scale Services Update"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTP": {
                "class": "Service_HTTP",
                "virtualAddresses": dynamic_endpoints,
                "pool": "asm_pool"
            },
            "asm_pool": {
                "class": "Pool",
                "members": [{"servicePort": 80, "serverAddresses": dynamic_endpoints}],
                "remark": "Auto-scale configuration applied based on demand"
            }
        })
    elif usecase == 6:
        # Usecase 6: Service Discovery & Orchestration (ASM)
        payload["declaration"]["id"] = f"{tenant}-service-discovery-{timestamp}"
        payload["declaration"]["label"] = "Service Discovery Update"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTP": {
                "class": "Service_HTTP",
                "virtualAddresses": dynamic_endpoints,
                "pool": "asm_pool"
            },
            "asm_pool": {
                "class": "Pool",
                "members": [{"servicePort": 80, "serverAddresses": dynamic_endpoints}],
                "remark": "Service discovery update applied"
            }
        })
    elif usecase == 7:
        # Usecase 7: Cluster Maintenance (ASM)
        payload["declaration"]["id"] = f"{tenant}-cluster-maintenance-{timestamp}"
        payload["declaration"]["label"] = "Cluster Maintenance Update"
        payload["declaration"]["Common"][tenant].update({
            "serviceHTTP": {
                "class": "Service_HTTP",
                "virtualAddresses": dynamic_endpoints,
                "pool": "asm_pool"
            },
            "asm_pool": {
                "class": "Pool",
                "members": [{"servicePort": 80, "serverAddresses": dynamic_endpoints}],
                "remark": "Cluster maintenance configuration applied"
            }
        })
    elif usecase == 8:
        # Usecase 8: Multi-layer Security Enforcement (AFM)
        payload["declaration"]["id"] = f"{tenant}-security-{timestamp}"
        payload["declaration"]["label"] = "Multi-layer Security Enforcement"
        payload["declaration"]["Common"][tenant].update({
            "afmPolicy": {
                "class": "AFM_Policy",
                "remark": "Security enforcement applied based on aggregated metrics",
                "enabled": True if ts_log.get("afmThreatScore", 0) > 0.7 else False
            }
        })
    else:
        payload = {"error": "No AS3 payload defined for this usecase"}
    
    return payload

def append_training_data(ts_log, prediction):
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

        response = requests.post(MODEL_SERVICE_URL, json=ts_log)
        if response.status_code != 200:
            return jsonify({"error": "Model service error", "details": response.json()}), 500

        prediction = response.json().get("prediction", "no_change")
        print(f"Model prediction: {prediction}")

        if prediction in ["scale_up", "scale_down"]:
            replica_count = update_deployment_scale(prediction)
        else:
            replica_count = "unchanged"

        as3_payload = generate_as3_payload(ts_log, prediction, replica_count)
        print("Generated AS3 payload:")
        print(json.dumps(as3_payload, indent=2))
        print("Simulated BIG-IP AS3 update completed.")

        append_training_data(ts_log, prediction)
        return jsonify({"status": "success", "prediction": prediction, "as3": as3_payload})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)