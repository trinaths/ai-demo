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
TARGET_NAMESPACE = "default"

# Environment variable for dynamic service name to get endpoints.
TARGET_SERVICE = os.getenv("TARGET_SERVICE")  # This must be set to a valid service name.
if not TARGET_SERVICE:
    raise ValueError("TARGET_SERVICE environment variable must be set to a valid Kubernetes service name.")

# Path for accumulating training data (shared via PVC)
TRAINING_DATA_PATH = "/app/training_data/accumulated_ts_logs.jsonl"

try:
    config.load_incluster_config()
except Exception:
    config.load_kube_config()

def get_dynamic_endpoints(service_name, namespace):
    """
    Retrieve a list of IP addresses for the given Kubernetes service.
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

def generate_as3_payload(ts_log, prediction, replica_count):
    usecase = ts_log.get("usecase")
    tenant = ts_log.get("tenant", "Tenant_Default")
    timestamp = ts_log.get("timestamp", "")
    # Query Kubernetes to get dynamic endpoints from the target service.
    dynamic_endpoints = get_dynamic_endpoints(TARGET_SERVICE, TARGET_NAMESPACE)
    if not dynamic_endpoints:
        raise RuntimeError(f"No endpoints found for service {TARGET_SERVICE} in namespace {TARGET_NAMESPACE}")

    # Example: Usecase-specific payloads driven by the "usecase" field.
    if usecase == 1:
        # Usecase 1: Dynamic Crypto Offload.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-crypto-{timestamp}",
                "label": "Dynamic Crypto Offload",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
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
                    }
                }
            }
        }
    elif usecase == 2:
        # Usecase 2: Traffic Steering (APM).
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-traffic-{timestamp}",
                "label": "Traffic Steering Update",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
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
                    }
                }
            }
        }
    elif usecase == 3:
        # Usecase 3: SLA Enforcement (APM).
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-sla-{timestamp}",
                "label": "SLA Enforcement Update",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
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
                    }
                }
            }
        }
    elif usecase == 4:
        # Usecase 4: Ingress/Egress Routing (LTM/System).
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-routing-{timestamp}",
                "label": "Dynamic Routing Update",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
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
                    }
                }
            }
        }
    elif usecase == 5:
        # Usecase 5: Auto-scale Services (ASM).
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-autoscale-{timestamp}",
                "label": "Auto-scale Services Update",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
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
                    }
                }
            }
        }
    elif usecase == 6:
        # Usecase 6: Service Discovery & Orchestration (ASM).
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-service-discovery-{timestamp}",
                "label": "Service Discovery Update",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
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
                    }
                }
            }
        }
    elif usecase == 7:
        # Usecase 7: Cluster Maintenance (ASM).
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-cluster-maintenance-{timestamp}",
                "label": "Cluster Maintenance Update",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
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
                    }
                }
            }
        }
    elif usecase == 8:
        # Usecase 8: Multi-layer Security Enforcement (AFM).
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-security-{timestamp}",
                "label": "Multi-layer Security Enforcement",
                "Common": {
                    "class": "Tenant",
                    tenant: {
                        "class": "Application",
                        "template": "generic",
                        "afmPolicy": {
                            "class": "AFM_Policy",
                            "remark": "Security enforcement applied based on aggregated metrics",
                            "enabled": True if ts_log.get("afmThreatScore", 0) > 0.7 else False
                        }
                    }
                }
            }
        }
    else:
        return {"error": "No AS3 payload defined for this usecase"}

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