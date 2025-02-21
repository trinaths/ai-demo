#!/usr/bin/env python3
"""
agent.py

Agent Service that:
1. Receives synthetic TS logs via /process-log.
2. Forwards the log to the unified Model Service for a prediction.
3. Retrieves dynamic backend endpoints from the target Kubernetes Service.
4. Generates a usecase‑specific AS3 JSON declaration:
   • Uses a static virtual IP (per use case) for BIG‑IP virtualAddresses.
   • Uses dynamic backend endpoints (list of IPs) for pool members.
   • Uses the deployment name (from USECASE_DEPLOYMENT_MAP) as the application key.
5. Updates a Kubernetes ConfigMap named "as3-json-{usecase}" (with labels f5type: virtual-server and as3: "true") with the AS3 declaration.
6. Scales the target deployment based on the prediction.
7. Appends the processed TS log for future retraining.
"""

import json
import os
import requests
from flask import Flask, request, jsonify
from kubernetes import client, config
import logging
import urllib3

# Disable warnings for unverified HTTPS requests (for demo purposes).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
TRAINING_DATA_PATH = "/app/models/synthetic_ts_logs.jsonl"

# Mapping of use cases (1-8) to deployments and services.
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

# Mapping of use case to static virtual IP addresses.
USECASE_VIRTUAL_IPS = {
    1: "192.168.0.101",
    2: "192.168.0.102",
    3: "192.168.0.103",
    4: "192.168.0.104",
    5: "192.168.0.105",
    6: "192.168.0.106",
    7: "192.168.0.107",
    8: "192.168.0.108"
}

# Labels to apply to AS3 ConfigMaps.
AS3_CONFIGMAP_LABELS = {
    "f5type": "virtual-server",
    "as3": "true"
}

# ------------------------------------------------------------------------------
# Kubernetes Helper Functions
# ------------------------------------------------------------------------------
def get_dynamic_endpoints(service_name, namespace):
    """
    Retrieve backend endpoints (IP addresses) from the given Kubernetes service.
    Returns a list of IPs (without ports) for pool members.
    """
    v1 = client.CoreV1Api()
    try:
        endpoints_obj = v1.read_namespaced_endpoints(service_name, namespace)
        addresses = []
        if endpoints_obj.subsets:
            for subset in endpoints_obj.subsets:
                # We assume the port is defined but only need the IPs for pool members.
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

# ------------------------------------------------------------------------------
# AS3 JSON Generation Functions for Each Use Case.
# ------------------------------------------------------------------------------
def get_as3_payload_for_usecase(usecase, tenant, timestamp, dynamic_endpoints, prediction):
    """
    Build a usecase-specific AS3 declaration.
    Uses the deployment name (from USECASE_DEPLOYMENT_MAP) as the application key.
    For virtualAddresses, a static IP (per use case) is used.
    For pool members, the dynamic endpoints (list of IPs) are used.
    """
    app_key = USECASE_DEPLOYMENT_MAP[usecase]["deployment"]
    if usecase == 1:
        # Use Case 1: Dynamic Crypto Offloading.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "Dynamic Crypto Offloading",
                "remark": "HTTPS with round-robin pool for SSL/TLS offloading",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTPS",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[1]],
                            "pool": "ssl_offload_pool",
                            "serverTLS": { "bigip": "/Common/clientssl" }
                        },
                        "ssl_offload_pool": {
                            "class": "Pool",
                            "loadBalancingMode": "round-robin",
                            "monitors": ["http"],
                            "members": [{
                                "servicePort": 8080,
                                "shareNodes": True,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"Crypto offloading pool; prediction: {prediction}"
                        }
                    }
                }
            }
        }
    elif usecase == 2:
        # Use Case 2: Traffic Steering via AI Insights.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "Traffic Steering via AI Insights",
                "remark": "Routing with least-connections load balancing",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTP",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[2]],
                            "pool": "traffic_steering_pool",
                            "loadBalancingMode": "least-connections"
                        },
                        "traffic_steering_pool": {
                            "class": "Pool",
                            "members": [{
                                "servicePort": 80,
                                "shareNodes": True,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"Traffic steering; prediction: {prediction}"
                        }
                    }
                }
            }
        }
    elif usecase == 3:
        # Use Case 3: SLA Enforcement.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "SLA Enforcement",
                "remark": "SLA enforcement with HTTP monitor",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTP",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[3]],
                            "pool": "sla_enforcement_pool",
                            "monitors": ["http"]
                        },
                        "sla_enforcement_pool": {
                            "class": "Pool",
                            "members": [{
                                "servicePort": 80,
                                "shareNodes": True,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"SLA enforcement; prediction: {prediction}"
                        }
                    }
                }
            }
        }
    elif usecase == 4:
        # Use Case 4: Multi-Cluster Ingress/Egress Routing.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "Multi-Cluster Ingress and Egress Routing",
                "remark": "Routing traffic across clusters",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTPS",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[4]],
                            "pool": "multicluster_pool"
                        },
                        "multicluster_pool": {
                            "class": "Pool",
                            "members": [{
                                "servicePort": 443,
                                "shareNodes": True,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"Routing across clusters; prediction: {prediction}"
                        }
                    }
                }
            }
        }
    elif usecase == 5:
        # Use Case 5: Auto-scale Services.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "Auto-scale Services",
                "remark": "Auto-scaling by adjusting connection limits",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTPS",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[5]],
                            "pool": "autoscale_pool"
                        },
                        "autoscale_pool": {
                            "class": "Pool",
                            "members": [{
                                "servicePort": 443,
                                "shareNodes": True,
                                "connectionLimit": 5000,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"Auto-scale configured; prediction: {prediction}"
                        }
                    }
                }
            }
        }
    elif usecase == 6:
        # Use Case 6: Service Discovery & Orchestration.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "Service Discovery and Orchestration",
                "remark": "Dynamic pool member update for service discovery",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTP",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[6]],
                            "pool": "service_discovery_pool"
                        },
                        "service_discovery_pool": {
                            "class": "Pool",
                            "members": [{
                                "servicePort": 80,
                                "shareNodes": True,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"Service discovery updated; prediction: {prediction}"
                        }
                    }
                }
            }
        }
    elif usecase == 7:
        # Use Case 7: Service Resilience & Cluster Maintenance.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "Service Resilience and Cluster Maintenance",
                "remark": "Ensuring minimum active pool members for resilience",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTPS",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[7]],
                            "pool": "resilience_pool",
                            "monitors": ["http"]
                        },
                        "resilience_pool": {
                            "class": "Pool",
                            "members": [{
                                "servicePort": 80,
                                "shareNodes": True,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"Resilience set; prediction: {prediction}",
                            "minimumMembersActive": 2
                        }
                    }
                }
            }
        }
    elif usecase == 8:
        # Use Case 8: Multi-Layer Security Enforcement.
        return {
            "class": "AS3",
            "action": "deploy",
            "persist": True,
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": f"{tenant}-{timestamp}",
                "label": "Multi-Layer Security Enforcement",
                "remark": "Enforcing security policies via WAF and Firewall updates",
                app_key: {
                    "class": "Tenant",
                    app_key: {
                        "class": "Application",
                        "template": "generic",
                        app_key: {
                            "class": "Service_HTTPS",
                            "virtualAddresses": [USECASE_VIRTUAL_IPS[8]],
                            "pool": "security_pool",                            
                             "monitors": ["https"],
                            "policyWAF": {
                                "bigip": "/Common/demo-waf-policy"
                            }
                        },
                        "security_pool": {
                            "class": "Pool",
                            "members": [{
                                "servicePort": 443,
                                "shareNodes": True,
                                "connectionLimit": 1000,
                                "serverAddresses": dynamic_endpoints
                            }],
                            "remark": f"Security enforcement; prediction: {prediction}",
                        }
                    }
                }
            }
        }
    else:
        return {"error": "No AS3 payload defined for this usecase"}

# ------------------------------------------------------------------------------
# ConfigMap Update Function.
# ------------------------------------------------------------------------------
def update_as3_configmap(as3_payload, usecase):
    """
    Update the AS3 ConfigMap for the given usecase.
    The ConfigMap name is "as3-json-{usecase}" with the proper labels.
    """
    config_map_name = f"app-{USECASE_DEPLOYMENT_MAP[usecase]["deployment"]}"
    v1 = client.CoreV1Api()
    patch_body = {
        "metadata": {
            "labels": AS3_CONFIGMAP_LABELS
        },
        "data": {
            "template": json.dumps(as3_payload, indent=2)
        }
    }
    try:
        try:
            v1.patch_namespaced_config_map(name=config_map_name, namespace=TARGET_NAMESPACE, body=patch_body)
            logging.info(f"ConfigMap '{config_map_name}' updated with new AS3 declaration.")
        except Exception as patch_err:
            logging.warning(f"ConfigMap '{config_map_name}' not found; creating new one.")
            config_map = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=config_map_name, namespace=TARGET_NAMESPACE, labels=AS3_CONFIGMAP_LABELS),
                data={"template": json.dumps(as3_payload, indent=2)}
            )
            v1.create_namespaced_config_map(namespace=TARGET_NAMESPACE, body=config_map)
            logging.info(f"ConfigMap '{config_map_name}' created with new AS3 declaration.")
    except Exception as e:
        logging.error(f"Error updating ConfigMap '{config_map_name}': {e}")

# ------------------------------------------------------------------------------
# Training Data Append Function.
# ------------------------------------------------------------------------------
def append_training_data(ts_log, prediction):
    ts_log["predicted_label"] = prediction
    try:
        os.makedirs(os.path.dirname(TRAINING_DATA_PATH), exist_ok=True)
        with open(TRAINING_DATA_PATH, "a") as f:
            f.write(json.dumps(ts_log) + "\n")
        logging.debug("Training data appended successfully.")
    except Exception as e:
        logging.error(f"Error appending training data: {e}")

# ------------------------------------------------------------------------------
# Agent Service Endpoint.
# ------------------------------------------------------------------------------
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

        # Forward the TS log to the Model Service for prediction.
        logging.info(f"Querying Model Service at {MODEL_SERVICE_URL} ...")
        response = requests.post(MODEL_SERVICE_URL, json=ts_log, timeout=5)
        logging.debug(f"Model Service response status: {response.status_code}")
        if response.status_code != 200:
            error_msg = f"Model service error: {response.text}"
            logging.error(error_msg)
            return jsonify({"error": "Model service error", "details": response.text}), 500

        prediction = response.json().get("prediction", "no_change")
        logging.info(f"Model prediction: {prediction}")

        # Scale the target deployment if prediction indicates scaling.
        if prediction in ["scale_up", "scale_down"]:
            logging.debug(f"Scaling deployment '{deployment_name}' based on prediction '{prediction}'")
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

        # Build the usecase-specific AS3 payload.
        as3_payload = get_as3_payload_for_usecase(
            usecase,
            ts_log.get("tenant", "Tenant_Default"),
            ts_log.get("timestamp", ""),
            dynamic_endpoints,
            prediction
        )
        logging.info("Generated AS3 payload:\n" + json.dumps(as3_payload, indent=2))
        update_as3_configmap(as3_payload, usecase)

        # Append the TS log for future retraining.
        append_training_data(ts_log, prediction)
        logging.debug("Finished processing TS log; sending response.")

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