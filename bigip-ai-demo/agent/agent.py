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
   • For each use case the AS3 JSON is built uniquely to simulate various configuration updates.
5. Updates (or creates) a Kubernetes ConfigMap named "as3-json-{usecase}" with labels 
   (f5type: virtual-server, as3: "true") so that F5 CIS pushes the configuration.
6. Scales the target deployment based on the prediction.
7. Appends the processed TS log for future retraining.
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

def get_dynamic_endpoints(service_name, namespace):
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
    8: {"deployment": "traffic-monitor", "service": "traffic-monitor-service"}
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

# ------------------------------------------------------------------------------
# AS3 JSON Generation Functions for Each Use Case.
# ------------------------------------------------------------------------------
def get_as3_payload_for_usecase(usecase, tenant, timestamp, dynamic_endpoints, prediction):
    """
    Build a usecase-specific AS3 declaration.
    For virtualAddresses, a static IP is used (per use case).
    For pool members, dynamic backend endpoints (list of IPs) are used.
    """
    tenantName = f"{tenant}_{usecase}"
    if usecase == 1:
        # Use Case 1: Dynamic Crypto Offloading.
        # This configuration sets up an HTTPS virtual server (acme_https_vs) that terminates SSL/TLS
        # using a TLS_Server object (acmeTLS) and routes decrypted traffic to a backend pool (acme_http_pool).
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
                tenantName: {
                    "class": "Application",
                    "template": "generic",
                    "acme_https_vs": {
                        "class": "Service_HTTPS",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[1]],
                        "pool": "acme_http_pool",
                        "serverTLS": "acmeTLS"
                    },
                    "acme_http_pool": {
                        "class": "Pool",
                        "loadBalancingMode": "round-robin",
                        "monitors": ["http"],
                        "members": [{
                            "servicePort": 8080,
                            "shareNodes": True,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"Crypto offloading pool; prediction: {prediction}"
                    },
                    "acmeTLS": {
                        "class": "TLS_Server",
                        "certificates": [{
                            "certificate": "acmeCert"
                        }]
                    },
                    "acmeCert": {
                        "class": "Certificate",
                        "remark": "For demo purposes only; replace with your own certificate",
                        "certificate": "-----BEGIN CERTIFICATE-----\nMIIDSDCCAjCgAwIBAgIEFPdzHjANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTESMBAGA1UEAxMJQWNtZSBDb3JwMRwwGgYJKoZIhvcNAQkBFg10ZXN0QGFjbWUuY29t\n-----END CERTIFICATE-----",
                        "privateKey": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDJY9CAD48s0icyWV8zzyp1lruhK5H1IbowZNZ0HafvivGK76HC2Oa22Pw2fYqRM9U8SMmQBpfWgT6CxlOK9lzVTCWQOWaP0DHnRGRWpdeHjh59yTDLwg4xqxWlkfnGdk0fQ/SXccravUClEvyXQimM/0MW8dkOKNJ2Q6pjwIqcP/xNuMuJS8mv0K8G+d+0KAhp8YDKFFTYva7mK5xrUuLj7Yd/o2Jm24r2/BtQfMfdz3nrtUBwZTml6+g53UsCnFCyFLdkcXMmHI83lUOcq3K1R8LxfHm9Ny5ZtdM19FCOvL3Y0LjKXlGeytEZZjufb9Lul3XqCtbPNkifLn7HKiK3AgMBAAEC\n-----END PRIVATE KEY-----"
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
                tenantName : {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTP": {
                        "class": "Service_HTTP",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[2]],
                        "pool": "traffic_steering_pool",
                        "loadBalancingMode": "least-connections"
                    },
                    "traffic_steering_pool": {
                        "class": "Pool",
                        "members": [{
                            "servicePort": 80,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"Traffic steering; prediction: {prediction}"
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
                tenantName: {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTP": {
                        "class": "Service_HTTP",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[3]],
                        "pool": "sla_enforcement_pool",
                        "monitor": "/Common/http"
                    },
                    "sla_enforcement_pool": {
                        "class": "Pool",
                        "members": [{
                            "servicePort": 80,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"SLA enforcement; prediction: {prediction}"
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
                "label": "Multi-Cluster Ingress/Egress Routing",
                "remark": "Routing traffic across clusters",
                tenantName: {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTPS": {
                        "class": "Service_HTTPS",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[4]],
                        "pool": "multicluster_pool"
                    },
                    "multicluster_pool": {
                        "class": "Pool",
                        "members": [{
                            "servicePort": 443,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"Routing across clusters; prediction: {prediction}"
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
                tenantName: {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTPS": {
                        "class": "Service_HTTPS",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[5]],
                        "pool": "autoscale_pool"
                    },
                    "autoscale_pool": {
                        "class": "Pool",
                        "members": [{
                            "servicePort": 443,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"Auto-scale configured; prediction: {prediction}",
                        "connectionLimit": 5000
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
                "label": "Service Discovery & Orchestration",
                "remark": "Dynamic pool member update for service discovery",
                tenantName: {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTP": {
                        "class": "Service_HTTP",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[6]],
                        "pool": "service_discovery_pool"
                    },
                    "service_discovery_pool": {
                        "class": "Pool",
                        "members": [{
                            "servicePort": 80,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"Service discovery updated; prediction: {prediction}"
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
                "label": "Service Resilience & Cluster Maintenance",
                "remark": "Ensuring minimum active pool members for resilience",
                tenantName: {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTP": {
                        "class": "Service_HTTP",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[7]],
                        "pool": "resilience_pool",
                        "monitor": "/Common/http"
                    },
                    "resilience_pool": {
                        "class": "Pool",
                        "members": [{
                            "servicePort": 80,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"Resilience set; prediction: {prediction}",
                        "minActiveMembers": 2
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
                tenantName: {
                    "class": "Application",
                    "template": "generic",
                    "serviceHTTPS": {
                        "class": "Service_HTTPS",
                        "virtualAddresses": [USECASE_VIRTUAL_IPS[8]],
                        "pool": "security_pool"
                    },
                    "security_pool": {
                        "class": "Pool",
                        "members": [{
                            "servicePort": 443,
                            "serverAddresses": dynamic_endpoints
                        }],
                        "remark": f"Security enforcement; prediction: {prediction}",
                        "connectionLimit": 1000,
                        "monitors": ["http"]
                    },
                    "wafPolicy": {
                        "class": "WAF_Policy",
                        "policy": "/Common/waf_policy",
                        "alertOnly": False,
                        "remark": "Dynamic WAF policy for security"
                    },
                    "firewallPolicy": {
                        "class": "Firewall_Rule_List",
                        "remark": "Dynamic Firewall policy for security",
                        "rules": [
                            {
                                "name": "block_tcp",
                                "action": "reject",
                                "protocol": "tcp",
                                "loggingEnabled": True
                            },
                            {
                                "name": "block_udp",
                                "action": "reject",
                                "protocol": "udp",
                                "loggingEnabled": True
                            }
                        ]
                    }
                }
            }
        }
    else:
        return {"error": "No AS3 payload defined for this usecase"}

# ------------------------------------------------------------------------------
# Kubernetes ConfigMap Update Functions.
# ------------------------------------------------------------------------------
def update_as3_configmap(as3_payload, usecase):
    config_map_name = f"as3-json-{usecase}"
    v1 = client.CoreV1Api()
    patch_body = {
        "metadata": {
            "labels": {
                "f5type": "virtual-server",
                "as3": "true"
            }
        },
        "data": {
            "template": json.dumps(as3_payload, indent=2)
        }
    }
    try:
        logging.debug(f"Patching ConfigMap '{config_map_name}' with: {patch_body}")
        v1.patch_namespaced_config_map(name=config_map_name, namespace=TARGET_NAMESPACE, body=patch_body)
        logging.info(f"ConfigMap '{config_map_name}' updated successfully.")
    except Exception as e:
        logging.error(f"Error patching ConfigMap '{config_map_name}': {e}. Attempting to create it.")
        config_map_body = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": config_map_name,
                "namespace": TARGET_NAMESPACE,
                "labels": {
                    "f5type": "virtual-server",
                    "as3": "true"
                }
            },
            "data": {
                "template": json.dumps(as3_payload, indent=2)
            }
        }
        try:
            v1.create_namespaced_config_map(namespace=TARGET_NAMESPACE, body=config_map_body)
            logging.info(f"ConfigMap '{config_map_name}' created successfully.")
        except Exception as create_err:
            logging.error(f"Failed to create ConfigMap '{config_map_name}': {create_err}")

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

        # Query the Model Service for prediction.
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