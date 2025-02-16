import json
import os
import pandas as pd
import numpy as np
import requests
from flask import Flask, request, jsonify
from sklearn.ensemble import RandomForestClassifier
import joblib
from kubernetes import client, config

try:
    from stable_baselines3 import PPO
    import gym
    from gym import spaces
    stable_baselines_available = True
except ImportError:
    stable_baselines_available = False
    print("⚠️ Warning: stable_baselines3 is not installed. RL models will not be trained.")

# Load Kubernetes configuration
config.load_incluster_config()
v1 = client.CoreV1Api()

# Define AI use cases
use_case_types = {
    "ssl_offloading": "supervised",
    "traffic_steering_sla": "reinforcement",
    "ingress_egress_routing": "reinforcement",
    "auto_scaling_service_discovery": "supervised",
    "cluster_resilience": "reinforcement",
    "performance_optimization": "supervised",
    "dynamic_traffic_steering": "reinforcement"
}

# Flask app to serve AI-powered decisions
app = Flask(__name__)

# Function to get live Kubernetes pod IPs
def get_pod_ips(namespace, label_selector):
    pod_list = v1.list_namespaced_pod(namespace, label_selector=label_selector)
    return [pod.status.pod_ip for pod in pod_list.items if pod.status.pod_ip]

# Function to update AS3 dynamically
def update_as3(as3_config):
    BIGIP_URL = "https://<BIG-IP>/mgmt/shared/appsvcs/declare"
    BIGIP_USERNAME = "admin"
    BIGIP_PASSWORD = "password"
    headers = {"Content-Type": "application/json"}
    response = requests.post(
        BIGIP_URL, json=as3_config, auth=(BIGIP_USERNAME, BIGIP_PASSWORD), headers=headers, verify=False
    )
    return response.status_code, response.json()

# Load trained models
trained_models = {}
for use_case, model_type in use_case_types.items():
    model_filename = f"{use_case}_model.pkl" if model_type == "supervised" else f"{use_case}_rl_model.zip"
    if os.path.exists(model_filename):
        if model_type == "supervised":
            trained_models[use_case] = joblib.load(model_filename)
        elif stable_baselines_available:
            trained_models[use_case] = PPO.load(model_filename)
        print(f"✅ Loaded model: {model_filename}")
    else:
        print(f"⚠️ Warning: Model file {model_filename} not found. Skipping.")

# Function to generate AS3 JSON per use case
def generate_as3_config(use_case, pod_ips):
    as3_templates = {
        "ssl_offloading": {
            "class": "AS3",
            "declaration": {
                "class": "ADC",
                "SSL_Offloading_Tenant": {
                    "class": "Tenant",
                    "SSL_Offloading_App": {
                        "class": "Application",
                        "service": {
                            "class": "Service_HTTPS",
                            "virtualAddresses": ["10.4.1.250"],
                            "virtualPort": 443,
                            "profileTLS": {"clientTLS": "clientssl", "serverTLS": "serverssl"},
                            "pool": "SSL_Offloading_Pool"
                        },
                        "SSL_Offloading_Pool": {
                            "class": "Pool",
                            "monitors": ["https"],
                            "members": [{"servicePort": 8443, "serverAddresses": pod_ips}]
                        }
                    }
                }
            }
        },
        "traffic_steering_sla": {
            "class": "AS3",
            "declaration": {
                "class": "ADC",
                "Traffic_Steering_Tenant": {
                    "class": "Tenant",
                    "Traffic_Steering_App": {
                        "class": "Application",
                        "service": {
                            "class": "Service_HTTP",
                            "virtualAddresses": ["10.4.1.251"],
                            "virtualPort": 80,
                            "pool": "Traffic_Steering_Pool"
                        },
                        "Traffic_Steering_Pool": {
                            "class": "Pool",
                            "monitors": ["http"],
                            "members": [{"servicePort": 8080, "serverAddresses": pod_ips}]
                        }
                    }
                }
            }
        },
        "auto_scaling_service_discovery": {
            "class": "AS3",
            "declaration": {
                "class": "ADC",
                "Auto_Scaling_Tenant": {
                    "class": "Tenant",
                    "Auto_Scaling_App": {
                        "class": "Application",
                        "service": {
                            "class": "Service_HTTP",
                            "virtualAddresses": ["10.4.1.252"],
                            "virtualPort": 80,
                            "pool": "Auto_Scaling_Pool"
                        },
                        "Auto_Scaling_Pool": {
                            "class": "Pool",
                            "monitors": ["http"],
                            "members": [{"servicePort": 8080, "serverAddresses": pod_ips}]
                        }
                    }
                }
            }
        },
        "cluster_resilience": {
            "class": "AS3",
            "declaration": {
                "class": "ADC",
                "Cluster_Resilience_Tenant": {
                    "class": "Tenant",
                    "Cluster_Resilience_App": {
                        "class": "Application",
                        "service": {
                            "class": "Service_HTTP",
                            "virtualAddresses": ["10.4.1.253"],
                            "virtualPort": 80,
                            "pool": "Cluster_Resilience_Pool"
                        },
                        "Cluster_Resilience_Pool": {
                            "class": "Pool",
                            "monitors": ["http"],
                            "members": [{"servicePort": 8080, "serverAddresses": pod_ips}]
                        }
                    }
                }
            }
        }
    }
    return as3_templates.get(use_case, {})

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    use_case = data.get("use_case")
    ts_log = data.get("ts_log")
    namespace = "bigip-ai"
    label_selector = "app=backend-service"

    if use_case not in trained_models:
        return jsonify({"error": "Invalid use case or model not loaded"}), 400

    model = trained_models[use_case]
    features = np.array([
        ts_log.get("system", {}).get("cpu", 50),
        ts_log.get("system", {}).get("memory", 50),
        ts_log.get("traffic", {}).get("throughput", 1000),
        ts_log.get("connections", {}).get("active", 5000)
    ])
    
    if use_case_types[use_case] == "supervised":
        prediction = model.predict(features.reshape(1, -1))[0]
    else:
        action, _ = model.predict(features)
        prediction = int(action)

    pod_ips = get_pod_ips(namespace, label_selector)
    as3_updates = generate_as3_config(use_case, pod_ips)
    update_as3(as3_updates)

    return jsonify({"use_case": use_case, "prediction": prediction, "updated_pods": pod_ips})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)