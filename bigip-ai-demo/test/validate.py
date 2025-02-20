#!/usr/bin/env python3
"""
validator.py

A unified script that generates synthetic TS logs for a given usecase and module,
and sends the log to the Agent Service.
Usage: python validator.py <usecase_number(1-8)> <module>
Valid modules: LTM, APM, ASM, SYSTEM, AFM.
This version retrieves the Agent Service endpoint dynamically from the cluster.
"""

import json
import random
import sys
import requests
from datetime import datetime
from kubernetes import client, config

def load_k8s_config():
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()

def get_nodeport_endpoint(service_name, namespace):
    """
    Retrieve the external endpoint for a NodePort service.
    Returns a list of endpoints in the format "NODE_IP:NodePort".
    """
    load_k8s_config()
    v1 = client.CoreV1Api()
    service = v1.read_namespaced_service(service_name, namespace)
    node_port = service.spec.ports[0].node_port  # Assumes first port is used.
    # Retrieve all nodes with ExternalIP addresses.
    nodes = v1.list_node()
    endpoints = []
    for node in nodes.items:
        for address in node.status.addresses:
            if address.type == "ExternalIP":
                endpoints.append(f"{address.address}:{node_port}")
    return endpoints

# Dynamically compute the Agent Service endpoint.
NAMESPACE = "bigip-demo"
agent_endpoints = get_nodeport_endpoint("agent-service", NAMESPACE)
#if not agent_endpoints:
#    print("Error: Could not retrieve Agent Service endpoints from Kubernetes.")
#    sys.exit(1)
AGENT_SERVICE_URL = f"http://10.4.1.115:30001/process-log"

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(1))

def generate_log(usecase, module):
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "deviceName": f"bigip-{usecase}",
        "tenant": random.choice(["Common", "Tenant_A", "Tenant_B"]),
        "cluster": NAMESPACE,
        "usecase": usecase,
        "module": module,
        "eventType": module.lower() + "_request"
    }
    if module == "LTM":
        log.update({
            "virtualServerName": "/Common/app.app/app_vs",
            "poolName": "/Common/app.app/app_pool",
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "cryptoLoad": round(random.uniform(0.0, 1.0), 3),
            "latency": round(random.uniform(0.01, 0.3), 3),
            "jitter": round(random.uniform(0.0, 0.05), 3),
            "packetLoss": round(random.uniform(0.0, 0.05), 3)
        })
    if module == "APM":
        log["system.connectionsPerformance"] = round(random.uniform(0.0, 1.0), 3)
    if module == "ASM":
        log.update({
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "asmAttackSignatures": random.choice(["SQL_Injection", "XSS", "None"])
        })
    if module == "SYSTEM":
        log.update({
            "cpu": round(random.uniform(0.0, 100.0), 1),
            "memory": round(random.uniform(0.0, 100.0), 1),
            "tmmCpu": round(random.uniform(0.0, 1.0), 3),
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "system.connectionsPerformance": round(random.uniform(0.0, 1.0), 3)
        })
    if module == "AFM":
        log.update({
            "acl_policy_name": "/Common/app",
            "acl_policy_type": "Enforced",
            "acl_rule_name": "ping",
            "action": random.choice(["Reject", "Allow"]),
            "hostname": "afm-host",
            "bigip_mgmt_ip": "10.0.1.100",
            "context_name": "/Common/app.app/app_vs",
            "context_type": "Virtual Server",
            "date_time": datetime.utcnow().strftime("%b %d %Y %H:%M:%S"),
            "dest_fqdn": "unknown",
            "dest_ip": random_ip(),
            "dst_geo": "Unknown",
            "dest_port": str(random.randint(80, 443)),
            "device_product": "Advanced Firewall Module",
            "device_vendor": "F5",
            "device_version": "14.0.0",
            "drop_reason": "Policy",
            "errdefs_msgno": "23003137",
            "errdefs_msg_name": "Network Event",
            "flow_id": "0000000000000000",
            "ip_protocol": "TCP",
            "severity": "8",
            "partition_name": "Common",
            "route_domain": "0",
            "vlan": "/Common/external",
            "application": "app.app",
            "telemetryEventCategory": "AFM",
            "afmThreatScore": round(random.uniform(0.0, 1.0), 3),
            "accessAnomaly": round(random.uniform(0.0, 1.0), 3),
            "asmAttackIndicator": 1 if random.choice(["SQL_Injection", "XSS", "None"]) != "None" else 0
        })
    # Add common network fields.
    log.update({
        "clientAddress": random_ip(),
        "clientPort": random.randint(1024, 65535),
        "serverAddress": random_ip(),
        "serverPort": str(random.randint(80, 443)),
        "protocol": random.choice(["HTTP", "HTTPS", "TCP"]),
        "httpMethod": random.choice(["GET", "POST"]),
        "httpUri": random.choice(["/", "/login"]),
        "httpStatus": random.choice([200, 404, 500]),
        "requestBytes": random.randint(500, 2000),
        "responseBytes": random.randint(1000, 5000)
    })
    return log

def main():
    if len(sys.argv) != 3:
        print("Usage: python validator.py <usecase_number(1-8)> <module>")
        sys.exit(1)
    try:
        usecase = int(sys.argv[1])
        module = sys.argv[2]
        valid_modules = ["LTM", "APM", "ASM", "SYSTEM", "AFM"]
        if usecase < 1 or usecase > 8:
            raise ValueError("Usecase number must be between 1 and 8.")
        if module not in valid_modules:
            raise ValueError(f"Module must be one of: {', '.join(valid_modules)}")
    except Exception as e:
        print("Invalid arguments:", e)
        sys.exit(1)
    
    log = generate_log(usecase, module)
    print(f"Generated TS Log for Usecase {usecase} ({module}):")
    print(json.dumps(log, indent=2))
    
    try:
        response = requests.post(AGENT_SERVICE_URL, json=log)
        print("Response from Agent Service:")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print("Error sending TS log:", e)

if __name__ == "__main__":
    main()