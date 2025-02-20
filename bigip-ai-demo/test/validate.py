#!/usr/bin/env python3
"""
validator.py

A script that generates synthetic TS logs for all 8 use cases 
and 5 modules (LTM, APM, ASM, SYSTEM, AFM) and sends them to 
the Agent Service in one execution.

Usage:
  python validator.py
"""

import json
import random
import sys
import time
import requests
from datetime import datetime

# Static Agent Service URL
AGENT_SERVICE_URL = "http://10.4.1.115:30001/process-log"

# Configuration
RETRY_LIMIT = 3  # Max retries for failed requests
TIME_GAP = 5  # Time delay (seconds) between each request

# Valid use cases and modules
USECASES = range(1, 9)
MODULES = ["LTM", "APM", "ASM", "SYSTEM", "AFM"]


def random_ip():
    """Generate a random IP address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def generate_log(usecase, module):
    """Generate a synthetic log entry based on the use case and module."""
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "deviceName": f"bigip-{usecase}",
        "tenant": random.choice(["Common", "Tenant_A", "Tenant_B"]),
        "cluster": "bigip-demo",
        "usecase": usecase,
        "module": module,
        "eventType": module.lower() + "_request",
        "clientAddress": random_ip(),
        "clientPort": random.randint(1024, 65535),
        "serverAddress": random_ip(),
        "serverPort": str(random.randint(80, 443)),
        "protocol": random.choice(["HTTP", "HTTPS", "TCP"]),
        "httpMethod": random.choice(["GET", "POST"]),
        "httpUri": random.choice(["/", "/login"]),
        "httpStatus": random.choice([200, 404, 500]),
        "requestBytes": random.randint(500, 2000),
        "responseBytes": random.randint(1000, 5000),
    }

    # Module-specific attributes
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
    elif module == "APM":
        log["system.connectionsPerformance"] = round(random.uniform(0.0, 1.0), 3)
    elif module == "ASM":
        log.update({
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "asmAttackSignatures": random.choice(["SQL_Injection", "XSS", "None"])
        })
    elif module == "SYSTEM":
        log.update({
            "cpu": round(random.uniform(0.0, 100.0), 1),
            "memory": round(random.uniform(0.0, 100.0), 1),
            "tmmCpu": round(random.uniform(0.0, 1.0), 3),
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "system.connectionsPerformance": round(random.uniform(0.0, 1.0), 3)
        })
    elif module == "AFM":
        log.update({
            "acl_policy_name": "/Common/app",
            "acl_policy_type": "Enforced",
            "acl_rule_name": "ping",
            "action": random.choice(["Reject", "Allow"]),
            "hostname": "afm-host",
            "bigip_mgmt_ip": "10.0.1.100",
            "context_name": "/Common/app.app/app_vs",
            "context_type": "Virtual Server",
            "dest_fqdn": "unknown",
            "dest_ip": random_ip(),
            "dst_geo": "Unknown",
            "dest_port": str(random.randint(80, 443)),
            "device_product": "Advanced Firewall Module",
            "device_vendor": "F5",
            "device_version": "14.0.0",
            "drop_reason": "Policy",
            "afmThreatScore": round(random.uniform(0.0, 1.0), 3),
            "accessAnomaly": round(random.uniform(0.0, 1.0), 3),
            "asmAttackIndicator": 1 if random.choice(["SQL_Injection", "XSS", "None"]) != "None" else 0
        })
    
    return log


def send_log(log):
    """Send a log entry to the Agent Service with retry logic."""
    for attempt in range(RETRY_LIMIT):
        try:
            response = requests.post(AGENT_SERVICE_URL, json=log, timeout=5)
            response.raise_for_status()
            print(f"[Usecase {log['usecase']}, {log['module']}] Response: {response.json()}")
            return
        except requests.exceptions.RequestException as e:
            print(f"Error sending log (Attempt {attempt+1}/{RETRY_LIMIT}): {e}")
            time.sleep(2)  # Retry delay
    print(f"Failed to send log after {RETRY_LIMIT} retries.")


def main():
    """Runs all use cases and modules in a single execution."""
    print(f"Starting full validation cycle across all use cases and modules.")

    for usecase in USECASES:
        for module in MODULES:
            print(f"\nValidating Use Case {usecase} - Module {module}")
            log = generate_log(usecase, module)
            print(json.dumps(log, indent=2))
            send_log(log)

            # Wait between each log submission
            time.sleep(TIME_GAP)

    print(f"\n✅ Completed one full validation cycle across all use cases.")


if __name__ == "__main__":
    main()