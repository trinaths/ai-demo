#!/usr/bin/env python3
"""
validator.py

A script that generates synthetic TS logs for all 8 use cases and 5 modules 
(LTM, APM, ASM, SYSTEM, AFM) and sends them to the Agent Service in one execution.
Each request is sent with a delay to simulate a realistic workload.

Usage:
  python validator.py
"""

import json
import random
import time
import os
import requests
import logging
from datetime import datetime

# Set up structured logging.
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

# Agent Service URL is configurable via an environment variable.
AGENT_SERVICE_URL = os.getenv("AGENT_SERVICE_URL", "http://10.4.1.115:30001/process-log")

# Configuration for retries and time gap.
RETRY_LIMIT = 3      # Maximum number of retry attempts for failed requests.
TIME_GAP = 5         # Time delay (in seconds) between each log submission.

# Valid use cases and modules.
USECASES = range(1, 9)
MODULES = ["LTM", "APM", "ASM", "SYSTEM", "AFM"]

def random_ip():
    """Generate a random IPv4 address."""
    ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    logging.debug(f"Generated random IP: {ip}")
    return ip

def generate_log(usecase, module):
    """Generate a synthetic log entry based on the use case and module."""
    logging.debug(f"Generating log for usecase {usecase}, module {module}")
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "deviceName": f"bigip-{usecase}",
        "tenant": random.choice(["Common", "Tenant_A", "Tenant_B"]),
        "cluster": "bigip-demo",
        "usecase": usecase,
        "module": module,
        "eventType": f"{module.lower()}_request",
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

    # Add module-specific fields.
    if module == "LTM":
        ltm_fields = {
            "virtualServerName": "/Common/app.app/app_vs",
            "poolName": "/Common/app.app/app_pool",
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "cryptoLoad": round(random.uniform(0.0, 1.0), 3),
            "latency": round(random.uniform(0.01, 0.3), 3),
            "jitter": round(random.uniform(0.0, 0.05), 3),
            "packetLoss": round(random.uniform(0.0, 0.05), 3)
        }
        log.update(ltm_fields)
        logging.debug(f"LTM specific fields added: {ltm_fields}")
    elif module == "APM":
        apm_value = round(random.uniform(0.0, 1.0), 3)
        log["system.connectionsPerformance"] = apm_value
        logging.debug(f"APM field system.connectionsPerformance: {apm_value}")
    elif module == "ASM":
        asm_fields = {
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "asmAttackSignatures": random.choice(["SQL_Injection", "XSS", "None"])
        }
        log.update(asm_fields)
        logging.debug(f"ASM specific fields added: {asm_fields}")
    elif module == "SYSTEM":
        system_fields = {
            "cpu": round(random.uniform(0.0, 100.0), 1),
            "memory": round(random.uniform(0.0, 100.0), 1),
            "tmmCpu": round(random.uniform(0.0, 1.0), 3),
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
            "system.connectionsPerformance": round(random.uniform(0.0, 1.0), 3)
        }
        log.update(system_fields)
        logging.debug(f"SYSTEM specific fields added: {system_fields}")
    elif module == "AFM":
        afm_fields = {
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
        }
        log.update(afm_fields)
        logging.debug(f"AFM specific fields added: {afm_fields}")

    logging.debug(f"Final generated log for usecase {usecase}, module {module}: {log}")
    return log

def send_log(log):
    """Send a log entry to the Agent Service with retry logic."""
    for attempt in range(1, RETRY_LIMIT + 1):
        try:
            logging.debug(f"Attempt {attempt}/{RETRY_LIMIT}: Sending log: {json.dumps(log)}")
            response = requests.post(AGENT_SERVICE_URL, json=log, timeout=5)
            response.raise_for_status()
            logging.info(f"[Usecase {log['usecase']}, {log['module']}] Received response: {response.json()}")
            return
        except requests.exceptions.RequestException as e:
            logging.error(f"Error sending log (Attempt {attempt}/{RETRY_LIMIT}): {e}")
            time.sleep(2)  # Wait before retrying.
    logging.error(f"Failed to send log after {RETRY_LIMIT} attempts.")

def main():
    logging.info("Starting full validation cycle across all use cases and modules.")
    for usecase in USECASES:
        logging.debug(f"Starting logs for usecase {usecase}")
        for module in MODULES:
            logging.info(f"Validating Use Case {usecase} - Module {module}")
            log = generate_log(usecase, module)
            logging.debug("Generated TS log:\n" + json.dumps(log, indent=2))
            send_log(log)
            logging.debug(f"Sleeping for {TIME_GAP} seconds before next log submission.")
            time.sleep(TIME_GAP)
    logging.info("Completed one full validation cycle across all use cases.")

if __name__ == "__main__":
    main()