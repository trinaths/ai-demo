#!/usr/bin/env python3
import json
import random
from datetime import datetime

# Multi-tenancy: simulate different tenants.
tenants = ["Common", "Tenant_A", "Tenant_B"]

# Map usecase numbers to modules.
# Usecase 1: LTM & SYSTEM (Crypto Offload)
# Usecase 2: APM (Traffic Steering)
# Usecase 3: APM (SLA Enforcement)
# Usecase 4: LTM & SYSTEM (Routing Update)
# Usecase 5: ASM (Auto-scale Services)
# Usecase 6: ASM (Service Discovery & Orchestration)
# Usecase 7: ASM (Cluster Maintenance)
# Usecase 8: AFM (Multi-layer Security Enforcement)
usecase_module_mapping = {
    1: ["LTM", "SYSTEM"],
    2: ["APM"],
    3: ["APM"],
    4: ["LTM", "SYSTEM"],
    5: ["ASM"],
    6: ["ASM"],
    7: ["ASM"],
    8: ["AFM"]
}

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_system_metrics():
    tmmCpu = round(random.uniform(0.0, 1.0), 3)
    tmmTraffic = round(random.uniform(0.0, 1.0), 3)
    cryptoLoad = round(0.6 * tmmCpu + 0.4 * tmmTraffic, 3)
    latency = round(random.uniform(0.01, 0.3), 3)
    jitter = round(random.uniform(0.0, 0.05), 3)
    packetLoss = round(random.uniform(0.0, 0.05), 3)
    return tmmCpu, tmmTraffic, cryptoLoad, latency, jitter, packetLoss

def generate_system_log():
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tenant": random.choice(tenants),
        "cpu": round(random.uniform(0.0, 100.0), 1),
        "memory": round(random.uniform(0.0, 100.0), 1),
        "tmmCpu": round(random.uniform(0.0, 1.0), 3),
        "throughputPerformance": round(random.uniform(0.0, 1.0), 3),
        "system.connectionsPerformance": round(random.uniform(0.0, 1.0), 3),
        "eventType": "system_info"
    }

def generate_afm_log():
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tenant": random.choice(tenants),
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
        # Multi-layer security fields:
        "afmThreatScore": round(random.uniform(0.0, 1.0), 3),
        "accessAnomaly": round(random.uniform(0.0, 1.0), 3),
        "asmAttackIndicator": 1 if random.choice(["SQL_Injection", "XSS", "None"]) != "None" else 0,
        "eventType": "afm_request"
    }

def generate_base_log(usecase, module):
    # For SYSTEM and AFM, use dedicated generators.
    if module == "SYSTEM":
        return generate_system_log()
    if module == "AFM":
        return generate_afm_log()

    tenant = random.choice(tenants)
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tenant": tenant,
    }
    if usecase in [1, 4]:
        tmmCpu, tmmTraffic, cryptoLoad, latency, jitter, packetLoss = generate_system_metrics()
        log["cryptoLoad"] = cryptoLoad
        log["latency"] = latency
        log["jitter"] = jitter
        log["packetLoss"] = packetLoss
        log["throughputPerformance"] = round(random.uniform(0.0, 1.0), 3)
        log.update({
            "event_source": "request_logging",
            "event_timestamp": datetime.utcnow().isoformat() + "Z",
            "hostname": "ltm-host",
            "client_ip": random_ip(),
            "server_ip": "",
            "http_method": random.choice(["GET", "POST"]),
            "http_uri": random.choice(["/", "/login"]),
            "virtual_name": "/Common/app.app/app_vs",
            "application": "app.app",
            "telemetryEventCategory": "LTM"
        })
    elif usecase in [2, 3]:
        log.update({
            "hostname": "apm-host",
            "errdefs_msgno": "01490102:5:",
            "partition_name": "Common",
            "session_id": hex(random.randint(0, 0xFFFFFF))[2:],
            "Access_Profile": "/Common/access_app",
            "Access_Policy_Result": random.choice(["Logon_Deny", "Allow"]),
            "telemetryEventCategory": "APM",
            "f5telemetry_timestamp": datetime.utcnow().isoformat() + "Z",
            "system.connectionsPerformance": round(random.uniform(0.0, 1.0), 3)
        })
    elif usecase in [5, 6, 7]:
        log.update({
            "hostname": "asm-host",
            "management_ip_address": "10.0.1.4",
            "http_class_name": "/Common/app.app/app_policy",
            "web_application_name": "/Common/app.app/app_policy",
            "policy_name": "/Common/app.app/app_policy",
            "policy_apply_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "violations": random.choice(["Evasion technique detected", "None"]),
            "support_id": str(random.randint(1000000000000000000, 9999999999999999999)),
            "request_status": random.choice(["blocked", "allowed"]),
            "response_code": "0",
            "ip_client": random_ip(),
            "route_domain": "0",
            "method": random.choice(["GET", "POST"]),
            "protocol": "HTTP",
            "query_string": "",
            "x_forwarded_for_header_value": random_ip(),
            "sig_ids": "",
            "sig_names": "",
            "date_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": random.choice(["Critical", "Moderate"]),
            "attack_type": random.choice(["Detection Evasion,Path Traversal", "None"]),
            "geo_location": "US",
            "ip_address_intelligence": "N/A",
            "username": "N/A",
            "session_id": hex(random.randint(0, 0xFFFFFF))[2:],
            "src_port": str(random.randint(1024, 65535)),
            "dest_port": str(random.randint(80, 443)),
            "dest_ip": random_ip(),
            "sub_violations": random.choice(["Evasion technique detected:Directory traversals", "None"]),
            "virus_name": "N/A",
            "violation_rating": random.choice(["3", "1", "5"]),
            "websocket_direction": "N/A",
            "websocket_message_type": "N/A",
            "device_id": "N/A",
            "staged_sig_ids": "",
            "staged_sig_names": "",
            "threat_campaign_names": "",
            "staged_threat_campaign_names": "",
            "blocking_exception_reason": "N/A",
            "captcha_result": "not_received",
            "uri": random.choice(["/directory/file", "/admin/secret"]),
            "fragment": "",
            "request": "GET /admin/..%2F..%2F..%2Fdirectory/file HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive",
            "telemetryEventCategory": "ASM",
            "application": "app.app",
            "asmAttackSignatures": random.choice(["SQL_Injection", "XSS", "None"]),
            "throughputPerformance": round(random.uniform(0.0, 1.0), 3)
        })
    return log

def add_module_specific_fields(log, module):
    if module == "LTM":
        log["sslProtocol"] = random.choice(["TLSv1.2", "TLSv1.3"])
        log["cipherSuite"] = random.choice(["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"])
    return log

def generate_ts_log(usecase, module):
    log = generate_base_log(usecase, module)
    log["module"] = module
    log["eventType"] = module.lower() + "_request"
    log["usecase"] = usecase
    log = add_module_specific_fields(log, module)
    return log

def main():
    total_logs_per_usecase = 10000
    output_file = "synthetic_ts_logs.jsonl"
    count = 0
    with open(output_file, "w") as f:
        for usecase, modules in usecase_module_mapping.items():
            for _ in range(total_logs_per_usecase):
                for module in modules:
                    log = generate_ts_log(usecase, module)
                    f.write(json.dumps(log) + "\n")
                    count += 1
    print(f"Generated {count} logs in {output_file}")

if __name__ == "__main__":
    main()