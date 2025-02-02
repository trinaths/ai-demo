import json
import pandas as pd
import random
from datetime import datetime, timedelta

# Number of logs to generate
NUM_LOGS = 10000  

# Define real-world attack types and behaviors
user_agents = [
    "Mozilla/5.0", "curl/7.68.0", "PostmanRuntime", "Nmap Scripting Engine",
    "SQLMap", "GoogleBot", "ZGrab", "BurpSuite", "Nessus"
]
ip_reputation_values = ["Good", "Suspicious", "Malicious"]
violations = [
    "SQL Injection", "XSS", "Remote File Inclusion", "Command Injection",
    "DDoS", "Brute Force", "Credential Stuffing"
]

# Attack Variations with Realistic Metrics
malicious_attack_patterns = [
    {"violation": "SQL Injection", "response_code": 403, "bytes_sent": 2800, "bytes_received": 1200, "request_rate": 1400},
    {"violation": "XSS", "response_code": 403, "bytes_sent": 2100, "bytes_received": 700, "request_rate": 1300},
    {"violation": "DDoS", "response_code": 503, "bytes_sent": 12000, "bytes_received": 600, "request_rate": 9000},
    {"violation": "Credential Stuffing", "response_code": 401, "bytes_sent": 5500, "bytes_received": 900, "request_rate": 2800},
    {"violation": "Brute Force", "response_code": 401, "bytes_sent": 4700, "bytes_received": 450, "request_rate": 3100},
    {"violation": "Remote File Inclusion", "response_code": 500, "bytes_sent": 3200, "bytes_received": 1800, "request_rate": 2000},
]

# Function to generate random timestamps within a time range
def random_timestamp():
    base_time = datetime.utcnow()
    random_offset = timedelta(days=random.randint(0, 27), hours=random.randint(0, 23), minutes=random.randint(0, 59), seconds=random.randint(0, 59), milliseconds=random.randint(0, 999))
    return (base_time - random_offset).isoformat() + "Z"

# Generate dataset
asm_logs = []
for i in range(NUM_LOGS):
    is_malicious = random.random() > 0.55  # 55% chance of being malicious

    if is_malicious:
        attack = random.choice(malicious_attack_patterns)
        log = {
            "timestamp": random_timestamp(),
            "src_ip": f"192.168.1.{random.randint(1, 255)}",
            "request": f"/api/attack?id={random.randint(100, 999)}",
            "violation": attack["violation"],
            "response_code": attack["response_code"],
            "bytes_sent": attack["bytes_sent"] + random.randint(-500, 500),
            "bytes_received": attack["bytes_received"] + random.randint(-200, 200),
            "request_rate": attack["request_rate"] + random.randint(-500, 500),
            "bot_signature": random.choice(["Known Malicious", "Suspicious", "Nessus", "BurpSuite"]),
            "severity": random.choice(["Medium", "High"]),  # Ensure attacks have at least Medium severity
            "user_agent": random.choice(user_agents),
            "ip_reputation": random.choice(["Suspicious", "Malicious"]),
            "prediction": 1  # Malicious traffic
        }
    else:
        log = {
            "timestamp": random_timestamp(),
            "src_ip": f"192.168.1.{random.randint(1, 255)}",
            "request": f"/api/resource?id={random.randint(100, 999)}",
            "violation": "None",
            "response_code": 200,
            "bytes_sent": random.randint(500, 5000),
            "bytes_received": random.randint(500, 3000),
            "request_rate": random.randint(100, 2000),
            "bot_signature": "Unknown",
            "severity": "Low",
            "user_agent": random.choice(user_agents),
            "ip_reputation": "Good",
            "prediction": 0  # Normal traffic
        }

    asm_logs.append(log)

# Convert to DataFrame
df_generated = pd.DataFrame(asm_logs)

# Validate & Save as CSV
csv_filename = "collected_traffic.csv"

if not df_generated.empty and all(col in df_generated.columns for col in ["timestamp", "src_ip", "request", "violation", "prediction"]):
    df_generated.to_csv(csv_filename, index=False)
    print(f"✅ Improved ASM training data successfully generated and saved as '{csv_filename}'!")
else:
    print("❌ Data validation failed! Missing required columns.")