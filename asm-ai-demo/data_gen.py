import json
import pandas as pd
import random
from datetime import datetime, timedelta

# Number of logs to generate
NUM_LOGS = 10000

# Define attack and normal traffic behaviors
user_agents = [
    "Mozilla/5.0", "curl/7.68.0", "PostmanRuntime", "GoogleBot",
    "ZGrab", "BurpSuite", "Nessus", "SQLMap", "Nmap Scripting Engine"
]
ip_reputation_values = ["Good", "Suspicious", "Malicious"]
violations = [
    "SQL Injection", "XSS", "Remote File Inclusion", "Command Injection",
    "DDoS", "Brute Force", "Credential Stuffing"
]

# Attack variations with improved feature separation
malicious_attack_patterns = [
    {"violation": "SQL Injection", "response_code": 403, "bytes_sent": 2800, "bytes_received": 1200, "request_rate": 2000},
    {"violation": "XSS", "response_code": 403, "bytes_sent": 2100, "bytes_received": 700, "request_rate": 1700},
    {"violation": "DDoS", "response_code": 503, "bytes_sent": 15000, "bytes_received": 1000, "request_rate": 10000},
    {"violation": "Credential Stuffing", "response_code": 401, "bytes_sent": 5500, "bytes_received": 900, "request_rate": 3000},
    {"violation": "Brute Force", "response_code": 401, "bytes_sent": 4700, "bytes_received": 450, "request_rate": 4000},
    {"violation": "Remote File Inclusion", "response_code": 500, "bytes_sent": 3200, "bytes_received": 1800, "request_rate": 2500},
]

# **📅 Generate random timestamps following normal traffic behavior**
def random_timestamp():
    base_time = datetime.utcnow()
    random_offset = timedelta(days=random.randint(0, 7), hours=random.randint(0, 23), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    return (base_time - random_offset).isoformat() + "Z"

# **🛠 Generate dataset with improved class separation**
asm_logs = []
for i in range(NUM_LOGS):
    is_malicious = random.random() > 0.50  # **Ensure 50%-50% class balance**

    if is_malicious:
        attack = random.choice(malicious_attack_patterns)
        log = {
            "timestamp": random_timestamp(),
            "src_ip": f"192.168.1.{random.randint(1, 255)}",
            "request": f"/api/attack?id={random.randint(100, 999)}",
            "violation": attack["violation"],
            "response_code": attack["response_code"],
            "bytes_sent": attack["bytes_sent"] + random.randint(-300, 300),
            "bytes_received": attack["bytes_received"] + random.randint(-100, 100),
            "request_rate": attack["request_rate"] + random.randint(-300, 300),
            "bot_signature": random.choice(["Known Malicious", "Suspicious", "BurpSuite", "SQLMap"]),
            "severity": random.choice(["High"]),  # **Force high severity for attacks**
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
            "request_rate": random.randint(50, 800),  # **Ensure low request rates for normal**
            "bot_signature": "Unknown",
            "severity": "Low",
            "user_agent": random.choice(user_agents),
            "ip_reputation": "Good",
            "prediction": 0  # Normal traffic
        }

    asm_logs.append(log)

# **📊 Convert to DataFrame**
df_generated = pd.DataFrame(asm_logs)

# **✅ Validate & Save CSV**
csv_filename = "collected_traffic.csv"

required_columns = ["timestamp", "src_ip", "request", "violation", "response_code", "bytes_sent", "bytes_received", "request_rate", "bot_signature", "severity", "user_agent", "ip_reputation", "prediction"]
if not df_generated.empty and all(col in df_generated.columns for col in required_columns):
    df_generated.to_csv(csv_filename, index=False)
    print(f"✅ Improved ASM training data successfully generated and saved as '{csv_filename}'!")
else:
    print("❌ Data validation failed! Missing required columns.")