import json
import pandas as pd
import random
from datetime import datetime, timedelta

# **📌 Number of logs to generate**
NUM_NORMAL = 5000
NUM_MALICIOUS = 5000
TOTAL_LOGS = NUM_NORMAL + NUM_MALICIOUS

# **🛠 Define attack & normal traffic behaviors**
user_agents = [
    "Mozilla/5.0", "curl/7.68.0", "PostmanRuntime", "GoogleBot",
    "ZGrab", "BurpSuite", "Nessus", "SQLMap", "Nmap Scripting Engine"
]
ip_reputation_values = ["Good", "Suspicious", "Malicious"]
violations = [
    "SQL Injection", "XSS", "Remote File Inclusion", "Command Injection",
    "DDoS", "Brute Force", "Credential Stuffing"
]

# **🔹 Attack variations with more distinct feature separation**
malicious_attack_patterns = [
    {"violation": "SQL Injection", "response_code": 403, "bytes_sent": 3000, "bytes_received": 1200, "request_rate": 2500},
    {"violation": "XSS", "response_code": 403, "bytes_sent": 2200, "bytes_received": 900, "request_rate": 1900},
    {"violation": "DDoS", "response_code": 503, "bytes_sent": 18000, "bytes_received": 2000, "request_rate": 15000},
    {"violation": "Credential Stuffing", "response_code": 401, "bytes_sent": 5800, "bytes_received": 1100, "request_rate": 4000},
    {"violation": "Brute Force", "response_code": 401, "bytes_sent": 5000, "bytes_received": 500, "request_rate": 5000},
    {"violation": "Remote File Inclusion", "response_code": 500, "bytes_sent": 3500, "bytes_received": 2000, "request_rate": 2700},
]

# **📅 Generate realistic timestamps**
def random_timestamp():
    base_time = datetime.utcnow()
    random_offset = timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    return (base_time - random_offset).isoformat() + "Z"

# **🚀 Generate normal and malicious logs separately**
logs = []

# **Generate normal traffic**
for _ in range(NUM_NORMAL):
    log = {
        "timestamp": random_timestamp(),
        "src_ip": f"192.168.1.{random.randint(1, 255)}",
        "request": f"/api/resource?id={random.randint(100, 999)}",
        "violation": "None",
        "response_code": 200,
        "bytes_sent": random.randint(500, 5000),
        "bytes_received": random.randint(500, 3000),
        "request_rate": random.randint(50, 800),  # **Keep normal request rates lower**
        "bot_signature": "Unknown",
        "severity": "Low",
        "user_agent": random.choice(user_agents),
        "ip_reputation": "Good",
        "prediction": 0  # **Normal traffic**
    }
    logs.append(log)

# **Generate malicious traffic**
for _ in range(NUM_MALICIOUS):
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
        "severity": "High",
        "user_agent": random.choice(user_agents),
        "ip_reputation": random.choice(["Suspicious", "Malicious"]),
        "prediction": 1  # **Malicious traffic**
    }
    logs.append(log)

# **🔄 Shuffle data to prevent sequential bias**
random.shuffle(logs)

# **📊 Convert to DataFrame**
df_generated = pd.DataFrame(logs)

# **✅ Validate & Save CSV**
csv_filename = "collected_traffic.csv"
required_columns = ["timestamp", "src_ip", "request", "violation", "response_code", "bytes_sent", "bytes_received", "request_rate", "bot_signature", "severity", "user_agent", "ip_reputation", "prediction"]

if not df_generated.empty and all(col in df_generated.columns for col in required_columns):
    df_generated.to_csv(csv_filename, index=False)
    print(f"✅ Successfully generated dataset with {len(df_generated)} samples: {NUM_NORMAL} normal, {NUM_MALICIOUS} malicious.")
else:
    print("❌ Data validation failed! Missing required columns.")