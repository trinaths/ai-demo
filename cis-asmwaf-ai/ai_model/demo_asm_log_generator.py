import json
import pandas as pd
import random

# Define real-world attack types and behaviors
user_agents = [
    "Mozilla/5.0", "curl/7.68.0", "PostmanRuntime", "Nmap Scripting Engine", "SQLMap"
]
ip_reputation_values = ["Good", "Suspicious", "Malicious"]
violations = [
    "SQL Injection", "XSS", "Remote File Inclusion", "Command Injection",
    "DDoS", "Brute Force", "Credential Stuffing"
]

# Improve Attack Variation
malicious_attack_patterns = [
    {"violation": "SQL Injection", "response_code": 403, "bytes_sent": 3000, "bytes_received": 1000, "request_rate": 1500},
    {"violation": "XSS", "response_code": 403, "bytes_sent": 2000, "bytes_received": 800, "request_rate": 1200},
    {"violation": "DDoS", "response_code": 503, "bytes_sent": 10000, "bytes_received": 500, "request_rate": 8000},
    {"violation": "Credential Stuffing", "response_code": 401, "bytes_sent": 6000, "bytes_received": 1000, "request_rate": 2500},
    {"violation": "Brute Force", "response_code": 401, "bytes_sent": 5000, "bytes_received": 500, "request_rate": 3000},
]

# Generate 10,000 improved ASM logs
asm_logs = []
for i in range(10000):
    is_malicious = random.random() > 0.5  # 50% chance of being malicious

    if is_malicious:
        attack = random.choice(malicious_attack_patterns)
        log = {
            "timestamp": f"2024-02-{random.randint(1, 28)}T12:{random.randint(10, 59)}:{random.randint(10, 59)}Z",
            "src_ip": f"192.168.1.{random.randint(1, 255)}",
            "request": f"/api/attack?id={random.randint(100, 999)}",
            "violation": attack["violation"],
            "response_code": attack["response_code"],
            "bytes_sent": attack["bytes_sent"] + random.randint(-500, 500),
            "bytes_received": attack["bytes_received"] + random.randint(-200, 200),
            "request_rate": attack["request_rate"] + random.randint(-500, 500),
            "bot_signature": random.choice(["Unknown", "Known Malicious"]),
            "severity": random.choice(["Medium", "High"]),  # All attacks should have at least Medium severity
            "user_agent": random.choice(user_agents),
            "ip_reputation": random.choice(["Suspicious", "Malicious"]),
            "label": 1  # Malicious traffic
        }
    else:
        log = {
            "timestamp": f"2024-02-{random.randint(1, 28)}T12:{random.randint(10, 59)}:{random.randint(10, 59)}Z",
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
            "label": 0  # Normal traffic
        }

    asm_logs.append(log)

# Convert to DataFrame
df_generated = pd.DataFrame(asm_logs)

# Save as CSV
csv_filename = "improved_asm_training_data.csv"
df_generated.to_csv(csv_filename, index=False)

print(f"✅ Improved ASM training data successfully generated and saved as '{csv_filename}'!")