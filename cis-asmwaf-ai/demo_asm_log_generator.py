import json
import random
import pandas as pd

violations = ["SQL Injection", "XSS", "Remote File Inclusion", "Command Injection", "Credential Stuffing"]

asm_logs = []
for i in range(100):
    log = {
        "timestamp": f"2024-02-{random.randint(1, 28)}T12:{random.randint(10, 59)}:{random.randint(10, 59)}Z",
        "src_ip": f"192.168.1.{random.randint(1, 255)}",
        "request": f"/api/v1/resource?id={random.randint(100, 999)}",
        "violation": random.choice(violations),
        "response_code": 403 if random.random() > 0.5 else 200,
        "bytes_sent": random.randint(500, 10000),
        "bytes_received": random.randint(500, 5000),
        "request_rate": random.randint(100, 5000),
        "bot_signature": "Unknown",
        "severity": random.choice(["Low", "Medium", "High"]),
        "label": 1 if random.random() > 0.6 else 0  # 1 = Malicious, 0 = Normal
    }
    asm_logs.append(log)

with open("asm_raw_logs.json", "w") as file:
    json.dump(asm_logs, file, indent=4)

print("ASM logs generated successfully!")

df = pd.DataFrame(asm_logs)
df["violation"] = df["violation"].astype("category").cat.codes
df.to_csv("asm_training_data.csv", index=False)

print("ASM logs converted to CSV for AI training!")
