import requests
import json

# Sample malicious traffic data in ASM JSON format (simulated)
asm_malicious_data = {
    "timestamp": "2025-02-01T12:00:00Z",  # Example timestamp
    "src_ip": "192.168.1.100",  # Malicious IP address
    "request": "/admin/login",  # The targeted URI/Endpoint
    "violation": "SQL Injection",  # Type of attack detected (e.g., SQL Injection)
    "bot_signature": "bot-12345",  # Fake bot signature (could be from a bot detection system)
    "severity": "High",  # Severity level of the attack
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",  # User-agent (common in attack attempts)
    "ip_reputation": "Malicious",  # IP reputation indicating that the IP is known for malicious activity
    "bytes_sent": 1000,  # Bytes sent during the request (example value)
    "bytes_received": 2000,  # Bytes received during the request (example value)
    "request_rate": 5,  # Request rate (example value, higher may indicate a DDoS attempt)
    "label": 1  # Label indicating that the data is malicious (1 = malicious)
}

# Send the malicious ASM data to the AI Agent's /analyze_traffic endpoint
response = requests.post("http://localhost:5000/analyze_traffic", json=asm_malicious_data)

# Print response from AI Agent
if response.status_code == 202:
    print("🟢 AI analysis started. Traffic data is being processed.")
else:
    print(f"❌ Error: {response.json()}")