import requests

# Define the base URL for the Agent Service (Node IP and NodePort)
NODE_IP = "<NodeIP>"  # Replace <NodeIP> with the actual IP of the node
NODE_PORT = 30080  # The NodePort we defined in the service

BASE_URL = f"http://{NODE_IP}:{NODE_PORT}/analyze"  # Construct the full URL

# Normal Traffic Payload (matching CSV structure)
normal_payload = {
    "src_ip": "192.168.1.100",
    "request": "/api/resource",
    "violation": "None",
    "response_code": 200,
    "bytes_sent": 4000,
    "bytes_received": 1500,
    "request_rate": 600,
    "bot_signature": "Unknown",
    "severity": "Low",  # Optional
    "user_agent": "Mozilla/5.0",  # Optional
    "ip_reputation": "Good",
    "label": 0  # Label for training, prediction will be stored in the 'prediction' column
}

# Malicious Traffic Payload (matching CSV structure)
malicious_payload = {
    "src_ip": "192.168.1.50",
    "request": "/api/malicious",
    "violation": "XSS",
    "response_code": 403,
    "bytes_sent": 1500,
    "bytes_received": 700,
    "request_rate": 1200,
    "bot_signature": "Known Malicious",
    "severity": "High",  # Optional
    "user_agent": "BadBot/1.0",  # Optional
    "ip_reputation": "Suspicious",
    "label": 1  # Label for training, prediction will be stored in the 'prediction' column
}

# Test normal traffic
response = requests.post(BASE_URL, json=normal_payload)
print("Normal Traffic Response:", response.json())

# Test malicious traffic
response = requests.post(BASE_URL, json=malicious_payload)
print("Malicious Traffic Response:", response.json())