import requests
import json

# Define the AI agent API endpoint
AI_AGENT_URL = "http://10.4.1.115:30001/analyze_traffic"

# Example normal traffic data
normal_traffic_data = {
    "event_type": "TRAFFIC",
    "timestamp": "2025-02-01T10:00:00Z",
    "ip_address": "192.168.1.20",
    "http_method": "GET",
    "uri": "/home",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "status_code": 200,
    "malicious": False,
    "attack_signature": "None"
}

# Send the telemetry data to the AI agent for processing
response = requests.post(AI_AGENT_URL, json=normal_traffic_data)

if response.status_code == 202:
    print("AI Agent received and is processing the traffic data.")
    print(f"Response: {response.json()}")
else:
    print(f"Failed to send data. Status Code: {response.status_code}")
    print(f"Error: {response.text}")