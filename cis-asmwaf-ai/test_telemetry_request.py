import requests
import json

# Define the AI agent API endpoint
AI_AGENT_URL = "http://10.4.1.115:30001/analyze_traffic"

# Fake telemetry data similar to what BigIP would send
fake_telemetry_data = {
    "event_type": "WAF_TRIGGERED",
    "timestamp": "2025-02-01T10:00:00Z",
    "ip_address": "192.168.1.10",
    "http_method": "GET",
    "uri": "/example/resource?id=123",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "status_code": 403,
    "malicious": True,
    "attack_signature": "SQL Injection Attempt"
}

# Log the telemetry data to inspect it
print("Sending telemetry data:")
print(json.dumps(fake_telemetry_data, indent=4))

# Send the telemetry data to the AI agent for processing with proper headers
headers = {
    'Content-Type': 'application/json',
}

try:
    response = requests.post(AI_AGENT_URL, json=fake_telemetry_data, headers=headers)

    if response.status_code == 200:
        print("AI Agent processed the telemetry successfully!")
        print(f"Response: {response.json()}")
    else:
        print(f"Failed to process telemetry. Status Code: {response.status_code}")
        print(f"Error: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"An error occurred while sending the request: {e}")