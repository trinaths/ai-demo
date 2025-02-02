import requests
import logging
from requests.exceptions import RequestException, HTTPError, Timeout
from datetime import datetime, timezone
from collections import OrderedDict

# **🛠 Configure Logging**
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# **📍 Define the base URL for the Agent Service**
NODE_IP = "10.4.1.115"  # Replace with actual IP
NODE_PORT = 30080  # The NodePort of the service

BASE_URL = f"http://{NODE_IP}:{NODE_PORT}/analyze"  # Construct the full URL

# **🔹 Number of Times to Repeat Requests for Consistency Check**
ITERATIONS_PER_IP = 3  

# **🔹 Function to Add Timestamp at Start of Payload**
def generate_payload(base_payload):
    timestamp = datetime.now(timezone.utc).isoformat()  
    ordered_payload = OrderedDict([("timestamp", timestamp)])  
    ordered_payload.update(base_payload)  
    return ordered_payload

# **🔹 Normal Traffic Payload**
BASE_NORMAL_PAYLOAD = {
    "src_ip": "192.168.1.100",
    "request": "/api/resource",
    "violation": "None",
    "response_code": 200,
    "bytes_sent": 4000,
    "bytes_received": 1500,
    "request_rate": 500,
    "bot_signature": "Unknown",
    "severity": "Low",
    "user_agent": "Mozilla/5.0",
    "ip_reputation": "Good",
    "prediction": 0  # ✅ Expected to be classified as "normal"
}

# **🔹 Malicious Traffic Payload**
BASE_MALICIOUS_PAYLOAD = {
    "src_ip": "192.168.1.50",
    "request": "/api/malicious",
    "violation": "SQL Injection",
    "response_code": 403,
    "bytes_sent": 3000,
    "bytes_received": 1000,
    "request_rate": 2200,  # 🚨 High request rate typical of attacks
    "bot_signature": "Known Malicious",
    "severity": "High",
    "user_agent": "BurpSuite",
    "ip_reputation": "Malicious",
    "prediction": 1  # 🚨 Expected to be classified as "malicious"
}

# **🔹 Function to Send Requests to Agent**
def send_traffic_request(payload, expected_prediction, iteration):
    """ Sends a POST request and verifies if the agent blocks/accepts correctly. """
    try:
        logger.info(f"🚀 [{iteration+1}/{ITERATIONS_PER_IP}] Sending request to {BASE_URL} with payload: {payload}")
        
        response = requests.post(BASE_URL, json=payload, timeout=10)  
        response.raise_for_status()  # Raise error for bad HTTP responses (4xx, 5xx)

        json_response = response.json()
        logger.info(f"✅ Response: {json_response}")

        # **Check if response matches expectation**
        actual_prediction = 1 if json_response["status"] == "malicious" else 0

        if actual_prediction != expected_prediction:
            logger.error(f"❌ [Iteration {iteration+1}] Incorrect classification! Expected: {expected_prediction}, Got: {actual_prediction}")
        else:
            logger.info(f"✅ [Iteration {iteration+1}] Correctly classified: {json_response}")

    except HTTPError as http_err:
        logger.error(f"❌ HTTP error occurred: {http_err}")
    except Timeout as timeout_err:
        logger.error(f"❌ Request timed out: {timeout_err}")
    except RequestException as req_err:
        logger.error(f"❌ Request error occurred: {req_err}")
    except ValueError as json_err:
        logger.error(f"❌ Error parsing JSON response: {json_err}")

# **🔹 Main Function to Test Both Normal & Malicious Traffic Multiple Times**
def main():
    logger.info(f"🔄 Running {ITERATIONS_PER_IP} tests per IP to ensure consistency.")

    for i in range(ITERATIONS_PER_IP):
        logger.info(f"🔹 Normal Traffic Test {i+1}/{ITERATIONS_PER_IP}...")
        normal_payload = generate_payload(BASE_NORMAL_PAYLOAD)
        send_traffic_request(normal_payload, expected_prediction=0, iteration=i)

        logger.info(f"🔹 Malicious Traffic Test {i+1}/{ITERATIONS_PER_IP}...")
        malicious_payload = generate_payload(BASE_MALICIOUS_PAYLOAD)
        send_traffic_request(malicious_payload, expected_prediction=1, iteration=i)

if __name__ == "__main__":
    main()