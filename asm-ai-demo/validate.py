import requests
import logging
import time
from requests.exceptions import RequestException, HTTPError, Timeout, ConnectionError
from datetime import datetime, timezone
from collections import OrderedDict

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Define the base URL for the Agent Service
NODE_IP = "10.4.1.115"  # Replace <NodeIP> with the actual IP of the node
NODE_PORT = 30080  # The NodePort we defined in the service

BASE_URL = f"http://{NODE_IP}:{NODE_PORT}/analyze"  # Construct the full URL

# Maximum retries and backoff factor for handling transient failures
MAX_RETRIES = 3
BACKOFF_FACTOR = 2  # Exponential backoff

def generate_payload(base_payload):
    """
    Generates a payload with a timezone-aware UTC timestamp as the first key.
    """
    timestamp = datetime.now(timezone.utc).isoformat()  # ISO 8601 format with UTC timezone
    ordered_payload = OrderedDict([("timestamp", timestamp)])  # Add timestamp first
    ordered_payload.update(base_payload)  # Append other fields in order
    return ordered_payload

# Base Payload templates (WITHOUT "timestamp" key)
BASE_NORMAL_PAYLOAD = {
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

BASE_MALICIOUS_PAYLOAD = {
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

def send_traffic_request(payload, attempt=1):
    """
    Function to send a POST request with traffic payload.
    Implements retry logic in case of network issues.
    Returns the JSON response if successful, otherwise None.
    """
    try:
        logger.info(f"Attempt {attempt}: Sending request to {BASE_URL} with payload: {payload}")

        response = requests.post(BASE_URL, json=payload, timeout=10)  # 10s timeout
        
        # Check if the response status code indicates success
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx, 5xx)
        
        # Try to parse the JSON response
        json_response = response.json()

        if isinstance(json_response, dict):  # Validate response format
            return json_response
        else:
            logger.error(f"Unexpected response format: {json_response}")
            return None

    except (HTTPError, ConnectionError, Timeout) as error:
        logger.error(f"Request error: {error}")

        if attempt < MAX_RETRIES:
            sleep_time = BACKOFF_FACTOR ** (attempt - 1)  # Exponential backoff
            logger.info(f"Retrying in {sleep_time} seconds...")
            time.sleep(sleep_time)
            return send_traffic_request(payload, attempt + 1)  # Recursive retry
        else:
            logger.error(f"Max retries reached. Failed to send request.")
    
    except ValueError as json_err:
        logger.error(f"Error parsing JSON response: {json_err}")

    return None  # Return None if there was an error

def main():
    # Test normal traffic with timestamp
    normal_payload = generate_payload(BASE_NORMAL_PAYLOAD)
    logger.info("\n🔹 Testing NORMAL traffic...")
    normal_response = send_traffic_request(normal_payload)
    if normal_response:
        logger.info(f"✅ Normal Traffic Response: {normal_response}")
    else:
        logger.error("❌ Failed to receive or parse normal traffic response.")
    
    # Test malicious traffic with timestamp
    malicious_payload = generate_payload(BASE_MALICIOUS_PAYLOAD)
    logger.info("\n🔹 Testing MALICIOUS traffic...")
    malicious_response = send_traffic_request(malicious_payload)
    if malicious_response:
        logger.info(f"✅ Malicious Traffic Response: {malicious_response}")
    else:
        logger.error("❌ Failed to receive or parse malicious traffic response.")

if __name__ == "__main__":
    main()