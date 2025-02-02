import requests
import logging
from requests.exceptions import RequestException, HTTPError, Timeout

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the base URL for the Agent Service
NODE_IP = "10.4.1.115"  # Replace <NodeIP> with the actual IP of the node
NODE_PORT = 30080  # The NodePort we defined in the service

BASE_URL = f"http://{NODE_IP}:{NODE_PORT}/analyze"  # Construct the full URL

# Payload templates (for normal and malicious traffic)
NORMAL_PAYLOAD = {
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

MALICIOUS_PAYLOAD = {
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

def send_traffic_request(payload):
    """
    Function to send a POST request with traffic payload.
    Returns the JSON response if successful or None if an error occurs.
    """
    try:
        logger.info("Sending request to %s with payload: %s", BASE_URL, payload)
        
        # Send POST request
        response = requests.post(BASE_URL, json=payload, timeout=10)  # Added timeout for network issues
        
        # Check if the response status code indicates success
        response.raise_for_status()  # Will raise an HTTPError for bad responses (4xx, 5xx)
        
        # Try to parse the JSON response
        return response.json()
    
    except HTTPError as http_err:
        logger.error("HTTP error occurred: %s", http_err)
    except Timeout as timeout_err:
        logger.error("Request timed out: %s", timeout_err)
    except RequestException as req_err:
        logger.error("Request error occurred: %s", req_err)
    except ValueError as json_err:
        logger.error("Error parsing JSON response: %s", json_err)
    
    return None  # Return None if there was an error

def main():
    # Test normal traffic
    logger.info("Testing normal traffic...")
    normal_response = send_traffic_request(NORMAL_PAYLOAD)
    if normal_response:
        logger.info("Normal Traffic Response: %s", normal_response)
    else:
        logger.error("Failed to receive or parse normal traffic response.")
    
    # Test malicious traffic
    logger.info("Testing malicious traffic...")
    malicious_response = send_traffic_request(MALICIOUS_PAYLOAD)
    if malicious_response:
        logger.info("Malicious Traffic Response: %s", malicious_response)
    else:
        logger.error("Failed to receive or parse malicious traffic response.")

if __name__ == "__main__":
    main()