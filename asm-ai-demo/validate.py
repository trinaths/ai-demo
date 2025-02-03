import requests
import logging
import time
from requests.exceptions import RequestException, HTTPError, Timeout, ConnectionError
from datetime import datetime, timezone
from collections import OrderedDict

# **📌 Configure logging**
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# **🌍 Define the AI-WAF API Endpoint**
NODE_IP = "10.4.1.115"  # Update with your AI-WAF node IP
NODE_PORT = 30080  # The exposed NodePort of the service
BASE_URL = f"http://{NODE_IP}:{NODE_PORT}/analyze"

# **🔄 Retry settings**
MAX_RETRIES = 3
BACKOFF_FACTOR = 2  # Exponential backoff

def generate_payload(base_payload):
    """
    Generates a payload with a timezone-aware UTC timestamp.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    ordered_payload = OrderedDict([("timestamp", timestamp)])  # Add timestamp first
    ordered_payload.update(base_payload)  # Append other fields in order
    return ordered_payload

def send_request(payload, attempt=1):
    """
    Sends a POST request to the AI-WAF.
    Implements retries in case of network failures.
    """
    try:
        logger.info(f"🚀 Attempt {attempt}: Sending request to {BASE_URL} with payload: {payload}")
        response = requests.post(BASE_URL, json=payload, timeout=10)  # 10s timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx, 5xx)
        json_response = response.json()
        
        if isinstance(json_response, dict):  # Ensure valid response format
            return json_response
        else:
            logger.error(f"⚠️ Unexpected response format: {json_response}")
            return None

    except (HTTPError, ConnectionError, Timeout) as error:
        logger.error(f"❌ Request error: {error}")

        if attempt < MAX_RETRIES:
            sleep_time = BACKOFF_FACTOR ** (attempt - 1)  # Exponential backoff
            logger.info(f"🔄 Retrying in {sleep_time} seconds...")
            time.sleep(sleep_time)
            return send_request(payload, attempt + 1)
        else:
            logger.error(f"❌ Max retries reached. Failed to send request.")
    
    except ValueError as json_err:
        logger.error(f"❌ Error parsing JSON response: {json_err}")

    return None  # Return None if there was an error

def test_requests(requests_list, expected_status):
    """
    Tests multiple payloads and validates their response.
    """
    for payload in requests_list:
        request_payload = generate_payload(payload)
        response = send_request(request_payload)

        if response:
            logger.info(f"✅ Response: {response}")

            # **Validate if response is as expected**
            if response.get("status") == expected_status:
                logger.info(f"✅ SUCCESS: {payload['src_ip']} classified correctly as {expected_status.upper()}")
            else:
                logger.error(f"❌ MISMATCH: Expected {expected_status.upper()} but got {response.get('status')}")
        else:
            logger.error(f"❌ Failed to receive response for {payload['src_ip']}")

def main():
    """
    Runs tests on both **malicious** and **normal** traffic.
    """

    # **🛑 Malicious Traffic Requests**
    malicious_traffic = [
        {
            "src_ip": "192.168.1.150",
            "request": "/login?username=admin' OR '1'='1' --&password=1234",
            "violation": "SQL Injection",
            "response_code": 403,
            "bytes_sent": 1800,
            "bytes_received": 500,
            "request_rate": 1300,
            "bot_signature": "SQLMap",
            "severity": "High",
            "user_agent": "Mozilla/5.0 (SQLMap)",
            "ip_reputation": "Suspicious",
            "prediction": 1
        },
        {
            "src_ip": "10.10.10.20",
            "request": "/search?q=<script>alert('XSS')</script>",
            "violation": "XSS",
            "response_code": 403,
            "bytes_sent": 2000,
            "bytes_received": 800,
            "request_rate": 1200,
            "bot_signature": "BurpSuite",
            "severity": "Medium",
            "user_agent": "BadBot/1.0",
            "ip_reputation": "Malicious",
            "prediction": 1
        },
        {
            "src_ip": "203.0.113.100",
            "request": "/api/data",
            "violation": "DDoS",
            "response_code": 503,
            "bytes_sent": 12000,
            "bytes_received": 3000,
            "request_rate": 9000,
            "bot_signature": "Unknown",
            "severity": "High",
            "user_agent": "Mozilla/5.0",
            "ip_reputation": "Malicious",
            "prediction": 1
        }
    ]

    # **✅ Good (Normal) Traffic Requests**
    normal_traffic = [
        {
            "src_ip": "192.168.1.50",
            "request": "/api/resource?id=123",
            "violation": "None",
            "response_code": 200,
            "bytes_sent": 3000,
            "bytes_received": 1500,
            "request_rate": 500,
            "bot_signature": "Unknown",
            "severity": "Low",
            "user_agent": "Mozilla/5.0",
            "ip_reputation": "Good",
            "prediction": 0
        },
        {
            "src_ip": "172.16.0.20",
            "request": "/home",
            "violation": "None",
            "response_code": 200,
            "bytes_sent": 5000,
            "bytes_received": 2500,
            "request_rate": 200,
            "bot_signature": "Unknown",
            "severity": "Low",
            "user_agent": "Mozilla/5.0",
            "ip_reputation": "Good",
            "prediction": 0
        },
        {
            "src_ip": "10.0.0.30",
            "request": "/api/user/profile",
            "violation": "None",
            "response_code": 200,
            "bytes_sent": 4500,
            "bytes_received": 2000,
            "request_rate": 300,
            "bot_signature": "Unknown",
            "severity": "Low",
            "user_agent": "Mozilla/5.0",
            "ip_reputation": "Good",
            "prediction": 0
        }
    ]

    logger.info("\n🔹 **Testing MALICIOUS traffic...**")
    test_requests(malicious_traffic, expected_status="malicious")

    logger.info("\n🔹 **Testing NORMAL traffic...**")
    test_requests(normal_traffic, expected_status="normal")

if __name__ == "__main__":
    main()