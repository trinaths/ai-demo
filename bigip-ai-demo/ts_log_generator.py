# > pip install faker pandas json tqdm
# This script generates sample AI-driven telemetry logs for the BigIP AI Demo 
# and saves them to JSON files for each AI use case category.
# The logs are generated using the Faker library and are based on the AI use case categories.
# Sample TS logs are from https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/output-example.html
# The logs are generated in the following format:
# {
#     "telemetryEventCategory": "LTM",
#     "system": {
#         "hostname": "bigip-1",
#         "cpu": 85,
#         "tmmCpu": 80,
#         "memory": 90
#     },
#     "virtualServers": {
#         "/Common/vs_https": {
#             "clientside.bitsIn": 1000000,
#             "clientside.bitsOut": 1000000,
#             "clientside.curConns": 1000
#         }
#     },
#     "request": {
#         "httpMethod": "GET",
#         "protocol": "HTTPS",
#        "requestTimestamp": "2021-07-01T12:00:00"
#     }
# }
#   
# The script generates 10,000 logs for each AI use case category:
# - SSL Offloading
# - Traffic Steering + SLA Enforcement
# - Ingress/Egress Routing
# - Auto-Scaling + Service Discovery
# - Cluster Resilience
# The logs are saved to JSON files for each AI use case category.
# The generated logs are saved to the following files:
# - ssl_offloading_logs.json
# - traffic_steering_sla_logs.json
# - ingress_egress_routing_logs.json
# - auto_scaling_service_discovery_logs.json
# - cluster_resilience_logs.json

import json
import random
from faker import Faker
import pandas as pd
from tqdm import tqdm
from datetime import datetime, timedelta

# Initialize Faker
fake = Faker()

# Number of samples per module
num_samples = 10000

# Helper function to generate timestamps
def generate_timestamp():
    start = datetime.now() - timedelta(days=30)
    end = datetime.now()
    return fake.date_time_between(start_date=start, end_date=end).isoformat()

# AI Use Case Merged Categories
ai_use_cases = {
    "ssl_offloading": [],
    "traffic_steering_sla": [],
    "ingress_egress_routing": [],
    "auto_scaling_service_discovery": [],
    "cluster_resilience": []
}

# Generate logs
for _ in tqdm(range(num_samples), desc="Generating AI Use Case Logs"):

    # SSL Offloading Logs
    ai_use_cases["ssl_offloading"].append({
        "telemetryEventCategory": "LTM",
        "system": {
            "hostname": fake.hostname(),
            "cpu": random.randint(50, 95),
            "tmmCpu": random.randint(40, 90),
            "memory": random.randint(60, 98)
        },
        "virtualServers": {
            "/Common/vs_https": {
                "clientside.bitsIn": random.randint(50000, 2000000),
                "clientside.bitsOut": random.randint(50000, 2000000),
                "clientside.curConns": random.randint(500, 5000)
            }
        },
        "request": {
            "httpMethod": "GET",
            "protocol": "HTTPS",
            "requestTimestamp": generate_timestamp()
        }
    })

    # Traffic Steering + SLA Enforcement Logs
    ai_use_cases["traffic_steering_sla"].append({
        "telemetryEventCategory": "LTM",
        "network": {
            "client": {"ip": fake.ipv4()},
            "server": {"ip": fake.ipv4()}
        },
        "virtualServers": {
            "/Common/vs_http": {
                "clientside.curConns": random.randint(100, 10000),
                "clientside.bitsIn": random.randint(50000, 5000000),
                "clientside.bitsOut": random.randint(50000, 5000000)
            }
        },
        "response": {
            "statusCode": random.choice([200, 301, 403, 404, 500]),
            "latency": random.randint(50, 500),
        },
        "request": {
            "httpMethod": random.choice(["GET", "POST"]),
            "requestTimestamp": generate_timestamp()
        },
        "multiTenancy": {
            "slaTier": random.choice(["Gold", "Silver", "Bronze"]),
            "tenant": fake.company()
        }
    })

    # Ingress/Egress Routing Logs
    ai_use_cases["ingress_egress_routing"].append({
        "telemetryEventCategory": "LTM",
        "system": {
            "failoverStatus": random.choice(["Active", "Standby"]),
            "syncStatus": random.choice(["Standalone", "In Sync"]),
            "hostname": fake.hostname()
        },
        "virtualServers": {
            "/Common/vs_routing": {
                "clientside.curConns": random.randint(500, 5000)
            }
        }
    })

    # Auto-Scaling + Service Discovery Logs
    ai_use_cases["auto_scaling_service_discovery"].append({
        "telemetryEventCategory": "LTM",
        "system": {
            "cpu": random.randint(50, 98),
            "memory": random.randint(60, 98),
            "hostname": fake.hostname()
        },
        "virtualServers": {
            "/Common/vs_autoscale": {
                "clientside.curConns": random.randint(100, 5000),
                "clientside.bitsIn": random.randint(50000, 5000000),
                "clientside.bitsOut": random.randint(50000, 5000000)
            }
        }
    })

    # Cluster Resilience Logs
    ai_use_cases["cluster_resilience"].append({
        "telemetryEventCategory": "LTM",
        "system": {
            "cpu": random.randint(50, 98),
            "memory": random.randint(60, 98),
            "failoverStatus": random.choice(["Active", "Standby"]),
            "syncStatus": random.choice(["Standalone", "In Sync"]),
            "hostname": fake.hostname()
        }
    })

# Save logs to JSON files
for use_case, logs in ai_use_cases.items():
    with open(f"{use_case}_logs.json", "w") as f:
        json.dump(logs, f, indent=4)

print("AI-Driven TS Log Generation Complete.")