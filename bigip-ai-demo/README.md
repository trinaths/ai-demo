# AI Powered BIG-IP for multi-cluster, multi-tenant Kubernetes/OpenShift based AI infrastructure with AI workloads.

## Introduction

This document discusses AI powered BIG-IP for customer centric usecases with multiple requirements.

### Architecture Overview:
The PoC integrates BIG‑IP with Kubernetes/OpenShift by deploying dedicated AI components (model, agent, validator) that monitor telemetry streams (TS logs) from various BIG‑IP modules. The system uses persistent storage (via PV/PVC) to share logs and trained models among components.
### Multi‑Tenant & Multi‑Cluster:
Each deployment is mapped to a specific use case and tenant (e.g., “Common,” “Tenant_A,” “Tenant_B”), ensuring that the BIG‑IP configuration (via AS3 declarations) is tailored per tenant. The agent dynamically retrieves endpoints from multiple clusters, ensuring seamless configuration updates across clusters.
### AI Workloads:
The model is trained on synthetic TS logs that mimic production telemetry (e.g., crypto loads, connection performance, latency metrics) and provides real‑time predictions. The agent then uses these predictions to update BIG‑IP configurations (via AS3 JSON) to manage traffic and scaling intelligently.

## Demo architecture

![architecture](https://github.com/trinaths/ai-demo/blob/main/bigip-ai-demo/demo.png)


### Data Generation & Training:

* Synthetic Attributes:
We use attributes such as cryptoLoad, latency, throughput, afmThreatScore, etc., which are generated with realistic random values. Using [F5 Telemetry Streaming example output JSON sample data](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/output-example.html).
* Model Training:
  * For supervised models (LTM, APM, SYSTEM, AFM), we extract features (e.g., cryptoLoad, latency, tmmCpu) and train a RandomForest classifier to predict actions like “offload_crypto” or “block_traffic”.
  * For ASM, we use a simple Q‑learning approach where we update a Q‑table based on a reward signal derived from matching an optimal action (e.g., “scale_up”, “discover_service”).
  * The training script (train_model.py) loads synthetic logs from a file, assigns labels based on usecase-specific thresholds, extracts features, trains models, and then serializes them to a persistent model file.

### Agent Service Operation:

* Receive TS Log:
  * The agent accepts a TS log via its /process-log endpoint.
* Get Prediction:
  * It sends the log to the Model Service to get an action prediction.
* Scale Deployment (if needed):
  * If the prediction indicates scaling (e.g., “scale_up”), the agent updates the target deployment.
* Generate AS3 Payload:
  * Using the usecase field, the agent builds a consolidated AS3 JSON declaration (using dynamic endpoints fetched from Kubernetes).
* Update AS3 ConfigMap:
  * The agent patches a ConfigMap (monitored by F5 CIS) with the new AS3 payload. F5 CIS automatically pushes the configuration to BIG‑IP.
* Append Training Data:
  * The processed log is saved for future retraining.
* Retraining:
  * A CronJob periodically triggers the Model Service’s /retrain endpoint to fine‑tune models with the new training data.

### Test Environment:

* A realistic environment is created with multiple sample deployments that simulate:
  * AI cluster workloads (traffic management),
  * East-West internal traffic (AI and RAG workflows),
  * Storage traffic (MinIO),
  * Global multi-cluster networking,
  * Low-latency, high-throughput services,
  * AI Workload Simulator (mimicking inference traffic).

All resources are deployed in the bigip-demo namespace.

### Validation:

* The validator script sends synthetic TS logs (with proper usecase and module settings) to the agent, triggering configuration updates and scaling decisions.
* This helps validate the entire end-to-end AI‑powered BIG‑IP management workflow.

## Usecases

### Dynamically offload crypto operations for optimal SSL/TLS processing

* SSL/TLS Offloading Design:
The AS3 declaration is built to configure an HTTPS virtual server with a specific static virtual IP and a dedicated pool for SSL offloading.
* AS3 Payload Details:
The AS3 JSON for use case 1 defines a Service_HTTPS that includes a serverTLS property pointing to a pre‑configured TLS profile. The pool (named "ssl_offload_pool") uses dynamic backend endpoints, ensuring that SSL/TLS traffic is offloaded to backend servers with lower crypto load.
* AI Integration:
The model predicts if crypto offloading is needed (based on attributes such as cryptoLoad or tmmCpu). If the prediction is "offload_crypto", the agent updates the BIG‑IP configuration accordingly.

### Steer traffic based on AI insights (e.g., load, security, SLA adherence)

* Traffic Steering Mechanism:
The PoC generates an AS3 payload that configures a Service_HTTP with a load balancing mode set to "least-connections".
* Real‑Time Data:
Dynamic backend endpoints are retrieved from Kubernetes services so that the BIG‑IP can steer traffic intelligently between available endpoints.
* AI Decision Making:
The model uses telemetry metrics (like connections performance) to predict if traffic should be steered differently. The agent then reflects this decision in the updated AS3 configuration.

### Ensure SLA enforcement by intelligently prioritizing traffic

* SLA Enforcement Strategy:
The AS3 declaration configures a virtual server that uses HTTP monitoring.
* Configuration Details:
The generated payload defines a pool ("sla_enforcement_pool") with a monitor (e.g., "http") to ensure only healthy endpoints receive traffic, thereby meeting SLA targets.
* AI Role:
The model assesses SLA-related metrics (e.g., system connections performance) and predicts whether to enforce SLA (prediction "enforce_sla"). The agent then updates the BIG‑IP configuration to prioritize traffic based on these predictions.

### Enable AI-driven ingress/egress routing for seamless multi-cluster connectivity

* Ingress/Egress Routing:
The AS3 payload configures a Service_HTTPS that uses a static virtual IP assigned to multi‑cluster routing.
* Dynamic Routing Pools:
The pool ("multicluster_pool") is populated with dynamic endpoints from across clusters. This allows BIG‑IP to route traffic seamlessly between clusters.
* AI‑Based Decisions:
The model analyzes metrics (such as throughput performance) to predict if a routing update is needed. The agent then updates the configuration so that routing across clusters is optimized.

### Auto-scale services based on demand patterns detected via AI

* Scaling Mechanism:
The AS3 declaration is used to update a pool ("autoscale_pool") that includes a connection limit, reflecting auto‑scaling decisions.
* Deployment Scaling:
The agent also scales the target Kubernetes deployment based on the model’s prediction ("scale_up" or "scale_down").
* AI Monitoring:
The model is trained on metrics such as throughput and connection counts. When a demand pattern is detected, the agent automatically updates both the BIG‑IP configuration and the Kubernetes deployment scaling.

### Improve service discovery & orchestration with AI-based network optimization

* Service Discovery:
The AS3 payload updates a pool ("service_discovery_pool") used for service discovery.
* Dynamic Member Updates:
The pool uses dynamic endpoints to ensure that the BIG‑IP always has the latest information about available services.
* AI‑Insights:
The model examines telemetry data (e.g., connection performance) to predict if service discovery needs to be adjusted. The agent then updates the BIG‑IP configuration to reflect the current state of services.

### Ensure service resilience with AI-powered cluster maintenance

* Resilience Configuration:
The AS3 payload configures a pool ("resilience_pool") with a defined minimum number of active members, ensuring service resilience.
* Monitoring and Maintenance:
The configuration includes monitors (e.g., "http") to continuously check endpoint health and maintain service availability.
* AI‑Based Prediction:
The model detects potential degradation (e.g., low throughput) and triggers predictions such as "maintain_cluster". The agent then adjusts BIG‑IP settings to enforce minimum active endpoints and maintain resilience.

## Code flow

### Model Service:

* Log generator (generate_logs.py) that creates synthetic telemetry logs (TS logs) for eight use cases across five modules (LTM, APM, ASM, SYSTEM, AFM).
* Training script (train_model.py) that loads synthetic logs, assigns labels based on usecase‑specific thresholds, extracts features, trains models (RandomForest for LTM, APM, SYSTEM, AFM and Q‑learning for ASM), and saves them.
* Flask-based model API (app.py) that exposes /predict (to return a prediction) and /retrain (to fine‑tune models using newly accumulated data).

### Agent Service:

* Flask‑based agent (agent.py) that receives TS logs from a validator, queries the model service for a prediction, dynamically retrieves current endpoints from a target Kubernetes Service, and then builds an AS3 JSON declaration that is usecase‑specific.
* Instead of posting directly to BIG‑IP, the agent updates a Kubernetes ConfigMap (monitored by F5 CIS) so that BIG‑IP is updated automatically.
* The agent also scales a target deployment via the Kubernetes API if needed and appends logs for retraining.

### Validator Script:

* A unified script (validator.py) that creates synthetic TS logs for any specified usecase (1–8) and module. This lets you simulate real-world traffic and validate the entire workflow.

### Test Environment (Kubernetes Manifests):

* We deploy a realistic, multi‑workload environment in our dedicated namespace (bigip-demo) with:
* An AI Cluster (simulating external AI workload traffic)
* An East‑West application (for internal AI/RAG workflows)
* A Storage service (using MinIO to simulate data storage traffic)
* A Multi‑Cluster service (global load balancing)
* A Low Latency application (performance‑optimized)
* An AI Workload Simulator (a Flask container simulating AI inference traffic)