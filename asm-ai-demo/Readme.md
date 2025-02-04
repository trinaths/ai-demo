## AI Intelligent F5 BIG-IP with Container Ingress Services (CIS)

This PoC demonstrates how BIG-IP can be enhanced with AI intelligence, using CIS as example.

This PoC proposes a self-learning AI-driven anomaly detection system that integrates with F5 BIG-IP and F5 CIS to dynamically detect and mitigate threats.

This innovative AI solution analyzes raw traffic logs, predicts malicious behaviour using machine learning models, and automatically updates F5 BIG-IP security policies via AS3 and CIS. 


![architecture](https://github.com/trinaths/ai-demo/tree/main/asm-ai-demo/diagram.png)


### PoC Architecture

* F5 BIG-IP Is deployed a router steering traffic to apps deployed in OpenShift 4.16.24 cluster configured with OVN-Kubernetes CNI.
* CIS v 2.19 is deployed in the cluster to manage the resources and update BIG-IP.
* BIG-IP is configured with WAF policy, iRule and Data groups to analyse incoming traffic and block the malicious IP addresses.
* Data is collected from BIG-IP. Eg: F5 Telemetry logs.
* AI Model preprocesses and feature classify the data. 
* AI Agent receives traffic logs data via /analyze API.
* * Preprocess incoming request data (converts categorical values, applies encoders). 
* * Uses above trained model to predict if traffic is malicious.
* * If malicious, update DataGroups in AS3 ConfigMap.
* CIS monitors AS3 ConfigMap changes and updates BIG-IP.
* After request processing, AI Agent stores the request log into local dataset so the AI Model can periodically retrain the model using the updated dataset.
* This helps is dynamic decision making when proper signatures are not in place to enforce WAF security.
* The Re-train process improves system decision making by
* * Learning new malicious attack patterns.
* * Immediate blacklisting 
* * Improve detection based on real-world traffic.
