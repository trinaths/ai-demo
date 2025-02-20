#!/bin/bash
# deploy.sh - Build Docker images and deploy the entire system to Kubernetes in a dedicated namespace

set -e  # Exit immediately if a command exits with a non-zero status.

# Variables (customize these as needed)
DOCKER_REGISTRY="docker-registry"   
NAMESPACE="bigip-demo"
MODEL_SERVICE_IMAGE="$DOCKER_REGISTRY/model-service:latest"
AGENT_SERVICE_IMAGE="$DOCKER_REGISTRY/agent-service:latest"

echo "Starting deployment process in namespace: $NAMESPACE"

# --- Create Namespace ---
echo "Creating namespace '$NAMESPACE' if it doesn't exist..."
kubectl apply -f k8s/namespace.yaml

# --- Build and push Model Service Docker image ---
echo "Building Model Service Docker image..."
cd model
docker build -t "$MODEL_SERVICE_IMAGE" .
echo "Pushing Model Service image to registry..."
docker push "$MODEL_SERVICE_IMAGE"
cd ..

# --- Build and push Agent Service Docker image ---
echo "Building Agent Service Docker image..."
cd agent
docker build -t "$AGENT_SERVICE_IMAGE" .
echo "Pushing Agent Service image to registry..."
docker push "$AGENT_SERVICE_IMAGE"
cd ..

# --- Deploy Kubernetes manifests in the target namespace ---

echo "Applying Kubernetes manifests to namespace '$NAMESPACE'..."

# Apply PVCs (model and training storage)
kubectl apply -f k8s/pvc.yaml --namespace "$NAMESPACE"

# Apply RBAC for the Agent Service
kubectl apply -f k8s/agent-service-rbac.yaml --namespace "$NAMESPACE"

# Deploy the Model Service
kubectl apply -f k8s/model-service-deployment.yaml --namespace "$NAMESPACE"

# Deploy the Agent Service
kubectl apply -f k8s/agent-service-deployment.yaml --namespace "$NAMESPACE"

# Deploy the sample workload (to be scaled by the agent)
kubectl apply -f k8s/sample-deployment.yaml --namespace "$NAMESPACE"

# Deploy the retraining CronJob
kubectl apply -f k8s/model-retrain-cron.yaml --namespace "$NAMESPACE"

echo "Kubernetes manifests applied successfully in namespace '$NAMESPACE'."
echo "Checking deployment status in namespace '$NAMESPACE'..."

# List all pods in the namespace to verify deployment
kubectl get pods --namespace "$NAMESPACE"

echo "Deployment complete."