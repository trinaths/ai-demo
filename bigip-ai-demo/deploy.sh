#!/bin/bash
# deploy.sh - Builds Docker images and deploys the entire demo environment.

set -e

DOCKER_REGISTRY="quay.io/trinathsquay"  # Update with your registry.
NAMESPACE="bigip-demo"
MODEL_SERVICE_IMAGE="$DOCKER_REGISTRY/model-service:latest"
AGENT_SERVICE_IMAGE="$DOCKER_REGISTRY/agent-service:latest"
AI_WORKLOAD_IMAGE="$DOCKER_REGISTRY/ai-workload-sim:latest"

echo "Starting deployment in namespace: $NAMESPACE"

# Create namespace.
kubectl apply -f k8s/namespace.yaml

# Build and push Model Service image.
cd model
docker build -t "$MODEL_SERVICE_IMAGE" .
docker push "$MODEL_SERVICE_IMAGE"
cd ..

# Build and push Agent Service image.
cd agent
docker build -t "$AGENT_SERVICE_IMAGE" .
docker push "$AGENT_SERVICE_IMAGE"
cd ..

# Build and push AI Workload Simulator image.
cd ai_workload_simulator
docker build -t "$AI_WORKLOAD_IMAGE" .
docker push "$AI_WORKLOAD_IMAGE"
cd ..

echo "Applying Kubernetes manifests to namespace $NAMESPACE..."
kubectl apply -f k8s/pvc.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/agent_service-rbac.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/model_service-deployment.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/agent_service-deployment.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/sample-deployment-improved.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/model-retrain-cron.yaml --namespace "$NAMESPACE"

echo "Deployment complete. Listing pods in namespace $NAMESPACE:"
kubectl get pods --namespace "$NAMESPACE"