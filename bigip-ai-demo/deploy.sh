#!/bin/bash
# deploy.sh - Builds Docker images and deploys the entire demo environment.
set -e
NAMESPACE="bigip-demo"
echo "Starting deployment in namespace: $NAMESPACE"
# Create namespace.
kubectl apply -f k8s/namespace.yaml
echo "Applying Kubernetes manifests to namespace $NAMESPACE..."
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/agent-service-rbac.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/model-service-deployment.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/agent-service-deployment.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/sample-deployment.yaml --namespace "$NAMESPACE"
#kubectl apply -f k8s/model-retrain-cron.yaml --namespace "$NAMESPACE"
kubectl apply -f k8s/cis.yaml
echo "Deployment complete. Listing pods in namespace $NAMESPACE:"
kubectl get pods --namespace "$NAMESPACE"