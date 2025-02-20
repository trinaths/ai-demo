#!/bin/bash
# cleanup.sh - Deletes the entire demo namespace.

set -e
NAMESPACE="bigip-demo"
echo "Deleting all demo resources..."
kubectl delete -f k8s/model-service-deployment.yaml --namespace "$NAMESPACE"
kubectl delete -f k8s/agent-service-deployment.yaml --namespace "$NAMESPACE"
kubectl delete -f k8s/pvc.yaml --namespace "$NAMESPACE"
kubectl delete -f k8s/agent-service-rbac.yaml --namespace "$NAMESPACE"
kubectl delete -f k8s/sample-deployment.yaml --namespace "$NAMESPACE"
#kubectl apply -f k8s/model-retrain-cron.yaml --namespace "$NAMESPACE"
kubectl delete -f k8s/cis.yaml
echo "Cleanup complete."