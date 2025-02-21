#!/bin/bash
# cleanup.sh - Deletes the entire demo namespace.

set -e
NAMESPACE="bigip-demo"
echo "Deleting all demo resources..."
kubectl delete namespace "$NAMESPACE" --force --grace-period=0
kubectl delete -f k8s/pvc.yaml
kubectl delete -f k8s/cis.yaml
echo "Cleanup complete."