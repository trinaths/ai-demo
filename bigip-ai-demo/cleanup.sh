#!/bin/bash
# cleanup.sh - Deletes the entire demo namespace.

set -e
NAMESPACE="bigip-demo"
echo "Deleting namespace '$NAMESPACE' and all its resources..."
kubectl delete namespace "$NAMESPACE"
kubectl delete -f k8s/cis.yaml
echo "Cleanup complete."