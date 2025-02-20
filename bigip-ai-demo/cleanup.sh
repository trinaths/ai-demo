#!/bin/bash
# cleanup.sh - Delete the dedicated namespace and all its resources

set -e  # Exit immediately if a command exits with a non-zero status.

NAMESPACE="bigip-demo"

echo "Deleting namespace '$NAMESPACE' and all its resources..."

kubectl delete namespace "$NAMESPACE"

echo "Cleanup complete: Namespace '$NAMESPACE' has been deleted."