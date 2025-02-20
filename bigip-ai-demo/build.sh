#!/bin/bash

DOCKER_REGISTRY="quay.io/trinathsquay" 
MODEL_SERVICE_IMAGE="$DOCKER_REGISTRY/model-service:latest"
AGENT_SERVICE_IMAGE="$DOCKER_REGISTRY/agent-service:latest"
AI_WORKLOAD_IMAGE="$DOCKER_REGISTRY/ai-workload-sim:latest"

# Build and push Model Service image.
cd model
docker build --no-cache  -t "$MODEL_SERVICE_IMAGE" .
docker push "$MODEL_SERVICE_IMAGE"
cd ..

# Build and push Agent Service image.
cd agent
docker build --no-cache  -t "$AGENT_SERVICE_IMAGE" .
docker push "$AGENT_SERVICE_IMAGE"
cd ..

# Build and push AI Workload Simulator image.
cd ai_workload_simulator
docker build --no-cache  -t "$AI_WORKLOAD_IMAGE" .
docker push "$AI_WORKLOAD_IMAGE"
cd ..