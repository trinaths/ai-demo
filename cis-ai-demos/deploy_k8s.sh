#!/usr/bin/bash
kubectl create ns ai-workloads
kubectl create secret generic bigip-login  -n kube-system --from-literal=username=admin  --from-literal=password=admin
kubectl create secret generic ai-agent-kubeconfig --from-file=kubeconfig=$HOME/.kube/config -n ai-workloads
kubectl apply -f ai-agent-role.yaml -f cis-deployment.yaml -f as3_configmap.yaml -f ai_model_deploy.yaml -f ai_agent_deploy.yaml