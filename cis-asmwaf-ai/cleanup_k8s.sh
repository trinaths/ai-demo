#!/usr/bin/bash
kubectl delete ns ai-workloads
kubectl delete -f ai-agent-role.yaml -f cis-deployment.yaml -f as3_configmap.yaml -f ai_model_deploy.yaml -f ai_agent_deploy.yaml
kubectl delete secret generic bigip-login  -n kube-system --from-literal=username=admin  --from-literal=password=admin
kubectl delete secret bigip-login  -n kube-system
kubectl delete secret ai-agent-kubeconfig -n ai-workloads