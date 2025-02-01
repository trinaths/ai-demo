#!/bin/bash
cd k8s
kubectl delete -f cron.yaml -f model.yaml -f agent.yaml -f as3cm.yaml -f cis.yaml -f rbac.yaml -f pvc.yaml 
kubectl delete secret bigip-login -n kube-system
kubectl delete secret kubeconfig-secret -n ai-workloads
kubectl delete ns ai-workloads
rm -rf /mnt/data
cd -