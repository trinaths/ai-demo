#!/bin/bash
cd k8s
mkdir /mnt/data
cp model/collected_traffic.csv /mnt/data/
kubectl create ns ai-workloads
kubectl create secret generic kubeconfig-secret --from-file=kubeconfig=$HOME/.kube/config -n ai-workloads
kubectl create secret generic bigip-login  -n kube-system --from-literal=username=admin  --from-literal=password=admin
kubectl apply -f pvc.yaml -f rbac.yaml -f cis.yaml -f as3cm.yaml -f agent.yaml -f model.yaml -f cron.yaml
kubectl get svc,deploy,po -n ai-workloads
cd -