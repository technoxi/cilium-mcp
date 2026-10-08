#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="${ROOT}/manifests"

echo "[multins] applying namespaces + workloads + policies"
kubectl apply -f "${M}/00-namespaces.yaml"
kubectl apply -f "${M}/10-workloads.yaml"
kubectl apply -f "${M}/40-policies-baseline.yaml"
kubectl apply -f "${M}/50-policy-crossns-allow.yaml"
kubectl apply -f "${M}/60-policy-clusterwide.yaml"

echo "[multins] waiting for workloads"
kubectl -n customer rollout status deploy/profile-api --timeout=180s
kubectl -n customer rollout status deploy/customer-portal --timeout=180s
kubectl -n payments rollout status deploy/payments-api --timeout=180s
kubectl -n payments rollout status deploy/payments-worker --timeout=180s
kubectl -n shared rollout status deploy/shared-auth-api --timeout=180s

echo "[multins] done"
kubectl -n customer get pods,svc
kubectl -n payments get pods,svc
kubectl -n shared get pods,svc
