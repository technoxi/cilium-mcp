#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-cilium-mcp-lab}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="${ROOT}/manifests"

echo "[fixture] applying namespace + baseline workloads"
kubectl apply -f "${M}/00-namespace.yaml"
kubectl apply -f "${M}/10-apps.yaml"
kubectl apply -f "${M}/20-hpa.yaml"
kubectl apply -f "${M}/30-ingress.yaml"
kubectl apply -f "${M}/40-policy-allow.yaml"

echo "[fixture] waiting for deployments"
kubectl -n "${NS}" rollout status deploy/api --timeout=180s
kubectl -n "${NS}" rollout status deploy/frontend --timeout=180s
kubectl -n "${NS}" rollout status deploy/db --timeout=180s
kubectl -n "${NS}" rollout status deploy/test-client --timeout=180s

echo "[fixture] done"
kubectl -n "${NS}" get pods,svc,hpa,ingress
