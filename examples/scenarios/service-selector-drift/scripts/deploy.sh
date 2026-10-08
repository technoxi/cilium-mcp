#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$ROOT/manifests"

echo "[service-selector-drift] deploying baseline"
kubectl apply -f "$M/00-namespace.yaml"
kubectl apply -f "$M/10-workloads.yaml"

kubectl -n selector-lab rollout status deploy/inventory-api --timeout=180s
kubectl -n selector-lab rollout status deploy/loadgen --timeout=180s
kubectl -n selector-lab get pods,svc,endpoints
