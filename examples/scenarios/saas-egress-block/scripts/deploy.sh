#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$ROOT/manifests"

echo "[saas-egress-block] deploying baseline"
kubectl apply -f "$M/00-namespace.yaml"
kubectl apply -f "$M/10-workloads.yaml"

kubectl -n saas-lab rollout status deploy/internal-api --timeout=180s
kubectl -n saas-lab rollout status deploy/payment-worker --timeout=180s
kubectl -n saas-lab get pods,svc
