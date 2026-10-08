#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$ROOT/manifests"

echo "[dns-egress-block] deploying baseline"
kubectl apply -f "$M/00-namespace.yaml"
kubectl apply -f "$M/10-workloads.yaml"

kubectl -n dns-lab rollout status deploy/api --timeout=180s
kubectl -n dns-lab rollout status deploy/frontend --timeout=180s
kubectl -n dns-lab get pods,svc
