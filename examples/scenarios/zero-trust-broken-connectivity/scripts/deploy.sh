#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$ROOT/manifests"

echo "[ztbc] deploying namespaces"
kubectl apply -f "$M/00-namespaces.yaml"

echo "[ztbc] deploying workloads"
kubectl apply -f "$M/10-workloads.yaml"

echo "[ztbc] applying policy-set-a"
kubectl apply -f "$M/20-policy-set-a.yaml"

echo "[ztbc] applying policy-set-b"
kubectl apply -f "$M/30-policy-set-b.yaml"

echo "[ztbc] waiting for rollouts..."
kubectl -n storefront rollout status deploy/web-frontend  --timeout=180s
kubectl -n storefront rollout status deploy/catalog-api   --timeout=180s
kubectl -n orders    rollout status deploy/orders-api     --timeout=180s
kubectl -n orders    rollout status deploy/orders-worker  --timeout=180s
kubectl -n infra     rollout status deploy/auth-service   --timeout=180s
kubectl -n infra     rollout status deploy/postgres-stub  --timeout=180s

echo ""
echo "[ztbc] current pods:"
kubectl get pods -n storefront
kubectl get pods -n orders
kubectl get pods -n infra

echo ""
echo "[ztbc] active deny policies:"
kubectl get cnp -n storefront
kubectl get cnp -n orders
kubectl get cnp -n infra

echo ""
echo "[ztbc] scenario ready. Run verify_broken.sh to confirm connectivity is broken by default (including internet egress)."
