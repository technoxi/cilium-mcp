#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="${ROOT}/manifests"

echo "[inject] applying deny policy customer-portal -> payments-api"
# Ensure a clean replace so changed manifest logic is always applied.
kubectl -n payments delete ciliumnetworkpolicy deny-customer-portal-to-payments-api --ignore-not-found
kubectl apply -f "${M}/90-failure-deny-customer-portal-to-payments-api.yaml"

echo "[inject] verifying policy validity"
kubectl -n payments get ciliumnetworkpolicy deny-customer-portal-to-payments-api
kubectl -n payments wait --for=jsonpath='{.status.conditions[0].status}'=True \
  ciliumnetworkpolicy/deny-customer-portal-to-payments-api --timeout=30s || true

echo "[inject] done"
