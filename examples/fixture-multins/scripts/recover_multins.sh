#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="${ROOT}/manifests"

echo "[recover] removing deny policy"
kubectl -n payments delete ciliumnetworkpolicy deny-customer-portal-to-payments-api --ignore-not-found

echo "[recover] restoring allow policy"
kubectl apply -f "${M}/50-policy-crossns-allow.yaml"

echo "[recover] done"
