#!/usr/bin/env bash
set -euo pipefail

ITERATIONS="${ITERATIONS:-30}"

echo "[multins-traffic] customer -> payments + customer -> customer"
kubectl -n customer exec deploy/customer-portal -- sh -lc '
for i in $(seq 1 '"${ITERATIONS}"'); do
  curl --max-time 2 -sS http://payments-api.payments:8080/ >/dev/null || true
  curl --max-time 2 -sS http://profile-api.customer:8080/ >/dev/null || true
  sleep 0.3
done
'

echo "[multins-traffic] payments -> payments"
kubectl -n payments exec deploy/payments-worker -- sh -lc '
for i in $(seq 1 '"${ITERATIONS}"'); do
  curl --max-time 2 -sS http://payments-api.payments:8080/ >/dev/null || true
  sleep 0.3
done
'

echo "[multins-traffic] done"
