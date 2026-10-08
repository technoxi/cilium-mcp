#!/usr/bin/env bash
set -euo pipefail

echo "[validate] customer-portal should reach payments-api"
kubectl -n customer exec deploy/customer-portal -- curl -sS --max-time 3 http://payments-api.payments.svc.cluster.local:8080/

echo "[validate] payments-worker should reach payments-api"
kubectl -n payments exec deploy/payments-worker -- curl -sS --max-time 3 http://payments-api.payments.svc.cluster.local:8080/

echo "[validate] ok"
