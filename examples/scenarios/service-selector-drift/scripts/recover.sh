#!/usr/bin/env bash
set -euo pipefail

echo "[service-selector-drift] restoring correct selector"
kubectl -n selector-lab patch svc inventory-api --type merge -p '{"spec":{"selector":{"app":"inventory-api"}}}'
kubectl -n selector-lab get endpoints inventory-api
