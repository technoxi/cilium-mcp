#!/usr/bin/env bash
set -euo pipefail

echo "[service-selector-drift] patching service selector to non-existent label"
kubectl -n selector-lab patch svc inventory-api --type merge -p '{"spec":{"selector":{"app":"inventory-api-v2"}}}'
kubectl -n selector-lab get svc inventory-api -o jsonpath='{.spec.selector}' && echo
kubectl -n selector-lab get endpoints inventory-api
