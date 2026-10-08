#!/usr/bin/env bash
set -euo pipefail

echo "[service-selector-drift] inventory service call"
kubectl -n selector-lab exec deploy/loadgen -- sh -lc 'curl --max-time 2 -sS http://inventory-api:8080/ || echo service-unreachable'
