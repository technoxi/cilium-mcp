#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-cilium-mcp-lab}"
ITERATIONS="${ITERATIONS:-40}"

echo "[traffic] generating API and frontend requests (${ITERATIONS} iterations)"
kubectl -n "${NS}" exec deploy/test-client -- sh -lc '
for i in $(seq 1 '"${ITERATIONS}"'); do
  curl --max-time 2 -sS http://api:8080/ >/dev/null || true
  curl --max-time 2 -sS http://frontend:8080/ >/dev/null || true
  sleep 0.3
done
'

echo "[traffic] done"
