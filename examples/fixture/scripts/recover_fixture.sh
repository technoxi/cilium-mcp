#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-cilium-mcp-lab}"

echo "[recover] restoring api image"
kubectl -n "${NS}" set image deploy/api api=hashicorp/http-echo:1.0

echo "[recover] removing deny policy if present"
kubectl -n "${NS}" delete ciliumnetworkpolicy deny-api-ingress --ignore-not-found

echo "[recover] waiting for api rollout"
kubectl -n "${NS}" rollout status deploy/api --timeout=180s

echo "[recover] done"
