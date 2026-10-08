#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-cilium-mcp-lab}"

echo "[cleanup] deleting fixture namespace ${NS}"
kubectl delete ns "${NS}" --ignore-not-found
