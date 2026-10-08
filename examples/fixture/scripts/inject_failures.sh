#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-cilium-mcp-lab}"
MODE="${1:-all}" # network | crashloop | all
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="${ROOT}/manifests"

inject_network() {
  echo "[inject] applying deny-api-ingress policy"
  kubectl apply -f "${M}/90-failure-deny-api-ingress.yaml"
}

inject_crashloop() {
  echo "[inject] setting bad image on api to induce pull failures"
  kubectl -n "${NS}" set image deploy/api api=hashicorp/http-echo:does-not-exist
}

case "${MODE}" in
  network) inject_network ;;
  crashloop) inject_crashloop ;;
  all)
    inject_network
    inject_crashloop
    ;;
  *)
    echo "usage: $0 [network|crashloop|all]"
    exit 1
    ;;
esac

echo "[inject] failure mode '${MODE}' applied"
