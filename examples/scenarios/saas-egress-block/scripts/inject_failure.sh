#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$ROOT/manifests"

echo "[saas-egress-block] injecting world egress deny"
kubectl apply -f "$M/90-failure-deny-world-egress.yaml"
kubectl -n saas-lab get ciliumnetworkpolicy deny-world-egress
