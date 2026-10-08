#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$ROOT/manifests"

echo "[dns-egress-block] injecting DNS deny"
kubectl apply -f "$M/90-failure-deny-dns-egress.yaml"
kubectl -n dns-lab get ciliumnetworkpolicy deny-frontend-dns
