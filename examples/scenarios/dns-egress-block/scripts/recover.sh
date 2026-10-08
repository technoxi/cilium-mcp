#!/usr/bin/env bash
set -euo pipefail

echo "[dns-egress-block] removing failure policy"
kubectl -n dns-lab delete ciliumnetworkpolicy deny-frontend-dns --ignore-not-found
