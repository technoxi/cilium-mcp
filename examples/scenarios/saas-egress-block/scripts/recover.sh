#!/usr/bin/env bash
set -euo pipefail

echo "[saas-egress-block] removing failure policy"
kubectl -n saas-lab delete ciliumnetworkpolicy deny-world-egress --ignore-not-found
