#!/usr/bin/env bash
set -euo pipefail

echo "[saas-egress-block] internal service call"
kubectl -n saas-lab exec deploy/payment-worker -- sh -lc 'curl --max-time 2 -sS http://internal-api:8080/ || echo internal-failed'

echo "[saas-egress-block] external SaaS call"
kubectl -n saas-lab exec deploy/payment-worker -- sh -lc 'curl --max-time 3 -sS https://api.github.com >/dev/null && echo external-ok || echo external-blocked'
