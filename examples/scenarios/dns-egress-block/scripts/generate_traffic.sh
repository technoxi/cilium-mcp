#!/usr/bin/env bash
set -euo pipefail

echo "[dns-egress-block] service DNS call"
kubectl -n dns-lab exec deploy/frontend -- sh -lc 'curl --max-time 2 -sS http://api:8080/ || echo dns-or-connect-failed'

echo "[dns-egress-block] explicit FQDN call"
kubectl -n dns-lab exec deploy/frontend -- sh -lc 'curl --max-time 2 -sS http://api.dns-lab:8080/ || echo dns-failed'
