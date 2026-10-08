#!/usr/bin/env bash
set -euo pipefail

echo "[ztbc] injecting server crash loop on orders/orders-api"
# hashicorp/http-echo exits on unknown flags; this creates a restart loop.
kubectl -n orders patch deploy/orders-api --type='json' -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/args","value":["-bad-flag"]}
]'

echo "[ztbc] waiting briefly for new ReplicaSet"
sleep 3
kubectl -n orders get pods -l app=orders-api -o wide

echo "[ztbc] crash mode injected. Expect restarts/CrashLoopBackOff on orders-api pod(s)."
