#!/usr/bin/env bash
set -euo pipefail

echo "[ztbc] recovering orders/orders-api from crash loop"
kubectl -n orders patch deploy/orders-api --type='json' -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/args","value":["-text=orders-ok","-listen=:8080"]}
]'

echo "[ztbc] waiting for rollout"
kubectl -n orders rollout status deploy/orders-api --timeout=180s
kubectl -n orders get pods -l app=orders-api

echo "[ztbc] recovery complete"
