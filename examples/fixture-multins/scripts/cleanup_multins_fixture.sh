#!/usr/bin/env bash
set -euo pipefail

echo "[cleanup] deleting multins namespaces"
kubectl delete ns customer payments shared --ignore-not-found

echo "[cleanup] deleting clusterwide policy"
kubectl delete ciliumclusterwidenetworkpolicy audit-cross-namespace-http --ignore-not-found
