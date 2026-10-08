#!/usr/bin/env bash
# Single verification script: continuously generates broken traffic for debugging.
# Stop with Ctrl+C.
set -uo pipefail

FRONTEND=$(kubectl -n storefront get pod -l app=web-frontend -o jsonpath='{.items[0].metadata.name}')
WORKER=$(kubectl   -n orders    get pod -l app=orders-worker  -o jsonpath='{.items[0].metadata.name}')

attempt=0
blocked=0
opened=0

check_fail() {
  local ns="$1" pod="$2" url="$3" label="$4"
  if kubectl exec -n "$ns" "$pod" -- curl -sf --max-time 4 "$url" > /dev/null 2>&1; then
    echo "[$label] UNEXPECTED_SUCCESS"
    opened=$((opened+1))
  else
    echo "[$label] BLOCKED"
    blocked=$((blocked+1))
  fi
}

print_crash_signals() {
  echo "[crash-signals] workload restart snapshot"
  kubectl -n orders get pods -l app=orders-api \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount,READY:.status.containerStatuses[0].ready \
    2>/dev/null || true

  kubectl -n storefront get pods -l app=catalog-api \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount,READY:.status.containerStatuses[0].ready \
    2>/dev/null || true

  kubectl -n infra get pods -l app=auth-service \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount,READY:.status.containerStatuses[0].ready \
    2>/dev/null || true
}

cleanup() {
  echo ""
  echo "[ztbc] stopped. total_attempts=$attempt blocked=$blocked unexpected_open=$opened"
}
trap cleanup EXIT INT TERM

echo "[ztbc] continuous broken verification started (Ctrl+C to stop)"
echo "[ztbc] this continuously creates traffic for Hubble/MCP debugging"
echo "[ztbc] includes crash/restart visibility signals"

while true; do
  attempt=$((attempt+1))
  echo ""
  echo "=== cycle $attempt ==="

  # Internal service paths (should fail)
  check_fail storefront "$FRONTEND" "http://catalog-api.storefront:8080"  "storefront->catalog-api"
  check_fail storefront "$FRONTEND" "http://orders-api.orders:8080"       "storefront->orders-api"
  check_fail storefront "$FRONTEND" "http://auth-service.infra:8080"      "storefront->auth-service"
  check_fail orders "$WORKER" "http://orders-api.orders:8080"             "orders->orders-api"
  check_fail orders "$WORKER" "http://postgres-stub.infra:5432"           "orders->postgres-stub"
  check_fail orders "$WORKER" "http://auth-service.infra:8080"            "orders->auth-service"

  # Internet egress paths (should fail due to NAT misconfig simulation)
  check_fail storefront "$FRONTEND" "https://api.ipify.org"               "storefront->internet"
  check_fail orders "$WORKER" "https://api.ipify.org"                    "orders->internet"

  # Crash/restart debug signals for agent correlation
  print_crash_signals

  echo "[ztbc] running totals: blocked=$blocked unexpected_open=$opened"
  sleep 2
done
