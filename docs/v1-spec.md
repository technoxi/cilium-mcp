# v1 MCP Spec (Context Plane)

## Product Goal
Build a high-signal MCP context layer for Kubernetes + Cilium that helps operators find root causes quickly and safely.

## Non-Goals (v1)
- Autonomous write operations.
- Generic shell execution passthrough.

## Guardrails
- Read-only by default.
- Namespace allowlist support.
- Structured evidence with explicit confidence.
- Repro commands are suggestions, not auto-executed.

## Tool Contracts

### `context.cluster_summary`
Input:
- `namespace`: optional string

Output focus:
- Cluster inventory snapshot.
- Health totals (running/pending/crashloop/restarts).
- Basic anomaly highlights.

### `context.workload_health`
Input:
- `namespace`: string, default `default`
- `top_n`: integer, default `10`

Output focus:
- Ranked unhealthy workloads.
- Failure reasons + restart pressure.

### `context.network_insights`
Input:
- `namespace`: string, default `default`
- `since_minutes`: integer, default `30`
- `limit`: integer, default `200`

Output focus:
- Cilium/Hubble deny flows.
- DNS/L7 error signals.
- Top noisy source/destination pairs.

### `context.incident_timeline`
Input:
- `namespace`: string
- `workload`: string
- `since_minutes`: integer, default `60`

Output focus:
- Time-ordered event + log + flow evidence.
- Candidate causal chain.

### `investigate.pod`
Input:
- `namespace`: string
- `pod`: string

Output focus:
- Pod status, restart causes, events, recent logs.

### `investigate.service_path`
Input:
- `namespace`: string
- `source_workload`: string
- `dest_service`: string
- `dest_port`: integer

Output focus:
- Endpoints availability.
- Suspected policy or DNS/service routing blockers.

### `investigate.policy_impact`
Input:
- `namespace`: string
- `source_labels`: map[string]string
- `dest_labels`: map[string]string
- `dest_port`: integer
- `protocol`: string (TCP/UDP)

Output focus:
- Policy objects likely affecting the flow.
- Confidence-ranked allow/deny hypothesis.

## Unified Output Schema

```json
{
  "executive_summary": ["..."],
  "top_findings": [
    {
      "id": "F-001",
      "title": "CrashLoopBackOff in payments-api",
      "severity": "high",
      "confidence": 0.88,
      "scope": "namespace/payments",
      "impact": "checkout requests failing"
    }
  ],
  "evidence": [
    {
      "type": "event|log|flow|metric|config",
      "timestamp": "2026-02-14T19:10:00Z",
      "source": "kubectl events",
      "detail": "Back-off restarting failed container"
    }
  ],
  "causal_graph": [
    {"from": "config-change", "to": "pod-crash", "reason": "bad env var"}
  ],
  "actions": [
    {
      "priority": "safe_now|next",
      "title": "Rollback deployment",
      "expected_outcome": "stabilize pods",
      "risk": "low"
    }
  ],
  "commands": [
    "kubectl -n payments rollout undo deploy/payments-api"
  ],
  "rollback_and_verification": [
    "kubectl -n payments rollout status deploy/payments-api",
    "kubectl -n payments get pods"
  ],
  "meta": {
    "tool": "context.workload_health",
    "generated_at": "ISO-8601",
    "data_freshness_seconds": 12,
    "degraded": false
  }
}
```
