# Scenario: Zero-Trust Broken Connectivity

**Namespaces**: `storefront` · `orders` · `infra`

A developer builds an e-commerce platform across three namespaces. They know zero-trust is the
right approach, apply `CiliumNetworkPolicy` objects with `ingressDeny`/`egressDeny` to lock down
every namespace — but they forget to write **any allow rules**.

Every pod is `Running`. Every `Service` has `Endpoints`. But every service call times out.

> **Note on Cilium deny semantics**: `ingressDeny`/`egressDeny` is explicit deny — it wins over
> allow rules and covers both same-namespace and cross-namespace traffic. The correct agent
> workflow is therefore **delete the broad deny → replace with targeted allow rules**, not simply
> "add allow rules on top."

---

## Architecture

```
  storefront ns                orders ns                  infra ns
  ┌─────────────────┐         ┌──────────────────┐       ┌────────────────────┐
  │ web-frontend    │──────▶  │ orders-api :8080 │       │ auth-service :8080 │
  │ (curl client)   │    ✗    │                  │  ✗    │                    │
  │                 │         │ orders-worker    │──────▶│ postgres-stub:5432 │
  │ catalog-api     │  ✗      │ (curl client)    │       │                    │
  │ :8080           │◀────────│                  │       └────────────────────┘
  └────────┬────────┘         └────────┬─────────┘               ▲  ▲
           │      ✗                    │      ✗                   │  │
           └───────────────────────────┴─────────────────────────┘  │
                  catalog-api & orders-api need auth-service ────────┘

All ✗ paths DROPPED by ingressDeny/egressDeny fromEntities: [cluster, world, host]
```

### Intended service graph

| Source | Destination | Port | Namespace hop |
|--------|-------------|------|---------------|
| `web-frontend` | `catalog-api` | 8080 | same (`storefront`) |
| `web-frontend` | `orders-api` | 8080 | cross (`storefront` → `orders`) |
| `web-frontend` | `auth-service` | 8080 | cross (`storefront` → `infra`) |
| `orders-worker` | `orders-api` | 8080 | same (`orders`) |
| `orders-worker` | `postgres-stub` | 5432 | cross (`orders` → `infra`) |
| `orders-api` | `auth-service` | 8080 | cross (`orders` → `infra`) |
| `catalog-api` | `auth-service` | 8080 | cross (`storefront` → `infra`) |
| All pods | kube-dns | 53 | system |

---

## Running the Scenario

### 1. Deploy

```bash
bash examples/scenarios/zero-trust-broken-connectivity/scripts/deploy.sh
```

### 2. Confirm the broken state

```bash
bash examples/scenarios/zero-trust-broken-connectivity/scripts/verify_broken.sh
```

Every curl should be **BLOCKED ✓** (internal + internet egress by default).

### 3. Run the AI agent

#### 🟢 Narrative prompt (recommended)

> All services in `storefront`, `orders`, and `infra` are running and healthy but no pod can
> reach any other. A `CiliumNetworkPolicy` with `ingressDeny`/`egressDeny` blocks all traffic
> in every namespace, but no allow rules were ever added.
>
> Please:
> 1. Fetch the existing policies with `investigate_policies` to understand the current deny setup.
> 2. Confirm dropped flows with `investigate_flow_query`.
> 3. Delete each broad `policy-set-a` policy with `act_delete_policy`.
> 4. Apply the minimum set of targeted `CiliumNetworkPolicy` allow rules that restore the
>    intended service graph while keeping zero-trust principles (only explicitly allowed traffic
>    passes). Use dry-run before applying live.

---

#### 🔵 Step-by-step tool prompts

```
# 1. Read the current policy state
investigate_policies  {"namespace": "storefront", "include_clusterwide": true}
investigate_policies  {"namespace": "orders"}
investigate_policies  {"namespace": "infra"}

# 2. Confirm what's being dropped
investigate_flow_query  {"namespace": "storefront", "since_minutes": 15, "limit": 200, "verdict": "DROPPED"}
investigate_flow_query  {"namespace": "orders",     "since_minutes": 15, "limit": 200, "verdict": "DROPPED"}

# 3. Understand the workloads
context_namespace_inventory  {"namespace": "storefront"}
context_namespace_inventory  {"namespace": "orders"}
context_namespace_inventory  {"namespace": "infra"}

# 4. Delete the broad deny policies (dry-run first)
act_delete_policy  {"namespace": "storefront", "policy": "policy-set-a", "dry_run": true}
act_delete_policy  {"namespace": "orders",     "policy": "policy-set-a", "dry_run": true}
act_delete_policy  {"namespace": "infra",      "policy": "policy-set-a", "dry_run": true}

act_delete_policy  {"namespace": "storefront", "policy": "policy-set-a", "dry_run": false}
act_delete_policy  {"namespace": "orders",     "policy": "policy-set-a", "dry_run": false}
act_delete_policy  {"namespace": "infra",      "policy": "policy-set-a", "dry_run": false}

# 5. Apply targeted allow rules (agent generates YAML per service path)
act_apply_policy  {"namespace": "<ns>", "policy_yaml": "<yaml>", "dry_run": true}
act_apply_policy  {"namespace": "<ns>", "policy_yaml": "<yaml>", "dry_run": false}
```

---

### 4. Generate continuous broken traffic for debugging

```bash
bash examples/scenarios/zero-trust-broken-connectivity/scripts/verify_broken.sh
```

This runs continuously and is meant to be kept running while the agent investigates.
Stop with `Ctrl+C`.

### 5. Teardown

```bash
bash examples/scenarios/zero-trust-broken-connectivity/scripts/teardown.sh
```

---

## What the Agent Should Produce

### Step A — Delete these policies

| Policy | Namespace |
|--------|-----------|
| `policy-set-a` | `storefront` |
| `policy-set-a` | `orders` |
| `policy-set-a` | `infra` |

### Step B — Apply these allow policies

| Policy name | Namespace | What it allows |
|---|---|---|
| `allow-dns-egress` | storefront, orders, infra | UDP+TCP/53 egress to kube-dns |
| `allow-web-frontend-egress` | storefront | Egress to `catalog-api:8080`, `orders-api.orders:8080`, `auth-service.infra:8080` |
| `allow-catalog-api-ingress` | storefront | Ingress from `web-frontend` on 8080 |
| `allow-catalog-api-egress` | storefront | Egress to `auth-service.infra:8080` |
| `allow-orders-api-ingress` | orders | Ingress from `web-frontend` (storefront) + `orders-worker` on 8080 |
| `allow-orders-api-egress` | orders | Egress to `auth-service.infra:8080` |
| `allow-orders-worker-egress` | orders | Egress to `orders-api:8080`, `postgres-stub.infra:5432` |
| `allow-auth-service-ingress` | infra | Ingress from `catalog-api` + `orders-api` + `orders-worker` on 8080 |
| `allow-postgres-stub-ingress` | infra | Ingress from `orders-worker` on 5432 |

---

## Why delete-then-replace (not add-on-top)?

Cilium's `ingressDeny`/`egressDeny` has **higher precedence than allow rules** — you cannot
override an explicit deny with a `fromEndpoints` allow in the same policy set. The correct
remediation workflow is to **remove the broad deny and replace it with a minimal allow set**,
which is also the right operational pattern in a real zero-trust migration.

---

## Policy Set B Is Enabled By Default

The scenario now applies policy-set-b during `deploy.sh`.
No separate inject step is required.

- Internal traffic behavior is influenced by `policy-set-a`.
- Additional traffic behavior is influenced by `policy-set-b`.

### Suggested agent prompt

> In the zero-trust lab, both internal service traffic and internet egress are failing by default.
> Investigate policy misconfiguration, identify deny rules causing impact, and provide safest recovery steps with evidence and confidence.


## One-Click Debug Prompt (Use While `verify_broken.sh` Is Running)

Copy/paste this to your agent:

```text
`verify_broken.sh` is running continuously and generating failing traffic for this scenario.
Please debug namespaces `storefront`, `orders`, and `infra` end-to-end.

What I need:
1) A short RCA with confidence score.
2) Exact policy objects currently causing blocked paths (namespace + policy name).
3) Safest recovery plan first, with dry-run commands before live changes.
4) Post-fix verification checklist (flows, pod health, and connectivity checks).

Constraints:
- Minimize blast radius.
- Do not apply broad allow-all rules.
- Prefer reversible, incremental changes.
```
