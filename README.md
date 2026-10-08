# cilium-mcp

MCP server starter for a **Kubernetes + Cilium context/action layer**.

## What this gives you
- Context-first tools to find high-signal issues quickly.
- Strict output schema with ranked findings, evidence, and reproducible commands.
- Kubernetes and Cilium/Hubble adapters (safe read-only defaults).
- Action tools with dry-run-first safety and audit logging.
- Fixture labs for realistic single-namespace and multi-namespace testing.

## Quickstart
```bash
cd /Users/snipextt/code/cilium-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cilium-mcp-server
```

## Run Modes
Stdio (default):
```bash
cilium-mcp-server
```

HTTP transport:
```bash
cilium-mcp-server --transport http --host 127.0.0.1 --port 8000 --path /mcp
```

## Action guardrails
```bash
# Optional: set token to require it for non-dry-run actions.
# If unset, token checks are disabled.
export CILIUM_MCP_APPROVAL_TOKEN='change-me'

# Maximum allowed absolute replica delta per act.scale call
export CILIUM_MCP_MAX_SCALE_DELTA=5

# JSONL audit trail for all successful action tool calls
export CILIUM_MCP_AUDIT_LOG_PATH='/tmp/cilium-mcp-audit.jsonl'
```

## Tool Families
Context:
- `context.cluster_summary`
- `context.workload_health`
- `context.namespace_inventory`
- `context.network_insights`
- `context.incident_timeline`
- `context.rca_pack`

Investigation:
- `investigate.pod`
- `investigate.service_path`
- `investigate.policy_impact`
- `investigate.logs_query`
- `investigate.events_query`
- `investigate.flow_query`
- `investigate.deployment`
- `investigate.hpa`
- `investigate.ingress`
- `investigate.dns_path`

Actions:
- `act.rollout_restart`
- `act.scale`
- `act.rollback`
- `act.apply_policy`
- `act.quarantine_workload`

## Fixture Labs
- Single-namespace fixture:
  - `/Users/snipextt/code/cilium-mcp/examples/fixture/README.md`
- Multi-namespace fixture:
  - `/Users/snipextt/code/cilium-mcp/examples/fixture-multins/README.md`

## Output Contract
All tools return a common report envelope:
- `executive_summary`
- `top_findings` (ranked by severity/confidence)
- `evidence`
- `causal_graph`
- `actions`
- `commands`
- `rollback_and_verification`
- `meta`

See `/Users/snipextt/code/cilium-mcp/docs/v1-spec.md` for full schema details.

## Local MCP HTTP Testing
Use this script to test MCP endpoints directly (without GUI client coupling):

```bash
cd /Users/snipextt/code/cilium-mcp
python3 scripts/mcp_cli_test.py --url http://127.0.0.1:8000/mcp list-tools
python3 scripts/mcp_cli_test.py --url http://127.0.0.1:8000/mcp call --tool context.namespace_inventory --args '{"namespace":"cilium-mcp-lab"}'
python3 scripts/mcp_cli_test.py --url http://127.0.0.1:8000/mcp call --tool context.rca_pack --args '{"namespace":"cilium-mcp-lab","workload":"api","since_minutes":5}'
```
