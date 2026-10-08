# Sample MCP Queries

- `context_cluster_summary` with `{"namespace":"default"}`
- `context_workload_health` with `{"namespace":"default","top_n":5}`
- `context_namespace_inventory` with `{"namespace":"cilium-mcp-lab"}`
- `context_namespace_inventory` with `{"namespace":"customer"}`
- `context_namespace_inventory` with `{"namespace":"payments"}`
- `context_network_insights` with `{"namespace":"default","since_minutes":20,"limit":100}`
- `context_incident_timeline` with `{"namespace":"default","workload":"api","since_minutes":90}`
- `context_rca_pack` with `{"namespace":"cilium-mcp-lab","workload":"api","since_minutes":30}`
- `context_rca_pack` with `{"namespace":"payments","workload":"payments-api","since_minutes":30,"source_namespace":"customer"}`
- `investigate_pod` with `{"namespace":"default","pod":"api-7bcbf"}`
- `investigate_service_path` with `{"namespace":"default","source_workload":"frontend","dest_service":"api","dest_port":8080}`
- `investigate_policy_impact` with `{"namespace":"default","source_labels":{"app":"frontend"},"dest_labels":{"app":"api"},"dest_port":8080,"protocol":"TCP"}`
- `investigate_policy_impact` with `{"namespace":"payments","source_labels":{"app":"customer-portal","io.kubernetes.pod.namespace":"customer"},"dest_labels":{"app":"payments-api"},"dest_port":8080,"protocol":"TCP"}`
- `investigate_logs_query` with `{"namespace":"default","pod":"api-7bcbf","tail":200,"contains":"error"}`
- `investigate_events_query` with `{"namespace":"default","contains":"Back-off","limit":25}`
- `investigate_flow_query` with `{"namespace":"default","since_minutes":30,"limit":100,"verdict":"DROPPED"}`
- `investigate_flow_query` with `{"namespace":"payments","since_minutes":10,"limit":200,"verdict":"DROPPED","source_namespace":"customer","dest_namespace":"payments"}`
- `investigate_deployment` with `{"namespace":"default","deployment":"api"}`
- `investigate_hpa` with `{"namespace":"default"}`
- `investigate_ingress` with `{"namespace":"default"}`
- `investigate_dns_path` with `{}`
- `act_rollback` with `{"namespace":"default","deployment":"api","dry_run":true}`
- `act_apply_policy` with `{"namespace":"default","policy_yaml":"apiVersion: cilium.io/v2\\nkind: CiliumNetworkPolicy\\nmetadata:\\n  name: sample\\nspec:\\n  endpointSelector: {}\\n","dry_run":true}`
- `act_quarantine_workload` with `{"namespace":"default","pod":"api-7bcbf","dry_run":true}`

# Scenario Prompts (New)

## saas-egress-block (namespace: saas-lab)
- "Investigate why payment-worker in saas-lab cannot reach external SaaS APIs in the last 15 minutes, and provide RCA with evidence and confidence. Confirm whether internal service traffic is still healthy."
- `context_namespace_inventory` with `{"namespace":"saas-lab"}`
- `investigate_flow_query` with `{"namespace":"saas-lab","since_minutes":15,"limit":200,"verdict":"DROPPED"}`
- `context_rca_pack` with `{"namespace":"saas-lab","workload":"payment-worker","since_minutes":15}`

## dns-egress-block (namespace: dns-lab)
- "Investigate DNS failures for frontend in dns-lab and determine whether this is policy-related DNS egress blocking or service-level failure."
- `context_namespace_inventory` with `{"namespace":"dns-lab"}`
- `investigate_flow_query` with `{"namespace":"dns-lab","since_minutes":15,"limit":200,"verdict":"DROPPED"}`
- `investigate_service_path` with `{"namespace":"dns-lab","source_workload":"frontend","dest_service":"api","dest_port":8080}`
- `context_rca_pack` with `{"namespace":"dns-lab","workload":"frontend","since_minutes":15}`

## service-selector-drift (namespace: selector-lab)
- "Investigate why clients in selector-lab cannot reach inventory-api even though pods look healthy. Check for service wiring and endpoint drift."
- `context_namespace_inventory` with `{"namespace":"selector-lab"}`
- `investigate_service_path` with `{"namespace":"selector-lab","source_workload":"loadgen","dest_service":"inventory-api","dest_port":8080}`
- `investigate_deployment` with `{"namespace":"selector-lab","deployment":"inventory-api"}`
- `context_rca_pack` with `{"namespace":"selector-lab","workload":"inventory-api","since_minutes":15}`
- `act_delete_policy` with `{"namespace":"payments","policy":"deny-customer-portal-to-payments-api","dry_run":true}`
