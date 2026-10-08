# cilium-mcp Multi-Namespace Fixture Lab

This fixture creates a cross-namespace policy lab for `team-a`, `team-b`, and `shared`.

## What it includes
- Namespaces: `team-a`, `team-b`, `shared`
- Workloads/services: `a-api`, `a-client`, `b-api`, `b-client`, `shared-api`
- Policies:
  - baseline namespace policies
  - cross-namespace allow (`team-a/a-client` -> `team-b/b-api:8080`)
  - clusterwide policy
  - failure injection deny policy

## Deploy
```bash
cd /Users/snipextt/code/cilium-mcp/examples/fixture-multins/scripts
./deploy_multins_fixture.sh
```

## Validate baseline connectivity
```bash
./validate_multins.sh
./generate_multins_traffic.sh
```

## Inject failure (cross-namespace deny)
```bash
./inject_multins_failures.sh
```

## Recover
```bash
./recover_multins.sh
```

## Cleanup
```bash
./cleanup_multins_fixture.sh
```

## Suggested MCP workflow
1. Discovery:
- `context.namespace_inventory {"namespace":"team-a"}`
- `context.namespace_inventory {"namespace":"team-b"}`

2. Baseline network:
- `context.network_insights {"namespace":"team-b","since_minutes":30}`
- `investigate.flow_query {"namespace":"team-b","since_minutes":30,"limit":100,"source_namespace":"team-a","dest_namespace":"team-b"}`

3. Policy reasoning:
- `investigate.policy_impact {"namespace":"team-b","source_labels":{"app":"a-client","io.kubernetes.pod.namespace":"team-a"},"dest_labels":{"app":"b-api"},"dest_port":8080,"protocol":"TCP"}`

4. RCA after failure injection:
- `context.rca_pack {"namespace":"team-b","workload":"b-api","since_minutes":30,"source_namespace":"team-a"}`
