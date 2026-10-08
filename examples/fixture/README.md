# cilium-mcp Fixture Lab

This fixture creates a realistic namespace for end-to-end MCP testing with:
- `frontend`, `api`, `db`, `test-client`
- HPA and ingress objects
- baseline Cilium policy
- repeatable failure injection and recovery scripts

## Deploy
```bash
cd /Users/snipextt/code/cilium-mcp/examples/fixture/scripts
./deploy_fixture.sh
```

## Generate traffic
```bash
./generate_traffic.sh
```

## Inject failures
```bash
# Network denial failure
./inject_failures.sh network

# Crashloop/image pull failure
./inject_failures.sh crashloop

# Both
./inject_failures.sh all
```

## Recover
```bash
./recover_fixture.sh
```

## Cleanup
```bash
./cleanup_fixture.sh
```

## Suggested MCP calls
- `context.workload_health` with `{"namespace":"cilium-mcp-lab","top_n":10}`
- `context.network_insights` with `{"namespace":"cilium-mcp-lab","since_minutes":30}`
- `context.rca_pack` with `{"namespace":"cilium-mcp-lab","workload":"api","since_minutes":30}`
- `investigate.flow_query` with `{"namespace":"cilium-mcp-lab","since_minutes":30,"verdict":"DROPPED"}`
