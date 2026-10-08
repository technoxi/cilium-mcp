# Additional Real-World Scenarios

This folder contains three runnable incident scenarios for Cilium-MCP demos.

## 1) saas-egress-block
- Namespace: `saas-lab`
- Story: payment worker loses internet/SaaS egress while internal service still works.
- Failure: Cilium `egressDeny` to `world`.

Commands:
- `./scripts/deploy.sh`
- `./scripts/generate_traffic.sh`
- `./scripts/inject_failure.sh`
- `./scripts/generate_traffic.sh`
- `./scripts/recover.sh`

## 2) dns-egress-block
- Namespace: `dns-lab`
- Story: frontend cannot resolve internal service names after DNS egress block.
- Failure: deny TCP/UDP 53 to kube-dns for frontend.

Commands:
- `./scripts/deploy.sh`
- `./scripts/generate_traffic.sh`
- `./scripts/inject_failure.sh`
- `./scripts/generate_traffic.sh`
- `./scripts/recover.sh`

## 3) service-selector-drift
- Namespace: `selector-lab`
- Story: service exists, pods healthy, but selector drift causes zero endpoints.
- Failure: patch service selector to wrong label.

Commands:
- `./scripts/deploy.sh`
- `./scripts/generate_traffic.sh`
- `./scripts/inject_failure.sh`
- `./scripts/generate_traffic.sh`
- `./scripts/recover.sh`

## Suggested MCP prompts
- "Investigate why workload connectivity failed in namespace `<ns>` in last 15 minutes and produce RCA with evidence and confidence."
- "Confirm whether this is policy-related, DNS-related, or service wiring related."
