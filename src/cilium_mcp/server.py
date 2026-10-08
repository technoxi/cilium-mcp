from __future__ import annotations

import argparse
import inspect
import json
import os

from fastmcp import FastMCP

from cilium_mcp.adapters.cilium import CiliumAdapter
from cilium_mcp.adapters.kubernetes import KubernetesAdapter
from cilium_mcp.config import Settings
from cilium_mcp.tools_actions import (
    apply_policy,
    delete_policy,
    quarantine_workload,
    rollback_deployment,
    rollout_restart,
    scale_deployment,
)
from cilium_mcp.tools_context import (
    cluster_summary,
    incident_timeline,
    namespace_inventory,
    network_insights,
    rca_pack,
    workload_health,
)
from cilium_mcp.tools_investigate import (
    deployment_diagnostics,
    dns_path,
    events_query,
    flow_query,
    hpa_diagnostics,
    ingress_diagnostics,
    logs_query,
    policies,
)
from cilium_mcp.tools_investigate import pod as investigate_pod
from cilium_mcp.tools_investigate import policy_impact, service_path

settings = Settings.from_env()
k8s = KubernetesAdapter(kube_context=settings.kube_context, timeout_seconds=settings.default_timeout_seconds)
cilium = CiliumAdapter(timeout_seconds=settings.default_timeout_seconds)

mcp = FastMCP("cilium-mcp")


def _serialize(report) -> dict:
    return json.loads(report.model_dump_json(by_alias=True))


_NULL_NAMESPACE_LITERALS = {"", "null", "none", "nil", "undefined"}


def _normalize_namespace(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if normalized.lower() in _NULL_NAMESPACE_LITERALS:
        return None
    return normalized


def _normalize_namespace_or_default(value: str | None, default: str = "default") -> str:
    return _normalize_namespace(value) or default


if hasattr(mcp, "prompt"):

    @mcp.prompt(name="prompt_debug_live_connectivity")
    def prompt_debug_live_connectivity(
        namespaces: str = "storefront,orders,infra",
        incident_hint: str = (
            "Pods look healthy, but connectivity is failing while a test script is running"
        ),
    ) -> str:
        """Template prompt for live connectivity debugging with cilium-mcp tools."""
        return (
            "You are the on-call SRE for a live Kubernetes connectivity incident.\n\n"
            f"Namespaces in scope: {namespaces}\n"
            f"Hint: {incident_hint}\n\n"
            "Operate with strict closure criteria. Do NOT stop at partial recovery.\n"
            "Do NOT finish until every required path is validated as SUCCESS or you can prove why a path is not fixable.\n\n"
            "Required path matrix (must all become SUCCESS):\n"
            "- storefront->catalog-api\n"
            "- storefront->orders-api\n"
            "- storefront->auth-service\n"
            "- orders->orders-api\n"
            "- orders->postgres-stub\n"
            "- orders->auth-service\n"
            "- storefront->internet\n"
            "- orders->internet\n\n"
            "Execution plan (follow in order):\n"
            "1) Baseline context and health\n"
            "   - Run context_namespace_inventory for each namespace in scope.\n"
            "   - Run context_workload_health for each namespace.\n"
            "   - Record pod readiness/restarts and key services/endpoints.\n"
            "2) Holistic traffic sweep first\n"
            "   - Run ONE broad investigate_flow_query sweep for dropped/denied traffic across scope (5-15m window).\n"
            "   - Build top dropped-path summary: source, destination, port, verdict, count.\n"
            "3) Path-level drilldown\n"
            "   - For each failed path in the matrix, run focused investigate_flow_query and investigate_service_path.\n"
            "   - Confirm whether failure is DNS, service wiring, or policy-driven.\n"
            "4) Policy correlation\n"
            "   - Run investigate_policies per namespace.\n"
            "   - Map each failed path to concrete policy selector/rule evidence.\n"
            "   - Infer from live state only; do not assume hardcoded names.\n"
            "5) Fix loop (smallest safe change first)\n"
            "   - Propose minimal blast-radius fix per failed path.\n"
            "   - Use dry-run commands first, then live commands.\n"
            "   - Prefer targeted rule edits over blanket deletes; use deletion only if targeted change is not feasible.\n"
            "   - After each change, re-check the full 8-path matrix and continue until closure criteria are met.\n"
            "6) Final output format\n"
            "   - RCA summary with confidence score.\n"
            "   - Evidence table: dropped flow signal, service path signal, policy signal, workload signal.\n"
            "   - Action log: what changed and why (namespace + object + reason).\n"
            "   - Verification table: all 8 paths with final status.\n"
            "   - Residual risk and rollback command(s).\n\n"
            "Constraints:\n"
            "- Minimize blast radius.\n"
            "- Do not propose broad allow-all rules.\n"
            "- Prefer reversible, incremental changes.\n"
            "- Do not finish early with partial success.\n"
        )


@mcp.tool(name="context_cluster_summary")
def tool_cluster_summary(namespace: str | None = None) -> dict:
    namespace = _normalize_namespace(namespace)
    return _serialize(cluster_summary(k8s, namespace, settings.namespace_allowlist))


@mcp.tool(name="context_workload_health")
def tool_workload_health(namespace: str = "default", top_n: int = 10) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(workload_health(k8s, namespace, top_n, settings.namespace_allowlist))


@mcp.tool(name="context_namespace_inventory")
def tool_namespace_inventory(namespace: str = "default") -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(namespace_inventory(k8s, namespace, settings.namespace_allowlist))


@mcp.tool(name="context_network_insights")
def tool_network_insights(namespace: str = "default", since_minutes: int = 30, limit: int = 200) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(network_insights(cilium, namespace, since_minutes, limit, settings.namespace_allowlist))


@mcp.tool(name="context_incident_timeline")
def tool_incident_timeline(namespace: str, workload: str, since_minutes: int = 60) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(incident_timeline(k8s, cilium, namespace, workload, since_minutes, settings.namespace_allowlist))


@mcp.tool(name="context_rca_pack")
def tool_context_rca_pack(
    namespace: str,
    workload: str,
    since_minutes: int = 60,
    source_namespace: str | None = None,
) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    source_namespace = _normalize_namespace(source_namespace)
    return _serialize(
        rca_pack(
            k8s,
            cilium,
            namespace,
            workload,
            since_minutes,
            source_namespace,
            settings.namespace_allowlist,
        )
    )


@mcp.tool(name="investigate_pod")
def tool_investigate_pod(namespace: str, pod: str) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(investigate_pod(k8s, namespace, pod, settings.namespace_allowlist))


@mcp.tool(name="investigate_service_path")
def tool_investigate_service_path(
    namespace: str,
    source_workload: str,
    dest_service: str,
    dest_port: int,
) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        service_path(
            k8s=k8s,
            namespace=namespace,
            source_workload=source_workload,
            dest_service=dest_service,
            dest_port=dest_port,
            allowlist=settings.namespace_allowlist,
        )
    )


@mcp.tool(name="investigate_policy_impact")
def tool_investigate_policy_impact(
    namespace: str,
    source_labels: dict[str, str],
    dest_labels: dict[str, str],
    dest_port: int,
    protocol: str = "TCP",
) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        policy_impact(
            k8s=k8s,
            cilium=cilium,
            namespace=namespace,
            source_labels=source_labels,
            dest_labels=dest_labels,
            dest_port=dest_port,
            protocol=protocol,
            allowlist=settings.namespace_allowlist,
        )
    )


@mcp.tool(name="act_rollout_restart")
def tool_act_rollout_restart(
    namespace: str,
    deployment: str,
    dry_run: bool = True,
    approval_message: str | None = None,
) -> dict:
    """Restart a deployment to apply configuration changes.

    Args:
        namespace: The target namespace.
        deployment: The name of the deployment to restart.
        dry_run: If True (default), simulates the change. If False, restarts it live.
        approval_message: REQUIRED when dry_run=False. DO NOT GUESS THIS MESSAGE.
            DO NOT reuse a previous approval message. For EVERY single live action,
            you MUST explicitly ask the user for a new approval message before
            attempting to run this tool with dry_run=False. When they reply, copy their
            EXACT new message word-for-word into this field.
    """
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        rollout_restart(
            k8s=k8s,
            namespace=namespace,
            deployment=deployment,
            dry_run=dry_run,
            approval_message=approval_message,
            expected_approval_message=settings.approval_message,
            allowlist=settings.namespace_allowlist,
            audit_log_path=settings.audit_log_path,
        )
    )


@mcp.tool(name="act_scale")
def tool_act_scale(
    namespace: str,
    deployment: str,
    replicas: int,
    dry_run: bool = True,
    approval_message: str | None = None,
) -> dict:
    """Scale a deployment to a specified number of replicas.

    Args:
        namespace: The target namespace.
        deployment: The name of the deployment to scale.
        replicas: The desired number of replicas.
        dry_run: If True (default), simulates the change. If False, scales it live.
        approval_message: REQUIRED when dry_run=False. DO NOT GUESS THIS MESSAGE.
            DO NOT reuse a previous approval message. For EVERY single live action,
            you MUST explicitly ask the user for a new approval message before
            attempting to run this tool with dry_run=False. When they reply, copy their
            EXACT new message word-for-word into this field.
    """
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        scale_deployment(
            k8s=k8s,
            namespace=namespace,
            deployment=deployment,
            replicas=replicas,
            dry_run=dry_run,
            approval_message=approval_message,
            expected_approval_message=settings.approval_message,
            allowlist=settings.namespace_allowlist,
            max_scale_delta=settings.max_scale_delta,
            audit_log_path=settings.audit_log_path,
        )
    )


@mcp.tool(name="act_rollback")
def tool_act_rollback(
    namespace: str,
    deployment: str,
    dry_run: bool = True,
    approval_message: str | None = None,
) -> dict:
    """Rollback a deployment to its previous revision.

    Args:
        namespace: The target namespace.
        deployment: The name of the deployment to rollback.
        dry_run: If True (default), simulates the change. If False, rolls it back live.
        approval_message: REQUIRED when dry_run=False. DO NOT GUESS THIS MESSAGE.
            DO NOT reuse a previous approval message. For EVERY single live action,
            you MUST explicitly ask the user for a new approval message before
            attempting to run this tool with dry_run=False. When they reply, copy their
            EXACT new message word-for-word into this field.
    """
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        rollback_deployment(
            k8s=k8s,
            namespace=namespace,
            deployment=deployment,
            dry_run=dry_run,
            approval_message=approval_message,
            expected_approval_message=settings.approval_message,
            allowlist=settings.namespace_allowlist,
            audit_log_path=settings.audit_log_path,
        )
    )


@mcp.tool(name="act_apply_policy")
def tool_act_apply_policy(
    namespace: str,
    policy_yaml: str,
    dry_run: bool = True,
    approval_message: str | None = None,
) -> dict:
    """Apply a CiliumNetworkPolicy manifest to the cluster.

    Args:
        namespace: The target namespace.
        policy_yaml: The raw YAML string of the policy to apply.
        dry_run: If True (default), simulates the change. If False, applies it live.
        approval_message: REQUIRED when dry_run=False. DO NOT GUESS THIS MESSAGE.
            DO NOT reuse a previous approval message. For EVERY single live action,
            you MUST explicitly ask the user for a new approval message before
            attempting to run this tool with dry_run=False. When they reply, copy their
            EXACT new message word-for-word into this field.
    """
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        apply_policy(
            k8s=k8s,
            namespace=namespace,
            policy_yaml=policy_yaml,
            dry_run=dry_run,
            approval_message=approval_message,
            expected_approval_message=settings.approval_message,
            allowlist=settings.namespace_allowlist,
            audit_log_path=settings.audit_log_path,
        )
    )


@mcp.tool(name="act_quarantine_workload")
def tool_act_quarantine_workload(
    namespace: str,
    pod: str,
    dry_run: bool = True,
    approval_message: str | None = None,
) -> dict:
    """Quarantine a pod using a security label, isolating it via network policies.

    Args:
        namespace: The target namespace.
        pod: The name of the pod to quarantine.
        dry_run: If True (default), simulates the change. If False, quarantines it live.
        approval_message: REQUIRED when dry_run=False. DO NOT GUESS THIS MESSAGE.
            DO NOT reuse a previous approval message. For EVERY single live action,
            you MUST explicitly ask the user for a new approval message before
            attempting to run this tool with dry_run=False. When they reply, copy their
            EXACT new message word-for-word into this field.
    """
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        quarantine_workload(
            k8s=k8s,
            namespace=namespace,
            pod=pod,
            dry_run=dry_run,
            approval_message=approval_message,
            expected_approval_message=settings.approval_message,
            allowlist=settings.namespace_allowlist,
            audit_log_path=settings.audit_log_path,
        )
    )


@mcp.tool(name="act_delete_policy")
def tool_act_delete_policy(
    namespace: str,
    policy: str,
    dry_run: bool = True,
    approval_message: str | None = None,
) -> dict:
    """Delete a CiliumNetworkPolicy from the cluster.

    Args:
        namespace: The target namespace.
        policy: The name of the policy to delete.
        dry_run: If True (default), simulates the change. If False, deletes it live.
        approval_message: REQUIRED when dry_run=False. DO NOT GUESS THIS MESSAGE.
            DO NOT reuse a previous approval message. For EVERY single live action,
            you MUST explicitly ask the user for a new approval message before
            attempting to run this tool with dry_run=False. When they reply, copy their
            EXACT new message word-for-word into this field.
    """
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(
        delete_policy(
            k8s=k8s,
            namespace=namespace,
            policy=policy,
            dry_run=dry_run,
            approval_message=approval_message,
            expected_approval_message=settings.approval_message,
            allowlist=settings.namespace_allowlist,
            audit_log_path=settings.audit_log_path,
        )
    )


@mcp.tool(name="investigate_logs_query")
def tool_investigate_logs_query(
    namespace: str,
    pod: str,
    tail: int = 200,
    contains: str | None = None,
) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(logs_query(k8s, namespace, pod, tail, contains, settings.namespace_allowlist))


@mcp.tool(name="investigate_events_query")
def tool_investigate_events_query(
    namespace: str,
    contains: str | None = None,
    limit: int = 30,
) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(events_query(k8s, namespace, contains, limit, settings.namespace_allowlist))


@mcp.tool(name="investigate_flow_query")
def tool_investigate_flow_query(
    namespace: str,
    since_minutes: int = 30,
    limit: int = 100,
    source_namespace: str | None = None,
    dest_namespace: str | None = None,
    source_pod: str | None = None,
    dest_pod: str | None = None,
    verdict: str | None = None,
    port: int | None = None,
) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    source_namespace = _normalize_namespace(source_namespace)
    dest_namespace = _normalize_namespace(dest_namespace)
    return _serialize(
        flow_query(
            cilium=cilium,
            namespace=namespace,
            since_minutes=since_minutes,
            limit=limit,
            source_namespace=source_namespace,
            dest_namespace=dest_namespace,
            source_pod=source_pod,
            dest_pod=dest_pod,
            verdict=verdict,
            port=port,
            allowlist=settings.namespace_allowlist,
        )
    )


@mcp.tool(name="investigate_deployment")
def tool_investigate_deployment(namespace: str, deployment: str | None = None) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(deployment_diagnostics(k8s, namespace, deployment, settings.namespace_allowlist))


@mcp.tool(name="investigate_hpa")
def tool_investigate_hpa(namespace: str) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(hpa_diagnostics(k8s, namespace, settings.namespace_allowlist))


@mcp.tool(name="investigate_ingress")
def tool_investigate_ingress(namespace: str) -> dict:
    namespace = _normalize_namespace_or_default(namespace)
    return _serialize(ingress_diagnostics(k8s, namespace, settings.namespace_allowlist))


@mcp.tool(name="investigate_dns_path")
def tool_investigate_dns_path() -> dict:
    return _serialize(dns_path(k8s, settings.namespace_allowlist))


@mcp.tool(name="investigate_policies")
def tool_investigate_policies(
    namespace: str = "default",
    policy_name: str | None = None,
    include_clusterwide: bool = True,
) -> dict:
    """Fetch the full spec of CiliumNetworkPolicies in a namespace.

    Args:
        namespace: Namespace to inspect.
        policy_name: Optional — fetch a single named policy instead of all policies.
        include_clusterwide: When True (default), also return
            CiliumClusterwideNetworkPolicies that may affect this namespace.
    """
    ns = _normalize_namespace_or_default(namespace)
    return _serialize(
        policies(
            k8s=k8s,
            namespace=ns,
            policy_name=policy_name,
            include_clusterwide=include_clusterwide,
            allowlist=settings.namespace_allowlist,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run cilium-mcp server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=os.getenv("CILIUM_MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=os.getenv("CILIUM_MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CILIUM_MCP_PORT", "8000")))
    parser.add_argument("--path", default=os.getenv("CILIUM_MCP_PATH", "/mcp"))
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
        return

    # FastMCP run() signatures differ across versions; pass only supported kwargs.
    run_signature = inspect.signature(mcp.run)
    accepted = set(run_signature.parameters.keys())
    kwargs: dict[str, object] = {}
    for key, value in {
        "transport": "http",
        "host": args.host,
        "port": args.port,
        "path": args.path,
        "stateless_http": True,
        "json_response": True,
    }.items():
        if key in accepted or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in run_signature.parameters.values()
        ):
            kwargs[key] = value

    if "transport" not in kwargs:
        raise RuntimeError(
            "Installed FastMCP version does not expose transport selection in mcp.run(). "
            "Use: fastmcp run src/cilium_mcp/server.py:mcp --transport http --host "
            f"{args.host} --port {args.port} --path {args.path}"
        )

    mcp.run(**kwargs)


if __name__ == "__main__":
    main()
