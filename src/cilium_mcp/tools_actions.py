from __future__ import annotations

from cilium_mcp.adapters.kubernetes import KubernetesAdapter
from cilium_mcp.audit import write_audit_event
from cilium_mcp.formatting import ReportBuilder
from cilium_mcp.models.report import Action, Evidence, Finding, Report
from cilium_mcp.safety import (
    check_approval_token,
    check_dry_run_preview,
    check_namespace,
    mark_dry_run_preview,
)


def _action_key(name: str, namespace: str, deployment: str, extra: str = "") -> str:
    return f"{name}:{namespace}:{deployment}:{extra}"


def rollout_restart(
    k8s: KubernetesAdapter,
    namespace: str,
    deployment: str,
    dry_run: bool,
    approval_token: str | None,
    expected_approval_token: str | None,
    allowlist: set[str] | None,
    audit_log_path: str,
) -> Report:
    rb = ReportBuilder("act.rollout_restart")
    rb.diagnostics["write_action"] = "true"

    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    key = _action_key("rollout_restart", namespace, deployment)
    if dry_run:
        mark_dry_run_preview(key)
    else:
        preview_ok = check_dry_run_preview(key)
        if not preview_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(preview_ok.reason)
            return rb.build()

        token_ok = check_approval_token(approval_token, expected_approval_token)
        if not token_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(token_ok.reason)
            return rb.build()

    result = k8s.rollout_restart_deployment(namespace=namespace, deployment=deployment, dry_run=dry_run)
    rb.diagnostics["kubectl_exit_code"] = str(result.exit_code)
    if not result.ok:
        rb.degraded = True
        rb.executive_summary.append("rollout restart command failed")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=result.stderr))
        return rb.build()

    mode = "dry-run preview" if dry_run else "applied"
    rb.executive_summary = [f"rollout_restart {mode} for deployment/{deployment} in namespace/{namespace}"]
    rb.findings.append(
        Finding(
            id="F-ACT-ROLLOUT-RESTART",
            title="Deployment restart action executed",
            severity="low",
            confidence=0.95,
            scope=f"namespace/{namespace}",
            impact=f"restart request {mode}",
        )
    )
    rb.actions.append(
        Action(
            priority="safe_now",
            title="Check rollout status",
            expected_outcome="confirm pods become ready",
            risk="low",
        )
    )
    rb.commands = [
        f"kubectl -n {namespace} rollout status deployment/{deployment}",
        f"kubectl -n {namespace} get pods -l app={deployment}",
    ]
    rb.rollback_and_verification = [
        f"kubectl -n {namespace} rollout history deployment/{deployment}",
        f"kubectl -n {namespace} get pods",
    ]
    write_audit_event(
        audit_log_path,
        {
            "tool": "act.rollout_restart",
            "namespace": namespace,
            "deployment": deployment,
            "dry_run": dry_run,
            "success": True,
        },
    )
    return rb.build()


def scale_deployment(
    k8s: KubernetesAdapter,
    namespace: str,
    deployment: str,
    replicas: int,
    dry_run: bool,
    approval_token: str | None,
    expected_approval_token: str | None,
    allowlist: set[str] | None,
    max_scale_delta: int,
    audit_log_path: str,
) -> Report:
    rb = ReportBuilder("act.scale")
    rb.diagnostics["write_action"] = "true"

    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    dep_json, dep_res = k8s.get_deployment(namespace, deployment)
    if not dep_res.ok:
        rb.degraded = True
        rb.executive_summary.append(f"deployment/{deployment} not found")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=dep_res.stderr))
        return rb.build()

    current = int(dep_json.get("spec", {}).get("replicas", 0))
    delta = abs(replicas - current)
    rb.diagnostics["current_replicas"] = str(current)
    rb.diagnostics["requested_replicas"] = str(replicas)

    if delta > max_scale_delta:
        rb.degraded = True
        rb.executive_summary.append(
            f"scale delta {delta} exceeds guardrail max {max_scale_delta}; request blocked"
        )
        return rb.build()

    key = _action_key("scale", namespace, deployment, str(replicas))
    if dry_run:
        mark_dry_run_preview(key)
    else:
        preview_ok = check_dry_run_preview(key)
        if not preview_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(preview_ok.reason)
            return rb.build()

        token_ok = check_approval_token(approval_token, expected_approval_token)
        if not token_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(token_ok.reason)
            return rb.build()

    result = k8s.scale_deployment(
        namespace=namespace,
        deployment=deployment,
        replicas=replicas,
        dry_run=dry_run,
    )
    rb.diagnostics["kubectl_exit_code"] = str(result.exit_code)
    if not result.ok:
        rb.degraded = True
        rb.executive_summary.append("scale command failed")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=result.stderr))
        return rb.build()

    mode = "dry-run preview" if dry_run else "applied"
    rb.executive_summary = [
        f"scale {mode} for deployment/{deployment} in namespace/{namespace}",
        f"replicas: {current} -> {replicas}",
    ]
    rb.findings.append(
        Finding(
            id="F-ACT-SCALE",
            title="Deployment scale action executed",
            severity="low",
            confidence=0.95,
            scope=f"namespace/{namespace}",
            impact=f"replica target {replicas} ({mode})",
        )
    )
    rb.actions.append(
        Action(
            priority="safe_now",
            title="Verify desired/available replicas converge",
            expected_outcome="deployment reaches steady state",
            risk="low",
        )
    )
    rb.commands = [
        f"kubectl -n {namespace} get deploy {deployment}",
        f"kubectl -n {namespace} rollout status deployment/{deployment}",
    ]
    rb.rollback_and_verification = [
        f"kubectl -n {namespace} scale deployment/{deployment} --replicas={current}",
        f"kubectl -n {namespace} get deploy {deployment}",
    ]
    write_audit_event(
        audit_log_path,
        {
            "tool": "act.scale",
            "namespace": namespace,
            "deployment": deployment,
            "dry_run": dry_run,
            "replicas_before": current,
            "replicas_after": replicas,
            "success": True,
        },
    )
    return rb.build()


def rollback_deployment(
    k8s: KubernetesAdapter,
    namespace: str,
    deployment: str,
    dry_run: bool,
    approval_token: str | None,
    expected_approval_token: str | None,
    allowlist: set[str] | None,
    audit_log_path: str,
) -> Report:
    rb = ReportBuilder("act.rollback")
    rb.diagnostics["write_action"] = "true"

    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    key = _action_key("rollback", namespace, deployment)
    if dry_run:
        mark_dry_run_preview(key)
    else:
        preview_ok = check_dry_run_preview(key)
        if not preview_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(preview_ok.reason)
            return rb.build()
        token_ok = check_approval_token(approval_token, expected_approval_token)
        if not token_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(token_ok.reason)
            return rb.build()

    result = k8s.rollout_undo_deployment(namespace=namespace, deployment=deployment, dry_run=dry_run)
    rb.diagnostics["kubectl_exit_code"] = str(result.exit_code)
    if not result.ok:
        rb.degraded = True
        rb.executive_summary.append("rollback command failed")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=result.stderr))
        return rb.build()

    mode = "dry-run preview" if dry_run else "applied"
    rb.executive_summary = [f"rollback {mode} for deployment/{deployment} in namespace/{namespace}"]
    rb.findings.append(
        Finding(
            id="F-ACT-ROLLBACK",
            title="Deployment rollback action executed",
            severity="low",
            confidence=0.95,
            scope=f"namespace/{namespace}",
            impact=f"rollback request {mode}",
        )
    )
    rb.actions.append(
        Action(
            priority="safe_now",
            title="Verify revision health after rollback",
            expected_outcome="service recovers to previous known-good state",
            risk="low",
        )
    )
    rb.commands = [
        f"kubectl -n {namespace} rollout history deployment/{deployment}",
        f"kubectl -n {namespace} rollout status deployment/{deployment}",
    ]
    rb.rollback_and_verification = [f"kubectl -n {namespace} get deploy {deployment}"]
    write_audit_event(
        audit_log_path,
        {
            "tool": "act.rollback",
            "namespace": namespace,
            "deployment": deployment,
            "dry_run": dry_run,
            "success": True,
        },
    )
    return rb.build()


def apply_policy(
    k8s: KubernetesAdapter,
    namespace: str,
    policy_yaml: str,
    dry_run: bool,
    approval_token: str | None,
    expected_approval_token: str | None,
    allowlist: set[str] | None,
    audit_log_path: str,
) -> Report:
    rb = ReportBuilder("act.apply_policy")
    rb.diagnostics["write_action"] = "true"

    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    key = _action_key("apply_policy", namespace, "manifest", str(len(policy_yaml)))
    if dry_run:
        mark_dry_run_preview(key)
    else:
        preview_ok = check_dry_run_preview(key)
        if not preview_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(preview_ok.reason)
            return rb.build()
        token_ok = check_approval_token(approval_token, expected_approval_token)
        if not token_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(token_ok.reason)
            return rb.build()

    result = k8s.apply_manifest(namespace=namespace, manifest_yaml=policy_yaml, dry_run=dry_run)
    rb.diagnostics["kubectl_exit_code"] = str(result.exit_code)
    if not result.ok:
        rb.degraded = True
        rb.executive_summary.append("policy apply command failed")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=result.stderr))
        return rb.build()

    mode = "dry-run preview" if dry_run else "applied"
    rb.executive_summary = [f"policy manifest {mode} in namespace/{namespace}"]
    rb.findings.append(
        Finding(
            id="F-ACT-APPLY-POLICY",
            title="Policy apply action executed",
            severity="low",
            confidence=0.95,
            scope=f"namespace/{namespace}",
            impact=f"policy manifest {mode}",
        )
    )
    rb.commands = [f"kubectl -n {namespace} get ciliumnetworkpolicies.cilium.io"]
    rb.rollback_and_verification = [f"kubectl -n {namespace} get ciliumnetworkpolicies.cilium.io -o wide"]
    write_audit_event(
        audit_log_path,
        {
            "tool": "act.apply_policy",
            "namespace": namespace,
            "dry_run": dry_run,
            "manifest_size": len(policy_yaml),
            "success": True,
        },
    )
    return rb.build()


def quarantine_workload(
    k8s: KubernetesAdapter,
    namespace: str,
    pod: str,
    dry_run: bool,
    approval_token: str | None,
    expected_approval_token: str | None,
    allowlist: set[str] | None,
    audit_log_path: str,
) -> Report:
    rb = ReportBuilder("act.quarantine_workload")
    rb.diagnostics["write_action"] = "true"

    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    key = _action_key("quarantine", namespace, pod)
    if dry_run:
        mark_dry_run_preview(key)
    else:
        preview_ok = check_dry_run_preview(key)
        if not preview_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(preview_ok.reason)
            return rb.build()
        token_ok = check_approval_token(approval_token, expected_approval_token)
        if not token_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(token_ok.reason)
            return rb.build()

    result = k8s.label_pod(namespace=namespace, pod=pod, key="security.quarantine", value="true", dry_run=dry_run)
    rb.diagnostics["kubectl_exit_code"] = str(result.exit_code)
    if not result.ok:
        rb.degraded = True
        rb.executive_summary.append("quarantine label command failed")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=result.stderr))
        return rb.build()

    mode = "dry-run preview" if dry_run else "applied"
    rb.executive_summary = [f"quarantine label {mode} on pod/{pod} in namespace/{namespace}"]
    rb.findings.append(
        Finding(
            id="F-ACT-QUARANTINE",
            title="Quarantine label action executed",
            severity="medium",
            confidence=0.95,
            scope=f"namespace/{namespace}",
            impact=f"pod/{pod} tagged for quarantine workflows",
        )
    )
    rb.commands = [f"kubectl -n {namespace} get pod {pod} --show-labels"]
    rb.rollback_and_verification = [f"kubectl -n {namespace} label pod {pod} security.quarantine-"]
    write_audit_event(
        audit_log_path,
        {
            "tool": "act.quarantine_workload",
            "namespace": namespace,
            "pod": pod,
            "dry_run": dry_run,
            "success": True,
        },
    )
    return rb.build()


def delete_policy(
    k8s: KubernetesAdapter,
    namespace: str,
    policy: str,
    dry_run: bool,
    approval_token: str | None,
    expected_approval_token: str | None,
    allowlist: set[str] | None,
    audit_log_path: str,
) -> Report:
    rb = ReportBuilder("act.delete_policy")
    rb.diagnostics["write_action"] = "true"

    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    key = _action_key("delete_policy", namespace, policy)
    if dry_run:
        mark_dry_run_preview(key)
    else:
        preview_ok = check_dry_run_preview(key)
        if not preview_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(preview_ok.reason)
            return rb.build()
        token_ok = check_approval_token(approval_token, expected_approval_token)
        if not token_ok.allowed:
            rb.degraded = True
            rb.executive_summary.append(token_ok.reason)
            return rb.build()

    result = k8s.delete_cilium_network_policy(namespace=namespace, policy=policy, dry_run=dry_run)
    rb.diagnostics["kubectl_exit_code"] = str(result.exit_code)
    if not result.ok:
        rb.degraded = True
        rb.executive_summary.append("delete policy command failed")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=result.stderr))
        return rb.build()

    mode = "dry-run preview" if dry_run else "applied"
    rb.executive_summary = [
        f"delete policy {mode} for ciliumnetworkpolicy/{policy} in namespace/{namespace}"
    ]
    rb.findings.append(
        Finding(
            id="F-ACT-DELETE-POLICY",
            title="Policy delete action executed",
            severity="medium",
            confidence=0.95,
            scope=f"namespace/{namespace}",
            impact=f"ciliumnetworkpolicy/{policy} delete {mode}",
        )
    )
    rb.actions.append(
        Action(
            priority="safe_now",
            title="Verify effective policy set after deletion",
            expected_outcome="confirm intended traffic policy behavior",
            risk="low",
        )
    )
    rb.commands = [
        f"kubectl -n {namespace} get ciliumnetworkpolicies.cilium.io",
        f"hubble observe --namespace {namespace} --since 5m --last 50",
    ]
    rb.rollback_and_verification = [
        f"kubectl -n {namespace} get ciliumnetworkpolicies.cilium.io -o wide"
    ]
    write_audit_event(
        audit_log_path,
        {
            "tool": "act.delete_policy",
            "namespace": namespace,
            "policy": policy,
            "dry_run": dry_run,
            "success": True,
        },
    )
    return rb.build()
