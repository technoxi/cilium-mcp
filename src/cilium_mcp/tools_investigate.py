from __future__ import annotations

import json

from cilium_mcp.adapters.cilium import CiliumAdapter
from cilium_mcp.adapters.kubernetes import KubernetesAdapter
from cilium_mcp.formatting import ReportBuilder
from cilium_mcp.models.report import Action, Evidence, Finding, Report
from cilium_mcp.safety import check_namespace


def pod(k8s: KubernetesAdapter, namespace: str, pod: str, allowlist: set[str] | None) -> Report:
    rb = ReportBuilder("investigate.pod")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    pods_json, pods_res = k8s.get_pods(namespace)
    logs_res = k8s.get_pod_logs(namespace, pod)

    if not pods_res.ok:
        rb.degraded = True
        rb.executive_summary.append("failed to query pod state")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=pods_res.stderr))
        return rb.build()

    selected = None
    for item in pods_json.get("items", []):
        if item.get("metadata", {}).get("name") == pod:
            selected = item
            break

    if not selected:
        rb.degraded = True
        rb.executive_summary.append(f"pod {pod} not found")
        return rb.build()

    phase = selected.get("status", {}).get("phase", "Unknown")
    container_statuses = selected.get("status", {}).get("containerStatuses", [])
    restarts = sum(cs.get("restartCount", 0) for cs in container_statuses)

    rb.executive_summary = [f"Pod: {pod}", f"Phase: {phase}", f"Total restarts: {restarts}"]

    if phase != "Running" or restarts > 0:
        rb.findings.append(
            Finding(
                id=f"F-POD-{pod}",
                title="Pod health concerns detected",
                severity="high" if phase != "Running" else "medium",
                confidence=0.88,
                scope=f"namespace/{namespace}",
                impact=f"phase={phase}, restarts={restarts}",
            )
        )

    if logs_res.ok and logs_res.stdout:
        tail_line = logs_res.stdout.splitlines()[-1]
        rb.evidence.append(Evidence(type="log", timestamp="", source="kubectl logs", detail=tail_line))
    else:
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl logs", detail=logs_res.stderr))

    rb.actions.append(
        Action(
            priority="safe_now",
            title="Check related events and rollout state",
            expected_outcome="identify if issue is local pod vs deployment-wide",
            risk="low",
        )
    )
    rb.commands += [
        f"kubectl -n {namespace} describe pod {pod}",
        f"kubectl -n {namespace} logs {pod} --tail 200",
    ]
    rb.rollback_and_verification = [f"kubectl -n {namespace} get pod {pod}"]

    return rb.build()


def service_path(
    k8s: KubernetesAdapter,
    namespace: str,
    source_workload: str,
    dest_service: str,
    dest_port: int,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("investigate.service_path")
    rb.diagnostics["service_lookup"] = "unknown"
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    svc_json, svc_res = k8s.get_service(namespace, dest_service)
    if not svc_res.ok:
        rb.diagnostics["service_lookup"] = "missing"
        rb.degraded = True
        rb.executive_summary.append(f"service {dest_service} not found in namespace {namespace}")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=svc_res.stderr))
        rb.commands.append(f"kubectl -n {namespace} get svc")
        return rb.build()

    ep_json, ep_res = k8s.get_endpoints(namespace, dest_service)
    if not ep_res.ok:
        rb.diagnostics["service_lookup"] = "service_found_endpoints_failed"
        rb.degraded = True
        rb.executive_summary.append("failed to fetch service endpoints")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=ep_res.stderr))
        return rb.build()
    rb.diagnostics["service_lookup"] = "service_found"

    subsets = ep_json.get("subsets", [])
    addresses = sum(len(s.get("addresses", [])) for s in subsets)
    ports = [p.get("port") for s in subsets for p in s.get("ports", [])]

    rb.executive_summary = [
        f"Path check: {source_workload} -> {dest_service}:{dest_port}",
        f"Service type: {svc_json.get('spec', {}).get('type', 'ClusterIP')}",
        f"Resolved endpoint addresses: {addresses}",
        f"Advertised service ports: {ports if ports else 'none'}",
    ]

    if addresses == 0:
        rb.findings.append(
            Finding(
                id="F-SVC-NO-ENDPOINTS",
                title=f"Service {dest_service} has no ready endpoints",
                severity="high",
                confidence=0.95,
                scope=f"namespace/{namespace}",
                impact="traffic will fail regardless of network policy",
            )
        )

    if dest_port not in ports:
        rb.findings.append(
            Finding(
                id="F-SVC-PORT-MISMATCH",
                title="Destination port is not exposed by service endpoints",
                severity="medium",
                confidence=0.8,
                scope=f"namespace/{namespace}",
                impact="connection resets/timeouts possible",
            )
        )

    rb.actions.append(
        Action(
            priority="safe_now",
            title="Validate labels/selectors and endpoint readiness",
            expected_outcome="confirm service wiring",
            risk="low",
        )
    )
    rb.commands += [
        f"kubectl -n {namespace} get svc {dest_service} -o yaml",
        f"kubectl -n {namespace} get endpoints {dest_service} -o yaml",
    ]

    return rb.build()


def policy_impact(
    k8s: KubernetesAdapter,
    cilium: CiliumAdapter,
    namespace: str,
    source_labels: dict[str, str],
    dest_labels: dict[str, str],
    dest_port: int,
    protocol: str,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("investigate.policy_impact")
    rb.diagnostics["policy_source"] = "unknown"
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    policy_res = cilium.cilium_policy_get(namespace)
    policy_text = ""
    source_name = ""
    if policy_res.ok:
        policy_text = policy_res.stdout
        source_name = "cilium policy get"
        rb.diagnostics["policy_source"] = "cilium_cli"
    else:
        cnp_json, cnp_res = k8s.get_cilium_network_policies(namespace)
        ccnp_json, ccnp_res = k8s.get_cilium_clusterwide_policies()
        if cnp_res.ok or ccnp_res.ok:
            cnp_count = len(cnp_json.get("items", [])) if cnp_res.ok else 0
            ccnp_count = len(ccnp_json.get("items", [])) if ccnp_res.ok else 0
            policy_text = f"cnp={cnp_count}, ccnp={ccnp_count}"
            source_name = "kubectl cilium policy CRDs"
            rb.diagnostics["policy_fallback"] = "used CRD fallback because cilium CLI policy get failed"
            rb.diagnostics["policy_source"] = "k8s_crd_fallback"
        else:
            rb.degraded = True
            rb.executive_summary.append("unable to read cilium policies")
            rb.evidence.append(Evidence(type="event", timestamp="", source="cilium", detail=policy_res.stderr))
            rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=cnp_res.stderr))
            rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=ccnp_res.stderr))
            return rb.build()

    label_hint = f"src={source_labels}, dst={dest_labels}, {protocol}/{dest_port}"
    text = policy_text.lower()
    src_hits = sum(1 for k, v in source_labels.items() if f"{k}" in text and f"{v}".lower() in text)
    dst_hits = sum(1 for k, v in dest_labels.items() if f"{k}" in text and f"{v}".lower() in text)
    likely_restrictive = "deny" in text or "ingress" in text or "egress" in text
    selector_signal = min(1.0, (src_hits + dst_hits) / max(1, len(source_labels) + len(dest_labels)))
    confidence = min(0.95, 0.45 + (0.25 if likely_restrictive else 0.0) + (0.3 * selector_signal))
    rb.diagnostics["selector_signal"] = f"{selector_signal:.2f}"
    rb.diagnostics["policy_reasoning"] = (
        f"src_hits={src_hits},dst_hits={dst_hits},restrictive_markers={str(likely_restrictive).lower()}"
    )

    rb.executive_summary = [
        f"Evaluating policy impact for {label_hint}",
        "Heuristic analysis over current namespace policy set",
    ]

    rb.evidence.append(
        Evidence(
            type="config",
            timestamp="",
            source=source_name,
            detail=f"policy output length={len(policy_text)} chars",
        )
    )

    rb.findings.append(
        Finding(
            id="F-POLICY-IMPACT",
            title="Potential policy influence on requested flow",
            severity="medium" if likely_restrictive else "low",
            confidence=confidence,
            scope=f"namespace/{namespace}",
            impact="flow may be denied or constrained depending on selector matching",
        )
    )

    rb.actions.append(
        Action(
            priority="next",
            title="Replay flow with hubble observe and compare verdicts",
            expected_outcome="confirm effective policy behavior",
            risk="low",
        )
    )
    rb.commands += [
        f"cilium policy get --namespace {namespace}",
        f"hubble observe --namespace {namespace} --protocol {protocol.lower()} --port {dest_port}",
    ]

    return rb.build()


def logs_query(
    k8s: KubernetesAdapter,
    namespace: str,
    pod: str,
    tail: int,
    contains: str | None,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("investigate.logs_query")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    logs_res = k8s.get_pod_logs(namespace, pod, tail=tail)
    if not logs_res.ok:
        rb.degraded = True
        rb.executive_summary.append("failed to read pod logs")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl logs", detail=logs_res.stderr))
        return rb.build()

    lines = logs_res.stdout.splitlines()
    if contains:
        lines = [ln for ln in lines if contains.lower() in ln.lower()]
    sample = lines[-10:]

    rb.executive_summary = [
        f"log query pod={pod} namespace={namespace}",
        f"lines matched: {len(lines)}",
    ]
    for ln in sample:
        rb.evidence.append(Evidence(type="log", timestamp="", source="kubectl logs", detail=ln))
    rb.commands = [f"kubectl -n {namespace} logs {pod} --tail {tail}"]
    return rb.build()


def events_query(
    k8s: KubernetesAdapter,
    namespace: str,
    contains: str | None,
    limit: int,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("investigate.events_query")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    events_json, events_res = k8s.get_events(namespace)
    if not events_res.ok:
        rb.degraded = True
        rb.executive_summary.append("failed to read events")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=events_res.stderr))
        return rb.build()

    items = events_json.get("items", [])
    rows: list[dict] = []
    for ev in items:
        msg = ev.get("message", "")
        if contains and contains.lower() not in msg.lower():
            continue
        rows.append(ev)
    rows = rows[-limit:]

    rb.executive_summary = [f"events query namespace={namespace}", f"events matched: {len(rows)}"]
    for ev in rows:
        rb.evidence.append(
            Evidence(
                type="event",
                timestamp=ev.get("lastTimestamp", ""),
                source="kubectl events",
                detail=ev.get("message", ""),
            )
        )
    rb.commands = [f"kubectl -n {namespace} get events --sort-by=.lastTimestamp"]
    return rb.build()


def flow_query(
    cilium: CiliumAdapter,
    namespace: str,
    since_minutes: int,
    limit: int,
    source_namespace: str | None,
    dest_namespace: str | None,
    source_pod: str | None,
    dest_pod: str | None,
    verdict: str | None,
    port: int | None,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("investigate.flow_query")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    res = cilium.hubble_query(
        namespace=namespace,
        since_minutes=since_minutes,
        limit=limit,
        source_namespace=source_namespace,
        dest_namespace=dest_namespace,
        source_pod=source_pod,
        dest_pod=dest_pod,
        verdict=verdict,
        port=port,
    )
    if not res.ok:
        rb.degraded = True
        rb.executive_summary.append("hubble flow query failed")
        rb.evidence.append(Evidence(type="event", timestamp="", source="hubble", detail=res.stderr))
        return rb.build()

    flows = 0
    drops = 0
    telemetry_loss_events = 0
    skipped_empty_verdict = 0
    for line in res.stdout.splitlines()[-limit:]:
        if "EVENTS LOST" in line.upper():
            telemetry_loss_events += 1
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        flow = doc.get("flow", {}) if isinstance(doc.get("flow", {}), dict) else {}
        verdict = doc.get("verdict", "") or flow.get("verdict", "")
        summary = doc.get("summary", "") or flow.get("Summary", "") or flow.get("summary", "")
        if not verdict:
            skipped_empty_verdict += 1
            continue
        flows += 1
        if str(verdict).upper() == "DROPPED":
            drops += 1
        rb.evidence.append(
            Evidence(
                type="flow",
                timestamp="",
                source="hubble",
                detail=f"verdict={verdict} summary={summary}",
            )
        )

    rb.executive_summary = [
        f"flow query namespace={namespace} since={since_minutes}m",
        f"flows={flows}, dropped={drops}",
    ]
    if source_namespace or dest_namespace:
        rb.executive_summary.append(
            f"cross-namespace filter source={source_namespace or '*'} dest={dest_namespace or '*'}"
        )
    if telemetry_loss_events > 0:
        rb.executive_summary.append(f"telemetry loss notices: {telemetry_loss_events}")
        rb.diagnostics["telemetry_loss"] = "true"
    else:
        rb.diagnostics["telemetry_loss"] = "false"
    rb.diagnostics["skipped_empty_verdict_records"] = str(skipped_empty_verdict)
    rb.commands = [f"hubble observe --namespace {namespace} --since {since_minutes}m --last {limit}"]
    return rb.build()


def deployment_diagnostics(
    k8s: KubernetesAdapter,
    namespace: str,
    deployment: str | None,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("investigate.deployment")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    if deployment:
        dep_json, dep_res = k8s.get_deployment(namespace, deployment)
        if not dep_res.ok:
            rb.degraded = True
            rb.executive_summary.append(f"deployment/{deployment} not found")
            rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=dep_res.stderr))
            return rb.build()
        items = [dep_json]
    else:
        deps_json, deps_res = k8s.get_deployments(namespace)
        if not deps_res.ok:
            rb.degraded = True
            rb.executive_summary.append("failed to query deployments")
            rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=deps_res.stderr))
            return rb.build()
        items = deps_json.get("items", [])

    rb.executive_summary = [f"deployment diagnostics namespace={namespace}", f"deployments analyzed: {len(items)}"]
    for dep in items[:20]:
        name = dep.get("metadata", {}).get("name", "unknown")
        spec_repl = dep.get("spec", {}).get("replicas", 0)
        avail = dep.get("status", {}).get("availableReplicas", 0)
        rb.evidence.append(
            Evidence(type="metric", timestamp="", source="kubectl deploy", detail=f"{name} replicas {avail}/{spec_repl}")
        )
    return rb.build()


def hpa_diagnostics(k8s: KubernetesAdapter, namespace: str, allowlist: set[str] | None) -> Report:
    rb = ReportBuilder("investigate.hpa")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    hpa_json, hpa_res = k8s.get_hpas(namespace)
    if not hpa_res.ok:
        rb.degraded = True
        rb.executive_summary.append("failed to query hpa")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=hpa_res.stderr))
        return rb.build()

    items = hpa_json.get("items", [])
    rb.executive_summary = [f"hpa diagnostics namespace={namespace}", f"hpa count: {len(items)}"]
    for hpa in items:
        name = hpa.get("metadata", {}).get("name", "unknown")
        cur = hpa.get("status", {}).get("currentReplicas", 0)
        des = hpa.get("status", {}).get("desiredReplicas", 0)
        rb.evidence.append(Evidence(type="metric", timestamp="", source="kubectl hpa", detail=f"{name} current={cur} desired={des}"))
    return rb.build()


def ingress_diagnostics(k8s: KubernetesAdapter, namespace: str, allowlist: set[str] | None) -> Report:
    rb = ReportBuilder("investigate.ingress")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    ing_json, ing_res = k8s.get_ingresses(namespace)
    if not ing_res.ok:
        rb.degraded = True
        rb.executive_summary.append("failed to query ingresses")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=ing_res.stderr))
        return rb.build()

    items = ing_json.get("items", [])
    rb.executive_summary = [f"ingress diagnostics namespace={namespace}", f"ingress count: {len(items)}"]
    for ing in items:
        name = ing.get("metadata", {}).get("name", "unknown")
        rules = ing.get("spec", {}).get("rules", [])
        hosts = [r.get("host", "") for r in rules]
        rb.evidence.append(Evidence(type="config", timestamp="", source="kubectl ingress", detail=f"{name} hosts={hosts}"))
    return rb.build()


def dns_path(k8s: KubernetesAdapter, allowlist: set[str] | None) -> Report:
    rb = ReportBuilder("investigate.dns_path")
    # DNS service lives in kube-system; allow if no list, or if kube-system is explicitly listed.
    ns_decision = check_namespace("kube-system", allowlist)
    if not ns_decision.allowed and allowlist is not None:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    svc_json, svc_res = k8s.get_dns_service()
    if not svc_res.ok:
        rb.degraded = True
        rb.executive_summary.append("failed to query kube-dns service")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=svc_res.stderr))
        return rb.build()

    cluster_ip = svc_json.get("spec", {}).get("clusterIP", "")
    ports = [p.get("port") for p in svc_json.get("spec", {}).get("ports", [])]
    rb.executive_summary = ["dns path diagnostics", f"kube-dns clusterIP={cluster_ip} ports={ports}"]
    rb.evidence.append(Evidence(type="config", timestamp="", source="kubectl svc kube-dns", detail="dns service resolved"))
    rb.commands = ["kubectl -n kube-system get svc kube-dns -o yaml"]
    return rb.build()