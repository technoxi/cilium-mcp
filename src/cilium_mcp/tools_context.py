from __future__ import annotations

import json
from collections import Counter

from cilium_mcp.adapters.cilium import CiliumAdapter
from cilium_mcp.adapters.kubernetes import KubernetesAdapter
from cilium_mcp.formatting import ReportBuilder
from cilium_mcp.models.report import Action, CausalEdge, Evidence, Finding, Report
from cilium_mcp.safety import check_namespace


def cluster_summary(k8s: KubernetesAdapter, namespace: str | None, allowlist: set[str] | None) -> Report:
    rb = ReportBuilder("context.cluster_summary")

    if namespace:
        ns_decision = check_namespace(namespace, allowlist)
        if not ns_decision.allowed:
            rb.degraded = True
            rb.executive_summary.append(ns_decision.reason)
            return rb.build()
        namespaces = [namespace]
    else:
        ns_json, ns_res = k8s.list_namespaces()
        if not ns_res.ok:
            rb.degraded = True
            rb.executive_summary.append("failed to list namespaces")
            rb.evidence.append(
                Evidence(type="event", timestamp="", source="kubectl", detail=ns_res.stderr or "unknown error")
            )
            return rb.build()
        namespaces = [i.get("metadata", {}).get("name", "") for i in ns_json.get("items", [])]

    total_pods = 0
    unhealthy = 0

    for ns in namespaces:
        if not ns:
            continue
        pods_json, pods_res = k8s.get_pods(ns)
        if not pods_res.ok:
            rb.degraded = True
            rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=pods_res.stderr))
            continue

        items = pods_json.get("items", [])
        total_pods += len(items)
        for p in items:
            phase = p.get("status", {}).get("phase", "Unknown")
            if phase not in ("Running", "Succeeded"):
                unhealthy += 1

    rb.executive_summary = [
        f"Analyzed namespaces: {len(namespaces)}",
        f"Total pods observed: {total_pods}",
        f"Unhealthy pod count: {unhealthy}",
    ]

    if unhealthy > 0:
        rb.findings.append(
            Finding(
                id="F-CLUSTER-UNHEALTHY-PODS",
                title="Detected unhealthy pods across analyzed namespaces",
                severity="high" if unhealthy > 5 else "medium",
                confidence=0.8,
                scope="cluster",
                impact="degraded service reliability",
            )
        )
        rb.actions.append(
            Action(
                priority="safe_now",
                title="Inspect failing pods and recent events",
                expected_outcome="isolate top failing workloads",
                risk="low",
            )
        )
        rb.commands += [
            "kubectl get pods -A",
            "kubectl get events -A --sort-by=.lastTimestamp",
        ]

    rb.rollback_and_verification = ["kubectl get pods -A"]
    return rb.build()


def namespace_inventory(k8s: KubernetesAdapter, namespace: str, allowlist: set[str] | None) -> Report:
    rb = ReportBuilder("context.namespace_inventory")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    pods_json, pods_res = k8s.get_pods(namespace)
    svc_json, svc_res = k8s.get_services(namespace)
    dep_json, dep_res = k8s.get_deployments(namespace)
    hpa_json, hpa_res = k8s.get_hpas(namespace)
    ing_json, ing_res = k8s.get_ingresses(namespace)
    cnp_json, cnp_res = k8s.get_cilium_network_policies(namespace)
    ccnp_json, ccnp_res = k8s.get_cilium_clusterwide_policies()

    results = [pods_res, svc_res, dep_res, hpa_res, ing_res, cnp_res, ccnp_res]
    if any(not r.ok for r in results):
        rb.degraded = True

    pods = [i.get("metadata", {}).get("name", "") for i in pods_json.get("items", [])]
    services = [i.get("metadata", {}).get("name", "") for i in svc_json.get("items", [])]
    deployments = [i.get("metadata", {}).get("name", "") for i in dep_json.get("items", [])]
    hpas = [i.get("metadata", {}).get("name", "") for i in hpa_json.get("items", [])]
    ingresses = [i.get("metadata", {}).get("name", "") for i in ing_json.get("items", [])]
    cnps = [i.get("metadata", {}).get("name", "") for i in cnp_json.get("items", [])]
    ccnps = [i.get("metadata", {}).get("name", "") for i in ccnp_json.get("items", [])]

    rb.executive_summary = [
        f"Namespace inventory for {namespace}",
        (
            f"pods={len(pods)}, services={len(services)}, deployments={len(deployments)}, "
            f"hpa={len(hpas)}, ingress={len(ingresses)}, cnp={len(cnps)}, ccnp={len(ccnps)}"
        ),
    ]
    rb.diagnostics["inventory_namespace"] = namespace

    rb.evidence.extend(
        [
            Evidence(type="config", timestamp="", source="kubectl pods", detail=f"pods: {pods}"),
            Evidence(type="config", timestamp="", source="kubectl services", detail=f"services: {services}"),
            Evidence(type="config", timestamp="", source="kubectl deployments", detail=f"deployments: {deployments}"),
            Evidence(type="config", timestamp="", source="kubectl hpa", detail=f"hpa: {hpas}"),
            Evidence(type="config", timestamp="", source="kubectl ingress", detail=f"ingress: {ingresses}"),
            Evidence(type="config", timestamp="", source="kubectl cnp", detail=f"cnp: {cnps}"),
            Evidence(type="config", timestamp="", source="kubectl ccnp", detail=f"ccnp: {ccnps}"),
        ]
    )

    for res, label in [
        (pods_res, "pods"),
        (svc_res, "services"),
        (dep_res, "deployments"),
        (hpa_res, "hpa"),
        (ing_res, "ingress"),
        (cnp_res, "cnp"),
        (ccnp_res, "ccnp"),
    ]:
        if not res.ok:
            rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=f"{label}: {res.stderr}"))

    rb.commands = [
        f"kubectl -n {namespace} get pods,svc,deploy,hpa,ingress",
        f"kubectl -n {namespace} get ciliumnetworkpolicies.cilium.io",
        "kubectl get ciliumclusterwidenetworkpolicies.cilium.io",
    ]
    return rb.build()


def workload_health(
    k8s: KubernetesAdapter,
    namespace: str,
    top_n: int,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("context.workload_health")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    pods_json, pods_res = k8s.get_pods(namespace)
    if not pods_res.ok:
        rb.degraded = True
        rb.executive_summary.append("failed to read pods")
        rb.evidence.append(Evidence(type="event", timestamp="", source="kubectl", detail=pods_res.stderr))
        return rb.build()

    findings: list[Finding] = []

    for item in pods_json.get("items", []):
        pod_name = item.get("metadata", {}).get("name", "unknown")
        status = item.get("status", {})
        phase = status.get("phase", "Unknown")
        container_statuses = status.get("containerStatuses", [])
        restarts = sum(cs.get("restartCount", 0) for cs in container_statuses)

        waiting_reasons = [
            cs.get("state", {}).get("waiting", {}).get("reason", "")
            for cs in container_statuses
            if cs.get("state", {}).get("waiting")
        ]
        if phase != "Running" or restarts >= 3 or any(waiting_reasons):
            severity = "high" if "CrashLoopBackOff" in waiting_reasons or restarts >= 10 else "medium"
            findings.append(
                Finding(
                    id=f"F-WORKLOAD-{pod_name}",
                    title=f"Pod {pod_name} is unstable",
                    severity=severity,
                    confidence=0.85,
                    scope=f"namespace/{namespace}",
                    impact=f"phase={phase}, restarts={restarts}, waiting={','.join(waiting_reasons) or 'none'}",
                )
            )
            rb.evidence.append(
                Evidence(
                    type="metric",
                    timestamp="",
                    source="kubectl get pods",
                    detail=f"pod={pod_name} phase={phase} restarts={restarts} waiting={waiting_reasons}",
                )
            )

    rb.findings.extend(findings[:top_n])

    rb.executive_summary = [
        f"Namespace analyzed: {namespace}",
        f"Pods analyzed: {len(pods_json.get('items', []))}",
        f"Unstable pods found: {len(findings)}",
    ]

    if findings:
        rb.actions.append(
            Action(
                priority="safe_now",
                title="Inspect unstable pods logs and events",
                expected_outcome="identify immediate failure reason",
                risk="low",
            )
        )
        rb.commands += [
            f"kubectl -n {namespace} get pods",
            f"kubectl -n {namespace} get events --sort-by=.lastTimestamp",
        ]

    rb.rollback_and_verification = [f"kubectl -n {namespace} get pods"]
    return rb.build()


def network_insights(
    cilium: CiliumAdapter,
    namespace: str,
    since_minutes: int,
    limit: int,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("context.network_insights")
    rb.diagnostics["hubble_cli"] = "unknown"
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    res = cilium.hubble_observe(namespace=namespace, since_minutes=since_minutes, limit=limit)
    if not res.ok:
        rb.diagnostics["hubble_cli"] = "unavailable"
        rb.degraded = True
        rb.executive_summary.append("hubble observe unavailable; returning degraded network context")
        rb.evidence.append(Evidence(type="event", timestamp="", source="hubble", detail=res.stderr))
        rb.commands += ["cilium hubble enable", "cilium hubble port-forward"]
        return rb.build()
    rb.diagnostics["hubble_cli"] = "available"
    if res.stderr:
        # Hubble can emit useful warnings (for example ring buffer loss) to stderr.
        rb.diagnostics["hubble_stderr"] = res.stderr

    denied = 0
    dns_errors = 0
    telemetry_loss_events = 0
    skipped_empty_verdict = 0
    pairs: Counter[str] = Counter()

    for line in res.stdout.splitlines():
        if "EVENTS LOST" in line.upper():
            telemetry_loss_events += 1
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue

        flow = doc.get("flow", {}) if isinstance(doc.get("flow", {}), dict) else {}
        verdict = doc.get("verdict", "") or flow.get("verdict", "")
        if not verdict:
            skipped_empty_verdict += 1
            continue

        source = flow.get("source", {}).get("pod_name", "unknown")
        dest = flow.get("destination", {}).get("pod_name", "unknown")
        l7 = flow.get("l7", {})

        pair = f"{source}->{dest}"
        pairs[pair] += 1

        if verdict == "DROPPED":
            denied += 1
            rb.evidence.append(
                Evidence(type="flow", timestamp="", source="hubble", detail=f"dropped flow {pair}")
            )
        if isinstance(l7, dict) and l7.get("dns", {}).get("rcode") not in (None, 0):
            dns_errors += 1

    rb.executive_summary = [
        f"Namespace analyzed: {namespace}",
        f"Window: last {since_minutes} minutes",
        f"Denied flows: {denied}, DNS errors: {dns_errors}",
    ]
    if telemetry_loss_events > 0:
        rb.executive_summary.append(f"Telemetry loss notices: {telemetry_loss_events}")
        rb.diagnostics["telemetry_loss"] = "true"
        rb.evidence.append(
            Evidence(
                type="event",
                timestamp="",
                source="hubble",
                detail=f"detected {telemetry_loss_events} telemetry loss notices",
            )
        )
    else:
        rb.diagnostics["telemetry_loss"] = "false"
    rb.diagnostics["skipped_empty_verdict_records"] = str(skipped_empty_verdict)

    if denied > 0:
        rb.findings.append(
            Finding(
                id="F-NET-DENIES",
                title="Denied network flows detected",
                severity="high" if denied > 20 else "medium",
                confidence=0.9,
                scope=f"namespace/{namespace}",
                impact="possible service connectivity failures",
            )
        )

    top_pairs = ", ".join(f"{k} ({v})" for k, v in pairs.most_common(3))
    if top_pairs:
        rb.evidence.append(Evidence(type="metric", timestamp="", source="hubble", detail=f"top talkers: {top_pairs}"))

    rb.actions.append(
        Action(
            priority="safe_now",
            title="Review policy impact for top denied flows",
            expected_outcome="map denies to policy intent vs misconfig",
            risk="low",
        )
    )
    rb.commands += [
        f"hubble observe --namespace {namespace} --since {since_minutes}m --last {limit}",
        f"cilium policy get --namespace {namespace}",
    ]

    return rb.build()


def incident_timeline(
    k8s: KubernetesAdapter,
    cilium: CiliumAdapter,
    namespace: str,
    workload: str,
    since_minutes: int,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("context.incident_timeline")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    events_json, events_res = k8s.get_events(namespace)
    pods_json, pods_res = k8s.get_pods(namespace)
    hubble_res = cilium.hubble_observe(namespace=namespace, since_minutes=since_minutes, limit=120)

    if not events_res.ok or not pods_res.ok:
        rb.degraded = True

    for event in events_json.get("items", [])[-25:]:
        msg = event.get("message", "")
        obj = event.get("involvedObject", {}).get("name", "")
        if workload in obj or workload in msg:
            rb.evidence.append(
                Evidence(
                    type="event",
                    timestamp=event.get("lastTimestamp", ""),
                    source="kubectl events",
                    detail=msg,
                )
            )

    for pod in pods_json.get("items", []):
        name = pod.get("metadata", {}).get("name", "")
        if workload not in name:
            continue
        status = pod.get("status", {})
        phase = status.get("phase", "Unknown")
        rb.evidence.append(Evidence(type="metric", timestamp="", source="kubectl get pods", detail=f"{name} phase={phase}"))

    if hubble_res.ok:
        for line in hubble_res.stdout.splitlines()[:40]:
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if doc.get("verdict", "") == "DROPPED":
                rb.evidence.append(Evidence(type="flow", timestamp="", source="hubble", detail="dropped flow near incident window"))
    else:
        rb.degraded = True
        rb.evidence.append(Evidence(type="event", timestamp="", source="hubble", detail=hubble_res.stderr))

    rb.executive_summary = [
        f"Incident timeline for workload={workload} namespace={namespace}",
        f"Window: last {since_minutes} minutes",
        f"Evidence points collected: {len(rb.evidence)}",
    ]

    if rb.evidence:
        rb.findings.append(
            Finding(
                id="F-INCIDENT-CORRELATED",
                title="Correlated multi-source incident evidence",
                severity="medium",
                confidence=0.75,
                scope=f"namespace/{namespace}",
                impact="supports faster root-cause isolation",
            )
        )
        rb.causal_graph.append(CausalEdge(from_node="workload-change", to_node="runtime-symptom", reason="temporal correlation"))

    rb.actions.append(
        Action(
            priority="next",
            title="Compare with last known good rollout and policy snapshot",
            expected_outcome="confirm trigger hypothesis",
            risk="low",
        )
    )
    rb.commands += [
        f"kubectl -n {namespace} get events --sort-by=.lastTimestamp",
        f"kubectl -n {namespace} get pods",
    ]
    rb.rollback_and_verification = [
        f"kubectl -n {namespace} rollout history deploy/{workload}",
        f"kubectl -n {namespace} get pods",
    ]

    return rb.build()


def rca_pack(
    k8s: KubernetesAdapter,
    cilium: CiliumAdapter,
    namespace: str,
    workload: str,
    since_minutes: int,
    source_namespace: str | None,
    allowlist: set[str] | None,
) -> Report:
    rb = ReportBuilder("context.rca_pack")
    ns_decision = check_namespace(namespace, allowlist)
    if not ns_decision.allowed:
        rb.degraded = True
        rb.executive_summary.append(ns_decision.reason)
        return rb.build()

    health = workload_health(k8s=k8s, namespace=namespace, top_n=10, allowlist=allowlist)
    net = network_insights(
        cilium=cilium, namespace=namespace, since_minutes=since_minutes, limit=200, allowlist=allowlist
    )
    timeline = incident_timeline(
        k8s=k8s,
        cilium=cilium,
        namespace=namespace,
        workload=workload,
        since_minutes=since_minutes,
        allowlist=allowlist,
    )

    rb.degraded = health.meta.degraded or net.meta.degraded or timeline.meta.degraded
    rb.diagnostics["subreports"] = "workload_health,network_insights,incident_timeline"
    rb.diagnostics["health_degraded"] = str(health.meta.degraded).lower()
    rb.diagnostics["network_degraded"] = str(net.meta.degraded).lower()
    rb.diagnostics["timeline_degraded"] = str(timeline.meta.degraded).lower()

    combined_findings = health.top_findings + net.top_findings + timeline.top_findings
    # The timeline correlation finding alone is not enough to call an incident.
    combined_findings = [f for f in combined_findings if f.id != "F-INCIDENT-CORRELATED"]
    rb.findings.extend(combined_findings[:20])
    combined_evidence = health.evidence + net.evidence + timeline.evidence
    rb.evidence.extend(combined_evidence[:120])

    dep_json, dep_res = k8s.get_deployment(namespace, workload)
    if dep_res.ok:
        desired = int(dep_json.get("spec", {}).get("replicas", 0))
        available = int(dep_json.get("status", {}).get("availableReplicas", 0))
        rb.evidence.append(
            Evidence(
                type="metric",
                timestamp="",
                source="kubectl deployment",
                detail=f"deployment/{workload} replicas available={available} desired={desired}",
            )
        )
        if available < desired:
            rb.findings.append(
                Finding(
                    id="F-RCA-ROLLOUT-GAP",
                    title="Deployment available replicas below desired",
                    severity="high" if desired > 0 and available == 0 else "medium",
                    confidence=0.9,
                    scope=f"namespace/{namespace}",
                    impact="workload not fully serving traffic",
                )
            )
            rb.causal_graph.append(
                CausalEdge(from_node="rollout-health", to_node="service-degradation", reason="insufficient available replicas")
            )

    ev_text = " ".join(e.detail.lower() for e in rb.evidence)
    has_drops = any(
        ("dropped flow" in e.detail.lower()) or ("policy denied" in e.detail.lower()) or ("ingress denied" in e.detail.lower())
        for e in rb.evidence
    )
    has_crash = ("crashloopbackoff" in ev_text) or ("back-off restarting failed container" in ev_text)
    has_readiness = ("readiness probe failed" in ev_text) or ("not ready" in ev_text)
    telemetry_loss = net.meta.diagnostics.get("telemetry_loss", "false") == "true"
    telemetry_degraded = health.meta.degraded or net.meta.degraded or timeline.meta.degraded or telemetry_loss

    if source_namespace:
        cross_res = cilium.hubble_query(
            namespace=namespace,
            since_minutes=since_minutes,
            limit=200,
            source_namespace=source_namespace,
            dest_namespace=namespace,
            verdict="DROPPED",
        )
        if cross_res.ok:
            cross_drops = 0
            for line in cross_res.stdout.splitlines():
                if "EVENTS LOST" in line.upper():
                    continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                flow = doc.get("flow", {}) if isinstance(doc.get("flow", {}), dict) else {}
                verdict = doc.get("verdict", "") or flow.get("verdict", "")
                if str(verdict).upper() == "DROPPED":
                    cross_drops += 1
            rb.diagnostics["cross_namespace_source"] = source_namespace
            rb.diagnostics["cross_namespace_dropped_flows"] = str(cross_drops)
            if cross_drops > 0:
                has_drops = True
                rb.evidence.append(
                    Evidence(
                        type="flow",
                        timestamp="",
                        source="hubble",
                        detail=(
                            f"cross-namespace dropped flows observed: "
                            f"{source_namespace} -> {namespace} count={cross_drops}"
                        ),
                    )
                )
        else:
            rb.diagnostics["cross_namespace_query_error"] = cross_res.stderr

    if has_drops:
        rb.findings.append(
            Finding(
                id="F-RCA-NETWORK-DENY",
                title="Likely network/policy contribution",
                severity="high",
                confidence=0.82,
                scope=f"namespace/{namespace}",
                impact="traffic drops observed in flow telemetry",
            )
        )
        rb.causal_graph.append(
            CausalEdge(from_node="network-policy-or-path", to_node="request-failures", reason="dropped flows detected")
        )
    if has_crash:
        rb.findings.append(
            Finding(
                id="F-RCA-RUNTIME-CRASH",
                title="Likely runtime crash contribution",
                severity="high",
                confidence=0.86,
                scope=f"namespace/{namespace}",
                impact="pod restart/back-off signals found",
            )
        )
        rb.causal_graph.append(
            CausalEdge(from_node="runtime-error", to_node="pod-instability", reason="crashloop/back-off evidence")
        )
    if has_readiness:
        rb.findings.append(
            Finding(
                id="F-RCA-READINESS",
                title="Likely readiness/endpoint contribution",
                severity="medium",
                confidence=0.74,
                scope=f"namespace/{namespace}",
                impact="ready endpoint set likely reduced",
            )
        )
        rb.causal_graph.append(
            CausalEdge(from_node="readiness-failure", to_node="endpoint-loss", reason="readiness failure evidence")
        )

    active_incident = has_drops or has_crash or has_readiness or any(f.id == "F-RCA-ROLLOUT-GAP" for f in rb.findings)
    if active_incident:
        rb.diagnostics["verdict"] = "ACTIVE_INCIDENT"
        rb.executive_summary.insert(0, "Verdict: ACTIVE INCIDENT")
    elif telemetry_degraded:
        rb.diagnostics["verdict"] = "INCIDENT_UNCERTAIN"
        rb.executive_summary.insert(0, "Verdict: INCIDENT UNCERTAIN (telemetry incomplete/degraded)")
        rb.actions.insert(
            0,
            Action(
                priority="safe_now",
                title="Improve telemetry quality and rerun RCA",
                expected_outcome="reduce false negatives before remediation decisions",
                risk="low",
            ),
        )
    else:
        rb.diagnostics["verdict"] = "NO_ACTIVE_INCIDENT"
        rb.executive_summary.insert(0, "Verdict: NO ACTIVE INCIDENT")
        rb.findings.append(
            Finding(
                id="F-RCA-NO-ACTIVE-INCIDENT",
                title="No high-signal fault indicators detected",
                severity="low",
                confidence=0.85,
                scope=f"namespace/{namespace}",
                impact="workload appears healthy in analyzed window",
            )
        )

    rb.actions.extend(
        [
            Action(
                priority="safe_now",
                title="Validate rollout and pod health for target workload",
                expected_outcome="confirm whether issue is rollout/runtime driven",
                risk="low",
            ),
            Action(
                priority="safe_now",
                title="Correlate dropped flows with policy/service path",
                expected_outcome="confirm whether connectivity controls are blocking traffic",
                risk="low",
            ),
            Action(
                priority="next",
                title="Execute dry-run rollback or restart if degradation persists",
                expected_outcome="safe remediation path prepared with minimal blast radius",
                risk="medium",
            ),
        ]
    )

    # Keep unique command list while preserving order.
    seen: set[str] = set()
    for cmd in (
        health.commands
        + net.commands
        + timeline.commands
        + [
            f"kubectl -n {namespace} get deploy {workload} -o yaml",
            f"kubectl -n {namespace} get events --sort-by=.lastTimestamp",
            f"hubble observe --namespace {namespace} --since {since_minutes}m --last 200",
        ]
    ):
        if cmd not in seen:
            rb.commands.append(cmd)
            seen.add(cmd)

    rb.rollback_and_verification = [
        f"kubectl -n {namespace} rollout status deploy/{workload}",
        f"kubectl -n {namespace} get pods",
        f"hubble observe --namespace {namespace} --since 5m --last 50",
    ]
    rb.executive_summary = [
        f"RCA pack for workload={workload} namespace={namespace}",
        f"Window analyzed: last {since_minutes} minutes",
        f"Findings aggregated: {len(rb.findings)} from 3 subreports",
    ] + rb.executive_summary
    return rb.build()
