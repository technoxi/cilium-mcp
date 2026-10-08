from __future__ import annotations

from cilium_mcp.models.report import Action, CausalEdge, Evidence, Finding, Meta, Report, iso_now
from cilium_mcp.scoring import rank_findings


class ReportBuilder:
    def __init__(self, tool_name: str, degraded: bool = False, data_freshness_seconds: int = 0) -> None:
        self.tool_name = tool_name
        self.degraded = degraded
        self.data_freshness_seconds = data_freshness_seconds
        self.diagnostics: dict[str, str] = {}
        self.executive_summary: list[str] = []
        self.findings: list[Finding] = []
        self.evidence: list[Evidence] = []
        self.causal_graph: list[CausalEdge] = []
        self.actions: list[Action] = []
        self.commands: list[str] = []
        self.rollback_and_verification: list[str] = []

    def build(self) -> Report:
        return Report(
            executive_summary=self.executive_summary,
            top_findings=rank_findings(self.findings),
            evidence=self.evidence,
            causal_graph=self.causal_graph,
            actions=self.actions,
            commands=self.commands,
            rollback_and_verification=self.rollback_and_verification,
            meta=Meta(
                tool=self.tool_name,
                generated_at=iso_now(),
                data_freshness_seconds=self.data_freshness_seconds,
                degraded=self.degraded,
                diagnostics=self.diagnostics,
            ),
        )
