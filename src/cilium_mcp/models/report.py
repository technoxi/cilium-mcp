from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
Priority = Literal["safe_now", "next"]
EvidenceType = Literal["event", "log", "flow", "metric", "config"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    scope: str
    impact: str


class Evidence(BaseModel):
    type: EvidenceType
    timestamp: str
    source: str
    detail: str


class CausalEdge(BaseModel):
    from_node: str = Field(serialization_alias="from")
    to_node: str = Field(serialization_alias="to")
    reason: str


class Action(BaseModel):
    priority: Priority
    title: str
    expected_outcome: str
    risk: str


class Meta(BaseModel):
    tool: str
    generated_at: str
    data_freshness_seconds: int
    degraded: bool
    diagnostics: dict[str, str] = Field(default_factory=dict)


class Report(BaseModel):
    executive_summary: list[str]
    top_findings: list[Finding]
    evidence: list[Evidence]
    causal_graph: list[CausalEdge]
    actions: list[Action]
    commands: list[str]
    rollback_and_verification: list[str]
    meta: Meta


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()
