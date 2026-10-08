from __future__ import annotations

from collections.abc import Iterable

from cilium_mcp.models.report import Finding

_SEVERITY_WEIGHT = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def rank_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Rank findings by severity first, then confidence."""
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_WEIGHT.get(f.severity, 0), f.confidence),
        reverse=True,
    )
