from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    kube_context: str | None
    namespace_allowlist: set[str] | None
    default_timeout_seconds: int
    approval_token: str | None
    max_scale_delta: int
    audit_log_path: str

    @staticmethod
    def from_env() -> "Settings":
        raw_allowlist = os.getenv("CILIUM_MCP_NAMESPACE_ALLOWLIST", "").strip()
        allowlist = {x.strip() for x in raw_allowlist.split(",") if x.strip()} if raw_allowlist else None
        timeout = int(os.getenv("CILIUM_MCP_TIMEOUT_SECONDS", "15"))
        return Settings(
            kube_context=os.getenv("CILIUM_MCP_KUBE_CONTEXT"),
            namespace_allowlist=allowlist,
            default_timeout_seconds=timeout,
            approval_token=os.getenv("CILIUM_MCP_APPROVAL_TOKEN"),
            max_scale_delta=int(os.getenv("CILIUM_MCP_MAX_SCALE_DELTA", "5")),
            audit_log_path=os.getenv("CILIUM_MCP_AUDIT_LOG_PATH", "/tmp/cilium-mcp-audit.jsonl"),
        )
