from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    reason: str


def check_namespace(namespace: str, allowlist: set[str] | None) -> SafetyDecision:
    if not allowlist:
        return SafetyDecision(True, "no namespace allowlist configured")
    if namespace in allowlist:
        return SafetyDecision(True, f"namespace {namespace} is in allowlist")
    return SafetyDecision(False, f"namespace {namespace} not in allowlist")


_PREVIEW_WINDOW_SECONDS = 600
_preview_cache: dict[str, float] = {}


def mark_dry_run_preview(action_key: str) -> None:
    _preview_cache[action_key] = time.time()


def check_dry_run_preview(action_key: str) -> SafetyDecision:
    ts = _preview_cache.get(action_key)
    if ts is None:
        return SafetyDecision(False, "no recent dry-run found for this action")
    if (time.time() - ts) > _PREVIEW_WINDOW_SECONDS:
        return SafetyDecision(False, "dry-run preview expired; rerun dry_run=true first")
    return SafetyDecision(True, "recent dry-run preview exists")


def check_approval_token(provided_token: str | None, expected_token: str | None) -> SafetyDecision:
    if not expected_token:
        return SafetyDecision(True, "approval token check disabled on server")
    if not provided_token:
        return SafetyDecision(False, "approval token is required for non-dry-run actions")
    if provided_token != expected_token:
        return SafetyDecision(False, "invalid approval token")
    return SafetyDecision(True, "approval token verified")
