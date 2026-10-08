from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cilium_mcp.models.report import iso_now


def write_audit_event(path: str, event: dict[str, Any]) -> None:
    payload = {"timestamp": iso_now(), **event}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True))
        f.write("\n")
