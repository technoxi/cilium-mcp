#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any


DEFAULT_URL = "http://127.0.0.1:8000/mcp"


class McpHttpClient:
    def __init__(self, url: str, timeout: float = 15.0) -> None:
        self.url = url
        self.timeout = timeout
        self.session_id: str | None = None
        self._id = 1

    def _next_id(self) -> int:
        cur = self._id
        self._id += 1
        return cur

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                sid = resp.headers.get("mcp-session-id")
                if sid:
                    self.session_id = sid
                raw = resp.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection error: {e}") from e

        if not raw:
            return {}
        # Some servers may append non-JSON lines; parse first JSON object found.
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Handle SSE payloads where JSON is carried in `data:` lines.
            sse_data_lines: list[str] = []
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    sse_data_lines.append(line[len("data:") :].strip())
            for line in sse_data_lines:
                if line.startswith("{") and line.endswith("}"):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        pass
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        pass
            raise RuntimeError(f"Non-JSON response: {raw[:300]}")

    def initialize(self) -> dict[str, Any]:
        init_payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-cli-test", "version": "0.1.0"},
            },
        }
        init_resp = self._post(init_payload)
        _ = self._post(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )
        return init_resp

    def tools_list(self) -> dict[str, Any]:
        return self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/list",
                "params": {},
            }
        )

    def tools_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                },
            }
        )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Minimal MCP HTTP tester for FastMCP /mcp endpoints")
    p.add_argument("--url", default=DEFAULT_URL, help="MCP HTTP endpoint (default: http://127.0.0.1:8000/mcp)")
    p.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout seconds")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Run initialize handshake")
    sub.add_parser("list-tools", help="List available tools")

    call = sub.add_parser("call", help="Call a tool")
    call.add_argument("--tool", required=True, help="Tool name (for example context.namespace_inventory)")
    call.add_argument(
        "--args",
        default="{}",
        help="JSON object for tool arguments (for example '{\"namespace\":\"default\"}')",
    )

    return p.parse_args()


def main() -> int:
    args = _parse_args()
    client = McpHttpClient(args.url, timeout=args.timeout)

    try:
        init_resp = client.initialize()
        if args.command == "init":
            print(json.dumps(init_resp, indent=2, ensure_ascii=False))
            return 0

        if args.command == "list-tools":
            resp = client.tools_list()
            print(json.dumps(resp, indent=2, ensure_ascii=False))
            return 0

        if args.command == "call":
            try:
                tool_args = json.loads(args.args)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid --args JSON: {e}") from e
            if not isinstance(tool_args, dict):
                raise RuntimeError("--args must decode to a JSON object")
            resp = client.tools_call(args.tool, tool_args)
            print(json.dumps(resp, indent=2, ensure_ascii=False))
            return 0

        raise RuntimeError(f"Unknown command: {args.command}")
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
