from __future__ import annotations

from dataclasses import dataclass

from cilium_mcp.shell import CommandResult, run_command


@dataclass
class CiliumAdapter:
    timeout_seconds: int

    def hubble_observe(self, namespace: str, since_minutes: int, limit: int = 200) -> CommandResult:
        # Requires local hubble relay connectivity (for example via `cilium hubble port-forward`).
        return run_command(
            [
                "hubble",
                "observe",
                "--namespace",
                namespace,
                "--since",
                f"{since_minutes}m",
                "--last",
                str(limit),
                "--output",
                "json",
            ],
            timeout_seconds=self.timeout_seconds,
        )

    def hubble_query(
        self,
        namespace: str,
        since_minutes: int,
        limit: int = 200,
        source_namespace: str | None = None,
        dest_namespace: str | None = None,
        source_pod: str | None = None,
        dest_pod: str | None = None,
        verdict: str | None = None,
        port: int | None = None,
    ) -> CommandResult:
        cmd = ["hubble", "observe"]
        # Hubble does not allow combining --namespace with --from-namespace/--to-namespace.
        if source_namespace or dest_namespace:
            if source_namespace:
                cmd += ["--from-namespace", source_namespace]
            if dest_namespace:
                cmd += ["--to-namespace", dest_namespace]
        else:
            cmd += ["--namespace", namespace]

        cmd += ["--since", f"{since_minutes}m", "--last", str(limit), "--output", "json"]
        if source_pod:
            cmd += ["--from-pod", source_pod]
        if dest_pod:
            cmd += ["--to-pod", dest_pod]
        if verdict:
            cmd += ["--verdict", verdict.upper()]
        if port is not None:
            cmd += ["--port", str(port)]
        return run_command(cmd, timeout_seconds=self.timeout_seconds)

    def cilium_status(self) -> CommandResult:
        return run_command(["cilium", "status", "--brief"], timeout_seconds=self.timeout_seconds)

    def cilium_policy_get(self, namespace: str) -> CommandResult:
        candidates = [
            ["cilium", "policy", "get", "--namespace", namespace],
            ["cilium", "policy", "get", "-n", namespace],
            ["cilium-dbg", "policy", "get", "--namespace", namespace],
        ]
        last = CommandResult(ok=False, stdout="", stderr="no command attempted", exit_code=1)
        for cmd in candidates:
            last = run_command(cmd, timeout_seconds=self.timeout_seconds)
            if last.ok:
                return last
        return last
