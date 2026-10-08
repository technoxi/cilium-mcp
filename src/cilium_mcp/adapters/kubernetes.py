from __future__ import annotations

from dataclasses import dataclass

from cilium_mcp.shell import CommandResult, run_command, run_command_with_input, run_json_command


@dataclass
class KubernetesAdapter:
    kube_context: str | None
    timeout_seconds: int

    def _base_cmd(self) -> list[str]:
        cmd = ["kubectl"]
        if self.kube_context:
            cmd += ["--context", self.kube_context]
        return cmd

    def get_pods(self, namespace: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "pods", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_events(self, namespace: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd()
            + ["-n", namespace, "get", "events", "--sort-by=.lastTimestamp", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_services(self, namespace: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "svc", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_endpoints(self, namespace: str, service: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "endpoints", service, "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_service(self, namespace: str, service: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "svc", service, "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_pod_logs(self, namespace: str, pod: str, tail: int = 80) -> CommandResult:
        return run_command(
            self._base_cmd() + ["-n", namespace, "logs", pod, "--tail", str(tail)],
            timeout_seconds=self.timeout_seconds,
        )

    def list_namespaces(self) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["get", "namespaces", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_cilium_network_policies(self, namespace: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd()
            + ["-n", namespace, "get", "ciliumnetworkpolicies.cilium.io", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_cilium_clusterwide_policies(self) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["get", "ciliumclusterwidenetworkpolicies.cilium.io", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_deployment(self, namespace: str, deployment: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "deploy", deployment, "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def rollout_restart_deployment(self, namespace: str, deployment: str, dry_run: bool) -> CommandResult:
        cmd = self._base_cmd() + ["-n", namespace, "rollout", "restart", f"deployment/{deployment}"]
        if dry_run:
            cmd_with_dry_run = cmd + ["--dry-run=server"]
            result = run_command(cmd_with_dry_run, timeout_seconds=self.timeout_seconds)
            if result.ok:
                return result
            # Some kubectl versions do not support dry-run for rollout restart.
            unsupported = ("unknown flag" in result.stderr.lower()) or ("--dry-run" in result.stderr.lower())
            if unsupported:
                exists = run_command(
                    self._base_cmd() + ["-n", namespace, "get", f"deployment/{deployment}"],
                    timeout_seconds=self.timeout_seconds,
                )
                if exists.ok:
                    return CommandResult(
                        ok=True,
                        stdout=(
                            "dry-run preview succeeded via compatibility fallback "
                            "(deployment exists; kubectl lacks rollout restart dry-run support)"
                        ),
                        stderr="",
                        exit_code=0,
                    )
                return CommandResult(
                    ok=False,
                    stdout="",
                    stderr=(
                        f"deployment/{deployment} not found in namespace/{namespace}; "
                        "cannot run rollout restart preview"
                    ),
                    exit_code=1,
                )
            return result
        return run_command(cmd, timeout_seconds=self.timeout_seconds)

    def scale_deployment(self, namespace: str, deployment: str, replicas: int, dry_run: bool) -> CommandResult:
        cmd = self._base_cmd() + ["-n", namespace, "scale", f"deployment/{deployment}", f"--replicas={replicas}"]
        if dry_run:
            cmd += ["--dry-run=server"]
        return run_command(cmd, timeout_seconds=self.timeout_seconds)

    def rollout_undo_deployment(self, namespace: str, deployment: str, dry_run: bool) -> CommandResult:
        cmd = self._base_cmd() + ["-n", namespace, "rollout", "undo", f"deployment/{deployment}"]
        if dry_run:
            cmd += ["--dry-run=server"]
        return run_command(cmd, timeout_seconds=self.timeout_seconds)

    def apply_manifest(self, namespace: str, manifest_yaml: str, dry_run: bool) -> CommandResult:
        cmd = self._base_cmd() + ["-n", namespace, "apply", "-f", "-"]
        if dry_run:
            cmd += ["--dry-run=server"]
        return run_command_with_input(cmd, input_text=manifest_yaml, timeout_seconds=self.timeout_seconds)

    def delete_cilium_network_policy(self, namespace: str, policy: str, dry_run: bool) -> CommandResult:
        cmd = self._base_cmd() + ["-n", namespace, "delete", "ciliumnetworkpolicy.cilium.io", policy]
        if dry_run:
            cmd += ["--dry-run=server"]
        return run_command(cmd, timeout_seconds=self.timeout_seconds)

    def label_pod(self, namespace: str, pod: str, key: str, value: str, dry_run: bool) -> CommandResult:
        cmd = self._base_cmd() + ["-n", namespace, "label", "pod", pod, f"{key}={value}", "--overwrite"]
        if dry_run:
            cmd += ["--dry-run=server"]
        return run_command(cmd, timeout_seconds=self.timeout_seconds)

    def get_deployments(self, namespace: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "deploy", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_hpas(self, namespace: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "hpa", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_ingresses(self, namespace: str) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", namespace, "get", "ingress", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )

    def get_dns_service(self) -> tuple[dict, CommandResult]:
        return run_json_command(
            self._base_cmd() + ["-n", "kube-system", "get", "svc", "kube-dns", "-o", "json"],
            timeout_seconds=self.timeout_seconds,
        )
