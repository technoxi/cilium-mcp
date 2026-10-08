from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int


def run_command(args: list[str], timeout_seconds: int = 15) -> CommandResult:
    try:
        proc = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return CommandResult(
            ok=proc.returncode == 0,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            exit_code=proc.returncode,
        )
    except FileNotFoundError as exc:
        return CommandResult(ok=False, stdout="", stderr=str(exc), exit_code=127)
    except subprocess.TimeoutExpired:
        return CommandResult(ok=False, stdout="", stderr=f"timeout after {timeout_seconds}s", exit_code=124)


def run_command_with_input(args: list[str], input_text: str, timeout_seconds: int = 15) -> CommandResult:
    try:
        proc = subprocess.run(
            args,
            input=input_text,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return CommandResult(
            ok=proc.returncode == 0,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            exit_code=proc.returncode,
        )
    except FileNotFoundError as exc:
        return CommandResult(ok=False, stdout="", stderr=str(exc), exit_code=127)
    except subprocess.TimeoutExpired:
        return CommandResult(ok=False, stdout="", stderr=f"timeout after {timeout_seconds}s", exit_code=124)


def run_json_command(args: list[str], timeout_seconds: int = 15) -> tuple[dict, CommandResult]:
    result = run_command(args, timeout_seconds=timeout_seconds)
    if not result.ok:
        return {}, result
    try:
        return json.loads(result.stdout or "{}"), result
    except json.JSONDecodeError:
        return {}, CommandResult(
            ok=False,
            stdout=result.stdout,
            stderr="failed to parse json output",
            exit_code=2,
        )
