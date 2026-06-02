from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    name: str
    status: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None


def run_tool(name: str, command: list[str], timeout: int = 120, cwd: str | Path | None = None) -> CommandResult:
    if not command or shutil.which(command[0]) is None:
        return CommandResult(name=name, status="missing", command=command, stderr=f"{command[0] if command else name} is not installed")
    try:
        completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        status = "ok" if completed.returncode == 0 else "error"
        return CommandResult(name=name, status=status, command=command, stdout=completed.stdout, stderr=completed.stderr, exit_code=completed.returncode)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(name=name, status="error", command=command, stdout=exc.stdout or "", stderr=f"Timed out after {timeout}s", exit_code=None)


def parse_json_output(result: CommandResult):
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {}
