from __future__ import annotations

from pathlib import Path
from .base import run_tool, CommandResult


def run(target: Path) -> CommandResult:
    # Thin wrapper for the real trivy scanner. Normalization is handled by agents in v0.1.
    command = ['trivy', 'fs', '--format', 'json']
    command = [str(target) if part == '{target}' else part for part in command]
    if '{target}' not in ['trivy', 'fs', '--format', 'json']:
        command.append(str(target))
    return run_tool('trivy', command)
