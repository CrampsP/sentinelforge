from __future__ import annotations

from pathlib import Path
from .base import run_tool, CommandResult


def run(target: Path) -> CommandResult:
    # Thin wrapper for the real osv scanner. Normalization is handled by agents in v0.1.
    command = ['osv-scanner', '--json']
    command = [str(target) if part == '{target}' else part for part in command]
    if '{target}' not in ['osv-scanner', '--json']:
        command.append(str(target))
    return run_tool('osv', command)
