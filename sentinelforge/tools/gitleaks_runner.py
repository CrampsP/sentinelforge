from __future__ import annotations

from pathlib import Path
from .base import run_tool, CommandResult


def run(target: Path) -> CommandResult:
    # Thin wrapper for the real gitleaks scanner. Normalization is handled by agents in v0.1.
    command = ['gitleaks', 'detect', '--source', '{target}', '--report-format', 'json', '--no-banner']
    command = [str(target) if part == '{target}' else part for part in command]
    if '{target}' not in ['gitleaks', 'detect', '--source', '{target}', '--report-format', 'json', '--no-banner']:
        command.append(str(target))
    return run_tool('gitleaks', command)
