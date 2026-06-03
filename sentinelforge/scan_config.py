from __future__ import annotations

from pathlib import Path

DEFAULT_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "sentinelforge.egg-info",
    "dist",
    "build",
    "reports",
}

DEFAULT_SKIP_FILES = {
    ".hermes_progress.json",
}

# Intentional vulnerable samples and test literals should not lower the score when
# SentinelForge audits its own repository. If a fixture directory is scanned as the
# target itself, the relative path will not start with tests/fixtures and the risky
# sample remains detectable.
DEFAULT_SKIP_PREFIXES = (
    ("tests",),
    ("docs", "examples"),
)


def should_skip_file(target: Path, path: Path) -> bool:
    path = path.resolve()
    target = target.resolve()
    if any(part in DEFAULT_SKIP_DIRS for part in path.parts):
        return True
    if path.name in DEFAULT_SKIP_FILES:
        return True
    try:
        rel = path.relative_to(target)
    except ValueError:
        return True
    rel_parts = rel.parts
    return any(rel_parts[: len(prefix)] == prefix for prefix in DEFAULT_SKIP_PREFIXES)
