from __future__ import annotations

from pathlib import Path

WORKFLOW = """name: SentinelForge Security Gate

on:
  push:
  pull_request:

jobs:
  sentinelforge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install SentinelForge
        run: pipx install .
      - name: Scan this project
        run: sentinelforge scan --target . --mode static
      - name: Fail if security grade is too low
        run: sentinelforge gate --report reports/latest_report.json --minimum-grade B
"""


def write_github_actions(output_dir: str | Path = ".github/workflows") -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "sentinelforge.yml"
    path.write_text(WORKFLOW, encoding="utf-8")
    return path
