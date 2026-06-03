from __future__ import annotations

import re
from pathlib import Path
from .models import Finding

LINE_RE = re.compile(r'^(?P<id>\S+)\s+reason=["\'](?P<reason>.+?)["\']\s*$')


def load_suppressions(path: str | Path) -> dict[str, str]:
    path = Path(path)
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = LINE_RE.match(stripped)
        if not m:
            raise ValueError(f"Invalid suppression line. Use: FINDING_ID reason=\"why\": {line}")
        out[m.group("id")] = m.group("reason")
    return out


def apply_suppressions(findings: list[Finding], suppressions: dict[str, str]) -> list[Finding]:
    return [f.model_copy(update={"status": "false_positive", "suppression_reason": suppressions[f.finding_id]}) if f.finding_id in suppressions else f for f in findings]
