from __future__ import annotations

import json
from pathlib import Path


def explain_finding(report_path: str | Path, finding_id: str) -> str:
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    for f in data.get("findings", []):
        if f.get("finding_id") == finding_id:
            loc = f.get("location") or {}
            where = loc.get("file") or loc.get("endpoint") or "the scanned project"
            line = f" line {loc.get('line_start')}" if loc.get("line_start") else ""
            steps = "\n".join(f"- {s}" for s in f.get("retest_steps", []) or ["Run SentinelForge again."])
            return f"""Finding {finding_id}: {f.get('title')}

Plain English:
SentinelForge found something that may make the app easier to break into or misuse.
This one is rated {f.get('severity')} severity.

Where it is:
{where}{line}

Why it matters:
{f.get('impact') or f.get('description')}

How to fix it:
{f.get('remediation')}

How to check the fix:
{steps}
"""
    raise ValueError(f"Finding not found: {finding_id}")
