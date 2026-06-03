from __future__ import annotations

import json
import subprocess
import shutil
from pathlib import Path
from .base import CommandResult
from sentinelforge.models import Finding, Location


def run_tool(name: str, args: list[str], timeout: int = 120) -> CommandResult:
    if not shutil.which(name):
        return CommandResult(name=name, status="missing", command=[name, *args])
    try:
        p = subprocess.run([name, *args], capture_output=True, text=True, timeout=timeout)
        return CommandResult(name=name, status="ok" if p.returncode in (0, 1) else "error", command=[name, *args], stdout=p.stdout, stderr=p.stderr, exit_code=p.returncode)
    except Exception as exc:
        return CommandResult(name=name, status="error", command=[name, *args], stderr=str(exc), exit_code=1)


def parse_json_findings(raw: str, scanner: str) -> list[Finding]:
    data = json.loads(raw or "[]")
    if isinstance(data, dict):
        data = data.get("results") or data.get("findings") or data.get("vulnerabilities") or []
    findings=[]
    for i,item in enumerate(data,1):
        sev = str(item.get("severity") or item.get("level") or "medium").lower()
        if sev not in {"info","low","medium","high","critical"}: sev="medium"
        findings.append(Finding(
            finding_id=f"SF-{scanner.upper()}-{i:04d}", title=item.get("title") or item.get("message") or f"{scanner} finding",
            category="External Scanner", cwe_id=item.get("cwe") or item.get("cwe_id"), owasp_mapping=None,
            severity=sev, cvss_score={"info":0,"low":2,"medium":5,"high":7.5,"critical":9.5}[sev], confidence="medium",
            source_agent=scanner, location=Location(file=item.get("file") or item.get("path"), line_start=item.get("line")),
            description=item.get("description") or item.get("message") or "External scanner reported an issue.",
            evidence=json.dumps(item)[:500], impact="This issue may weaken the application depending on reachability and context.",
            remediation=item.get("remediation") or "Review scanner output and apply the recommended secure fix.",
            references=item.get("references") or [], retest_steps=[f"Re-run {scanner} and SentinelForge."]
        ))
    return findings
