from __future__ import annotations

import json
from pathlib import Path
from .models import SecurityReport, Finding
from .redaction import redact_text


def write_json_report(report: SecurityReport, output_dir: str | Path = "reports") -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "latest_report.json"
    data = report.model_dump(mode="json")
    text = json.dumps(data, indent=2)
    path.write_text(redact_text(text), encoding="utf-8")
    return path


def _finding_md(f: Finding) -> str:
    loc_bits = []
    if f.location.file:
        loc_bits.append(f.location.file)
    if f.location.line_start:
        loc_bits.append(f"line {f.location.line_start}")
    if f.location.package:
        loc_bits.append(f"package {f.location.package}")
    loc = ", ".join(loc_bits) or "Not specified"
    return f"""### {f.finding_id}: {f.title}

- Severity: **{f.severity}**
- Confidence: {f.confidence}
- Category: {f.category}
- Location: `{loc}`
- CWE: {f.cwe_id or "Not mapped"}

This is risky because: {f.description}

Evidence: `{redact_text(f.evidence)}`

An attacker could: {f.impact}

To fix it: {f.remediation}

To retest:
{chr(10).join(f"- {step}" for step in f.retest_steps) or "- Re-run SentinelForge after applying the fix."}
"""


def write_markdown_report(report: SecurityReport, json_path: Path, output_dir: str | Path = "reports") -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "latest_report.md"
    critical = [f for f in report.findings if f.severity == "critical"]
    top = sorted(report.findings, key=lambda f: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[f.severity], reverse=True)[:5]
    text = f"""# SentinelForge Security Report

## 1. Executive Summary

SentinelForge v{report.sentinelforge_version} scanned `{report.target}` in `{report.scan_mode}` mode. No report can prove software is perfectly secure, but this scan shows what the configured tools detected.

Security standards mapped in this report: {", ".join(report.security_standards)}.

## 2. Final Grade

- Score: **{report.summary.score} / 100**
- Grade: **{report.summary.grade}**

## 3. Ship / Do Not Ship Decision

**{report.summary.ship_decision}**

## 4. Critical Blockers

{chr(10).join(f"- {reason}" for reason in report.summary.automatic_fail_reasons) or "- No automatic fail conditions detected by configured scanners."}

## 5. Top 5 Risks

{chr(10).join(f"- **{f.severity.upper()}** — {f.title}" for f in top) or "- No findings detected."}

## 6. Full Findings

{chr(10).join(_finding_md(f) for f in report.findings) or "No findings detected by configured scanners."}

## 7. Fix Plan

- Fix critical and high findings first.
- Rotate any real exposed secret immediately.
- Re-run the scan after each fix.
- Manually review business logic and authorization paths; scanners cannot prove those are safe.

## 8. Retest Plan

Run:

```bash
sentinelforge scan --target {report.target} --mode {report.scan_mode}
```

## 9. Blue Team Hardening Checklist

{chr(10).join(f"- {item}" for item in report.blue_team_checklist) or "- Add security headers, rate limiting, audit logs, dependency updates, and secret rotation process before production."}

## 10. Tool Results

- Tools run: {", ".join(report.tools_run) or "None"}
- Tools missing: {", ".join(report.tools_missing) or "None"}

## 11. False Positive Notes

Some scanner findings may be false positives. Confirm exploitability before making large rewrites, but treat secrets and critical dependency issues urgently.

## 12. Raw JSON Location

`{json_path}`
"""
    path.write_text(redact_text(text), encoding="utf-8")
    return path


def write_reports(report: SecurityReport, output_dir: str | Path = "reports") -> tuple[Path, Path]:
    json_path = write_json_report(report, output_dir)
    md_path = write_markdown_report(report, json_path, output_dir)
    return md_path, json_path
