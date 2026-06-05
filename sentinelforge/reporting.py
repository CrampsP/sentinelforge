from __future__ import annotations

import html
import json
from pathlib import Path
from .models import SecurityReport, Finding
from .redaction import redact_text


def write_json_report(report: SecurityReport, output_dir: str | Path = "reports") -> Path:
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    path = out / "latest_report.json"
    path.write_text(redact_text(json.dumps(report.model_dump(mode="json"), indent=2)), encoding="utf-8")
    return path


def _finding_md(f: Finding) -> str:
    loc_bits = []
    if f.location.file: loc_bits.append(f.location.file)
    if f.location.line_start: loc_bits.append(f"line {f.location.line_start}")
    if f.location.package: loc_bits.append(f"package {f.location.package}")
    if f.location.endpoint: loc_bits.append(f"endpoint {f.location.endpoint}")
    loc = ", ".join(loc_bits) or "Not specified"
    suppressed = f"\n- Suppressed: {f.suppression_reason}" if f.suppression_reason else ""
    kev = "\n- Known exploited in the wild: yes" if f.known_exploited else ""
    return f"""### {f.finding_id}: {f.title}

- Severity: **{f.severity}**
- Confidence: {f.confidence}
- Category: {f.category}
- Location: `{loc}`
- CWE: {f.cwe_id or "Not mapped"}{kev}{suppressed}

This is risky because: {f.description}

Evidence: `{redact_text(f.evidence)}`

An attacker could: {f.impact}

To fix it: {f.remediation}

To retest:
{chr(10).join(f"- {step}" for step in f.retest_steps) or "- Re-run SentinelForge after applying the fix."}
"""


def write_markdown_report(report: SecurityReport, json_path: Path, output_dir: str | Path = "reports") -> Path:
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    path = out / "latest_report.md"
    top = sorted(report.findings, key=lambda f: {"critical":5,"high":4,"medium":3,"low":2,"info":1}[f.severity], reverse=True)[:5]
    text = f"""# SentinelForge Security Report

## 1. Executive Summary

SentinelForge v{report.sentinelforge_version} scanned `{report.target}` in `{report.scan_mode}` mode. No scanner can prove software is perfectly secure, but this scan shows what SentinelForge found.

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
- Fix known-exploited CVEs before shipping.
- Re-run the scan after each fix.
- Manually review business logic and authorization paths; scanners cannot prove those are safe.

## 8. Retest Plan

Run:

```bash
sentinelforge scan --target {report.target} --mode {report.scan_mode}
```

## 9. Blue Team Hardening Checklist

{chr(10).join(f"- {item}" for item in report.blue_team_checklist) or "- Add security headers, rate limiting, audit logs, dependency updates, and secret rotation process before production."}

## 10. CI/CD Recommendation

Run `sentinelforge gate --report reports/latest_report.json --minimum-grade B` in CI before shipping.

## 11. Tool Results

- Tools run: {", ".join(report.tools_run) or "None"}
- Tools missing: {", ".join(report.tools_missing) or "None"}

## 12. False Positive Notes

Use `.sentinelforgeignore` with a required reason, for example: `SF-STATIC-0001 reason="test fixture only"`.

## 13. Raw JSON Location

`{json_path}`
"""
    path.write_text(redact_text(text), encoding="utf-8")
    return path


def write_html_report(report: SecurityReport, output_dir: str | Path = "reports") -> Path:
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    path = out / "latest_report.html"
    rows = "".join(f"<tr><td>{html.escape(f.finding_id)}</td><td>{html.escape(f.severity)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.category)}</td></tr>" for f in report.findings)
    text = f"""<!doctype html><html><head><meta charset='utf-8'><title>SentinelForge Report</title><style>body{{font-family:Arial,sans-serif;max-width:980px;margin:40px auto}}.grade{{font-size:48px;font-weight:bold}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}</style></head><body><h1>SentinelForge Security Report</h1><div class='grade'>{html.escape(report.summary.grade)} — {report.summary.score}/100</div><p><b>Decision:</b> {html.escape(report.summary.ship_decision)}</p><h2>Findings</h2><table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Category</th></tr>{rows}</table></body></html>"""
    path.write_text(redact_text(text), encoding="utf-8")
    return path


def write_badge(report: SecurityReport, output_dir: str | Path = "reports") -> Path:
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    path = out / "sentinelforge_badge.txt"
    path.write_text(f"Security: {report.summary.grade} by SentinelForge ({report.summary.score}/100)\n", encoding="utf-8")
    return path


def write_reports(report: SecurityReport, output_dir: str | Path = "reports") -> tuple[Path, Path]:
    json_path = write_json_report(report, output_dir)
    md_path = write_markdown_report(report, json_path, output_dir)
    write_html_report(report, output_dir)
    write_badge(report, output_dir)
    return md_path, json_path
