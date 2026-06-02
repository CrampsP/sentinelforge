from __future__ import annotations

from pathlib import Path
from sentinelforge.models import Finding, Location


def tool_unavailable_finding(idx: int, tool: str, install_hint: str) -> Finding:
    return Finding(
        finding_id=f"SF-TOOL-{idx:04d}", title=f"Scanner tool unavailable: {tool}", category="Tool Status",
        cwe_id=None, owasp_mapping=None, severity="info", cvss_score=0.0, confidence="high", status="open",
        source_agent="tool_status", location=Location(),
        description=f"{tool} was not available, so SentinelForge could not use it for this scan.",
        evidence=f"Missing command: {tool}", impact="The scan may miss findings that this tool would have detected.",
        remediation=install_hint, safe_fix_suggestion=None, references=[],
        retest_steps=[f"Install {tool}.", "Re-run SentinelForge."]
    )


def blue_team_checklist(target: Path) -> list[str]:
    return [
        "Add security headers: CSP, HSTS, X-Frame-Options/frame-ancestors, X-Content-Type-Options, and Referrer-Policy.",
        "Add rate limiting to login, signup, password reset, and expensive API routes.",
        "Log authentication failures, authorization denials, and admin actions.",
        "Use a secret manager or environment variables; never commit real credentials.",
        "Set up dependency update automation and security alerts.",
        "Create a backup and restore plan before production.",
        "Manually review business logic and object-level authorization; static scanners cannot prove those are safe.",
    ]
