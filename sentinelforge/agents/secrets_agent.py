from __future__ import annotations

import re
from pathlib import Path
from sentinelforge.models import Finding, Location
from sentinelforge.redaction import redact_text
from sentinelforge.scan_config import should_skip_file

SECRET_REGEXES = [
    (re.compile(r"sk_live_[A-Za-z0-9_.\-]{8,}"), "Live API key"),
    (re.compile(r"ghp_[A-Za-z0-9_]{20,}"), "GitHub token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"]?([^'\"\s]{8,})"), "Hardcoded secret assignment"),
]

SKIP_DIRS = {'.git', 'node_modules', '.venv', '__pycache__'}


def scan(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    idx = 1
    for path in target.rglob('*'):
        if not path.is_file() or should_skip_file(target, path):
            continue
        try:
            lines = path.read_text(errors='ignore').splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for regex, secret_type in SECRET_REGEXES:
                if regex.search(line):
                    findings.append(Finding(
                        finding_id=f"SF-SECRET-{idx:04d}",
                        title=f"Suspected hardcoded secret: {secret_type}",
                        category="Secrets",
                        cwe_id="CWE-798",
                        owasp_mapping="A02: Cryptographic Failures",
                        severity="high",
                        cvss_score=8.0,
                        confidence="medium",
                        status="open",
                        source_agent="secrets_agent",
                        location=Location(file=str(path), line_start=line_no, line_end=line_no),
                        description="A credential-like value appears to be stored in the repository.",
                        evidence=redact_text(line),
                        impact="If this value is real, attackers may be able to access private systems or data. Exposed secrets should be rotated, not just deleted from code.",
                        remediation="Move the secret into a secure environment variable or secrets manager, remove it from code, and rotate the credential if it may be real.",
                        safe_fix_suggestion="Replace the literal value with an environment variable lookup and add a sample .env.example placeholder.",
                        references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                        retest_steps=["Rotate the secret if real.", "Remove it from the repository.", "Re-run SentinelForge and a dedicated secret scanner."]
                    ))
                    idx += 1
                    break
    return findings
