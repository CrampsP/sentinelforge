from __future__ import annotations

import re
from pathlib import Path
from sentinelforge.models import Finding, Location
from sentinelforge.scan_config import should_skip_file

CODE_EXTS = {'.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.rb', '.php'}


def _finding(fid: str, title: str, severity: str, file: Path, line: int, evidence: str, category: str = "Static Analysis", cwe: str | None = None) -> Finding:
    cvss = {"critical": 9.1, "high": 7.5, "medium": 5.5, "low": 2.5, "info": 0.0}[severity]
    return Finding(
        finding_id=fid,
        title=title,
        category=category,
        cwe_id=cwe,
        owasp_mapping=None,
        severity=severity, cvss_score=cvss, confidence="medium", status="open",
        source_agent="static_analysis_agent",
        location=Location(file=str(file), line_start=line, line_end=line),
        description=f"SentinelForge found a risky code pattern: {title}.",
        evidence=evidence.strip()[:500],
        impact="This may let attackers execute unintended actions, access data, or weaken security depending on how the code is used.",
        remediation="Review this code path and replace the risky pattern with validated input, safe APIs, and server-side authorization checks.",
        safe_fix_suggestion="Add focused tests around this path, then replace the risky pattern with a safer framework-supported approach.",
        references=["https://owasp.org/www-project-top-ten/"],
        retest_steps=["Fix the code pattern.", "Re-run SentinelForge static scan."]
    )


def scan(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        (re.compile(r"subprocess\.(Popen|run|call).*shell\s*=\s*True"), "Shell command execution with shell=True", "high", "CWE-78"),
        (re.compile(r"eval\s*\("), "Use of eval", "high", "CWE-95"),
        (re.compile(r"exec\s*\("), "Use of exec", "high", "CWE-95"),
        (re.compile(r"SELECT .*\+|execute\(f['\"]|execute\([^,]*(\+|% )"), "Possible unsafe SQL construction", "high", "CWE-89"),
        (re.compile(r"CORS\([^\)]*origins\s*=\s*['\"]\*['\"]|Access-Control-Allow-Origin.*\*"), "Overly broad CORS", "medium", "CWE-942"),
        (re.compile(r"debug\s*=\s*True"), "Debug mode enabled", "medium", "CWE-489"),
    ]
    idx = 1
    for path in target.rglob('*'):
        if not path.is_file() or path.suffix not in CODE_EXTS or should_skip_file(target, path):
            continue
        try:
            lines = path.read_text(errors='ignore').splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for regex, title, severity, cwe in patterns:
                if "re.compile(" in line:
                    continue
                if regex.search(line):
                    findings.append(_finding(f"SF-STATIC-{idx:04d}", title, severity, path, line_no, line, cwe=cwe))
                    idx += 1
    return findings
