from __future__ import annotations

from pathlib import Path
from sentinelforge.models import Finding, Location


def scan(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    idx = 1
    dockerfiles = list(target.rglob('Dockerfile')) + list(target.rglob('*.Dockerfile'))
    for dockerfile in dockerfiles:
        lines = dockerfile.read_text(errors='ignore').splitlines()
        has_user = any(line.strip().upper().startswith('USER ') for line in lines)
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith('FROM ') and (':latest' in stripped or ':' not in stripped.split()[1]):
                findings.append(_iac(idx, "Docker image uses latest or unpinned tag", "medium", dockerfile, line_no, stripped)); idx += 1
            if stripped.upper().startswith('EXPOSE ') and any(port in stripped for port in ['22', '2375', '5432', '3306', '6379']):
                findings.append(_iac(idx, "Potentially sensitive port exposed in Dockerfile", "medium", dockerfile, line_no, stripped)); idx += 1
        if not has_user:
            findings.append(_iac(idx, "Container may run as root because no USER is set", "low", dockerfile, 1, "No USER directive found")); idx += 1
    for compose in list(target.rglob('docker-compose.yml')) + list(target.rglob('docker-compose.yaml')):
        lines = compose.read_text(errors='ignore').splitlines()
        for line_no, line in enumerate(lines, start=1):
            if 'privileged: true' in line:
                findings.append(_iac(idx, "Privileged container enabled", "high", compose, line_no, line)); idx += 1
            if '/var/run/docker.sock' in line:
                findings.append(_iac(idx, "Docker socket mounted into container", "high", compose, line_no, line)); idx += 1
    return findings


def _iac(idx: int, title: str, severity: str, file: Path, line: int, evidence: str) -> Finding:
    cvss = {"high": 7.2, "medium": 5.0, "low": 2.0}[severity]
    return Finding(
        finding_id=f"SF-IAC-{idx:04d}", title=title, category="Container/IaC", cwe_id=None,
        owasp_mapping="A05: Security Misconfiguration", severity=severity, cvss_score=cvss,
        confidence="medium", status="open", source_agent="container_iac_agent",
        location=Location(file=str(file), line_start=line, line_end=line),
        description="A deployment configuration appears to use an insecure default or risky container setting.",
        evidence=evidence.strip(), impact="Container and infrastructure misconfigurations can increase blast radius if the app is compromised.",
        remediation="Harden the container or deployment config using least privilege, pinned images, non-root users, and minimal exposed ports.",
        safe_fix_suggestion="Pin image versions, add a non-root USER, remove privileged mode, and avoid mounting host-sensitive paths.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
        retest_steps=["Update deployment configuration.", "Re-run SentinelForge static scan."]
    )
