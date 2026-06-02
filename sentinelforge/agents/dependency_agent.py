from __future__ import annotations

import json
from pathlib import Path
from sentinelforge.models import Finding, Location

RISKY_PACKAGES = {
    "django": ("1.", "Outdated Django major version may contain known security issues."),
    "flask": ("0.", "Outdated Flask major version may contain known security issues."),
    "requests": ("2.19", "Old requests version has known security advisories."),
    "pyyaml": ("3.", "Old PyYAML versions are risky when unsafe loaders are used."),
}


def _finding(idx: int, package: str, version: str, file: Path, description: str) -> Finding:
    return Finding(
        finding_id=f"SF-DEP-{idx:04d}", title=f"Potentially risky dependency: {package} {version}",
        category="Dependency", cwe_id=None, owasp_mapping="A06: Vulnerable and Outdated Components",
        severity="medium", cvss_score=5.0, confidence="low", status="open", source_agent="dependency_agent",
        location=Location(file=str(file), package=package), description=description,
        evidence=f"{package}=={version}", impact="Vulnerable or outdated dependencies may expose the app to known attacks.",
        remediation="Check OSV, NVD, and package advisories, then upgrade to a supported fixed version.",
        safe_fix_suggestion="Update the dependency and run application tests before shipping.",
        references=["https://osv.dev/"], retest_steps=["Upgrade the package.", "Re-run SentinelForge."]
    )


def scan(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    idx = 1
    for req in target.rglob('requirements.txt'):
        for line in req.read_text(errors='ignore').splitlines():
            stripped = line.strip()
            if '==' not in stripped or stripped.startswith('#'):
                continue
            pkg, version = stripped.split('==', 1)
            lower = pkg.lower()
            if lower in RISKY_PACKAGES and version.startswith(RISKY_PACKAGES[lower][0]):
                findings.append(_finding(idx, lower, version, req, RISKY_PACKAGES[lower][1])); idx += 1
    for pkgjson in target.rglob('package.json'):
        try:
            data = json.loads(pkgjson.read_text(errors='ignore'))
        except json.JSONDecodeError:
            continue
        for section in ['dependencies', 'devDependencies']:
            for pkg, version in data.get(section, {}).items():
                if str(version).startswith('*') or str(version).lower() == 'latest':
                    findings.append(_finding(idx, pkg, str(version), pkgjson, "Dependency version is unpinned or uses latest.")); idx += 1
    return findings
