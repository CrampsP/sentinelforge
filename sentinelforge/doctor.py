from __future__ import annotations

import shutil
from dataclasses import dataclass

REQUIRED_SCANNER_TOOLS = {
    "semgrep": "Static code analysis",
    "bandit": "Python security analysis",
    "osv-scanner": "Open-source dependency vulnerability scanning",
    "trivy": "Filesystem, dependency, container, and IaC scanning",
    "gitleaks": "Secret detection",
}


@dataclass(frozen=True)
class ToolCheck:
    name: str
    purpose: str
    status: str
    path: str | None


def check_tools() -> list[ToolCheck]:
    """Return deterministic readiness information for scanner tools."""
    results: list[ToolCheck] = []
    for name, purpose in REQUIRED_SCANNER_TOOLS.items():
        path = shutil.which(name)
        results.append(
            ToolCheck(
                name=name,
                purpose=purpose,
                status="available" if path else "missing",
                path=path,
            )
        )
    return results


def format_doctor_report(results: list[ToolCheck]) -> str:
    lines = ["SentinelForge tool readiness", ""]
    for result in results:
        marker = "✓" if result.status == "available" else "!"
        location = result.path if result.path else "not installed"
        lines.append(f"{marker} {result.name}: {result.status} — {result.purpose} ({location})")
    missing = [r.name for r in results if r.status == "missing"]
    lines.append("")
    if missing:
        lines.append("Missing tools do not stop SentinelForge, but scans are stronger when they are installed.")
        lines.append("Missing: " + ", ".join(missing))
    else:
        lines.append("All recommended scanner tools are available.")
    return "\n".join(lines)
