from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from .agents import static_analysis_agent, dependency_agent, secrets_agent, container_iac_agent, blue_team_agent
from .models import SecurityReport
from .normalization import deduplicate_findings
from .reporting import write_reports
from .scoring import score_findings

SCANNER_TOOLS = {
    "semgrep": "Install Semgrep: python -m pip install semgrep or see https://semgrep.dev/docs/getting-started/",
    "bandit": "Install Bandit: python -m pip install bandit",
    "osv-scanner": "Install OSV-Scanner: https://google.github.io/osv-scanner/installation/",
    "trivy": "Install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
    "gitleaks": "Install Gitleaks: https://github.com/gitleaks/gitleaks#installing",
}


def run_static_scan(target: Path, output_dir: Path = Path("reports")) -> tuple[SecurityReport, Path, Path]:
    target = target.resolve()
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"Target directory does not exist: {target}")

    started = datetime.now(timezone.utc)
    findings = []
    findings.extend(static_analysis_agent.scan(target))
    findings.extend(dependency_agent.scan(target))
    findings.extend(secrets_agent.scan(target))
    findings.extend(container_iac_agent.scan(target))

    tools_run: list[str] = []
    tools_missing: list[str] = []
    tool_idx = 1
    for tool, hint in SCANNER_TOOLS.items():
        if shutil.which(tool):
            tools_run.append(tool)
        else:
            tools_missing.append(tool)
            findings.append(blue_team_agent.tool_unavailable_finding(tool_idx, tool, hint))
            tool_idx += 1

    findings = deduplicate_findings(findings)
    summary = score_findings(findings)
    report = SecurityReport(
        target=str(target), scan_mode="static", scan_started_at=started,
        scan_finished_at=datetime.now(timezone.utc), summary=summary, tools_run=tools_run,
        tools_missing=tools_missing, findings=findings,
        blue_team_checklist=blue_team_agent.blue_team_checklist(target),
    )
    md_path, json_path = write_reports(report, output_dir)
    return report, md_path, json_path
