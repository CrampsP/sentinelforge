from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from .agents import static_analysis_agent, dependency_agent, secrets_agent, container_iac_agent, blue_team_agent
from .agents import ai_app_agent, route_inventory_agent, product_profile_agent
from .models import SecurityReport
from .normalization import deduplicate_findings
from .reporting import write_reports
from .scoring import score_findings
from .dynamic import run_safe_dynamic_baseline
from .targeting import validate_dynamic_target
from .kev import enrich_with_kev, load_kev_cache
from .suppression import apply_suppressions, load_suppressions
from .policy import load_policy

SCANNER_TOOLS = {
    "semgrep": "Install Semgrep: python -m pip install semgrep or see https://semgrep.dev/docs/getting-started/",
    "bandit": "Install Bandit: python -m pip install bandit",
    "osv-scanner": "Install OSV-Scanner: https://google.github.io/osv-scanner/installation/",
    "trivy": "Install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
    "gitleaks": "Install Gitleaks: https://github.com/gitleaks/gitleaks#installing",
}


def run_static_scan(target: Path, output_dir: Path = Path("reports")) -> tuple[SecurityReport, Path, Path]:
    return run_scan(target=target, output_dir=output_dir, mode="static")


def run_scan(
    target: Path,
    output_dir: Path = Path("reports"),
    *,
    mode: str = "static",
    url: str | None = None,
    i_am_authorized: bool = False,
    allow_public_target: bool = False,
    policy_path: str | Path | None = None,
    suppression_path: str | Path | None = None,
    kev_path: str | Path | None = None,
    use_kev: bool = False,
) -> tuple[SecurityReport, Path, Path]:
    target = target.resolve()
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"Target directory does not exist: {target}")
    if mode not in {"static", "standard"}:
        raise ValueError("SentinelForge v1.5 supports --mode static and --mode standard")

    policy = load_policy(policy_path)
    product_profile = product_profile_agent.build_profile(target)
    started = datetime.now(timezone.utc)
    findings = []
    findings.extend(static_analysis_agent.scan(target))
    findings.extend(dependency_agent.scan(target))
    findings.extend(secrets_agent.scan(target))
    findings.extend(container_iac_agent.scan(target))
    findings.extend(ai_app_agent.scan(target))
    findings.extend(route_inventory_agent.scan(target))

    if mode == "standard" and url:
        decision = validate_dynamic_target(url, i_am_authorized=i_am_authorized, allow_public_target=allow_public_target)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        findings.extend(run_safe_dynamic_baseline(url))

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
    if use_kev:
        try:
            findings = enrich_with_kev(findings, load_kev_cache(kev_path))
        except Exception:
            pass
    suppress_file = Path(suppression_path) if suppression_path else target / ".sentinelforgeignore"
    findings = apply_suppressions(findings, load_suppressions(suppress_file))
    summary = score_findings(findings)
    report = SecurityReport(
        target=str(target), scan_mode=mode, scan_started_at=started,
        scan_finished_at=datetime.now(timezone.utc), summary=summary, tools_run=tools_run,
        tools_missing=tools_missing, findings=findings,
        blue_team_checklist=blue_team_agent.blue_team_checklist(target),
        product_profile=product_profile,
    )
    md_path, json_path = write_reports(report, output_dir)
    return report, md_path, json_path
