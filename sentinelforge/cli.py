from __future__ import annotations

from pathlib import Path
import typer

from .doctor import check_tools, format_doctor_report
from .gate import evaluate_gate
from .scanner import run_scan
from .policy import write_policy
from .ci import write_github_actions
from .explain import explain_finding
from .license import LicenseError, LicenseManager

app = typer.Typer(help="SentinelForge security scanner and risk grader.", invoke_without_command=False)


@app.callback()
def main():
    """SentinelForge security scanner and risk grader."""


@app.command()
def scan(
    target: str = typer.Option(..., "--target", help="Path to the authorized target repository."),
    mode: str = typer.Option("static", "--mode", help="Scan mode: static or standard."),
    output_dir: str = typer.Option("reports", "--output-dir", help="Directory for reports."),
    url: str | None = typer.Option(None, "--url", help="Local/staging URL for safe standard-mode baseline checks."),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="Confirm you are authorized to scan the URL target."),
    allow_public_target: bool = typer.Option(False, "--allow-public-target", help="Allow authorized public URL dynamic scans."),
    policy: str | None = typer.Option(None, "--policy", help="Optional SentinelForge policy YAML."),
    use_kev: bool = typer.Option(False, "--use-kev", help="Try to enrich CVEs with CISA known-exploited data."),
):
    """Run an authorized SentinelForge scan."""
    license_manager = LicenseManager()
    trial_will_be_used = False
    try:
        trial_will_be_used, _ = license_manager.ensure_scan_allowed()
        report, md_path, json_path = run_scan(
            Path(target), Path(output_dir), mode=mode, url=url,
            i_am_authorized=i_am_authorized, allow_public_target=allow_public_target,
            policy_path=policy, use_kev=use_kev,
        )
        if trial_will_be_used:
            license_manager.mark_trial_used()
    except PermissionError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except LicenseError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from exc
    typer.echo(f"SentinelForge scan complete: grade {report.summary.grade}, score {report.summary.score}")
    if trial_will_be_used:
        typer.echo("Free trial scan used. Future scans require an activated SentinelForge license.")
    typer.echo(f"Markdown report: {md_path}")
    typer.echo(f"JSON report: {json_path}")
    typer.echo(f"HTML report: {Path(md_path).with_name('latest_report.html')}")


@app.command("init-policy")
def init_policy(
    template: str = typer.Option("ai-app", "--template", help="Policy template name."),
    output: str = typer.Option("sentinelforge.policy.yaml", "--output", help="Where to write the policy file."),
):
    """Create a starter policy file."""
    path = write_policy(output, template)
    typer.echo(f"Created policy file: {path}")


@app.command("init-ci")
def init_ci(
    output_dir: str = typer.Option(".github/workflows", "--output-dir", help="Where to create the GitHub Actions workflow."),
):
    """Create a GitHub Actions workflow that runs SentinelForge."""
    path = write_github_actions(output_dir)
    typer.echo(f"Created GitHub Actions workflow: {path}")


@app.command()
def explain(
    report: str = typer.Option(..., "--report", help="Path to SentinelForge JSON report."),
    finding_id: str = typer.Option(..., "--finding-id", help="Finding ID to explain."),
):
    """Explain one finding in very plain English."""
    typer.echo(explain_finding(report, finding_id))


@app.command()
def doctor():
    """Check whether recommended scanner tools are installed."""
    typer.echo(format_doctor_report(check_tools()))


@app.command("license-status")
def license_status():
    """Show SentinelForge trial/license status."""
    status = LicenseManager().status()
    if status.activated:
        typer.echo("License active. Unlimited local scans are enabled.")
        if status.license_id:
            typer.echo(f"License id: {status.license_id}")
        if status.customer_email:
            typer.echo(f"Licensed email: {status.customer_email}")
        return
    if status.trial_used:
        typer.echo("Trial scan used. Continued scans require an activated SentinelForge license.")
        if status.trial_used_at:
            typer.echo(f"Trial used at: {status.trial_used_at}")
        typer.echo("After you receive a key, run: sentinelforge activate YOUR-LICENSE-KEY")
        return
    typer.echo("Trial scan available. You can run one full SentinelForge scan before activation is required.")


@app.command()
def activate(
    license_key: str = typer.Argument(..., help="SentinelForge license key."),
):
    """Activate SentinelForge with a license key."""
    try:
        status = LicenseManager().activate(license_key)
    except LicenseError as exc:
        typer.echo(f"Invalid license key: {exc}")
        raise typer.Exit(code=2) from exc
    typer.echo("License activated. Unlimited local scans are enabled.")
    if status.license_id:
        typer.echo(f"License id: {status.license_id}")


@app.command()
def gate(
    report: str = typer.Option(..., "--report", help="Path to SentinelForge JSON report."),
    minimum_grade: str = typer.Option("B", "--minimum-grade", help="Minimum acceptable grade."),
):
    """Fail CI/CD if a report does not meet the configured security grade."""
    result = evaluate_gate(Path(report), minimum_grade=minimum_grade)
    typer.echo(result.message)
    raise typer.Exit(code=result.exit_code)


if __name__ == "__main__":
    app()
