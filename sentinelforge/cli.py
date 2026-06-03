from __future__ import annotations

from pathlib import Path
import typer

from .doctor import check_tools, format_doctor_report
from .gate import evaluate_gate
from .scanner import run_scan

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
):
    """Run an authorized SentinelForge scan."""
    try:
        report, md_path, json_path = run_scan(
            Path(target),
            Path(output_dir),
            mode=mode,
            url=url,
            i_am_authorized=i_am_authorized,
            allow_public_target=allow_public_target,
        )
    except PermissionError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"SentinelForge scan complete: grade {report.summary.grade}, score {report.summary.score}")
    typer.echo(f"Markdown report: {md_path}")
    typer.echo(f"JSON report: {json_path}")


@app.command()
def doctor():
    """Check whether recommended scanner tools are installed."""
    typer.echo(format_doctor_report(check_tools()))


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
