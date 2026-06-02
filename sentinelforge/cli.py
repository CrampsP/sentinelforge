from __future__ import annotations

from pathlib import Path
import typer

from .scanner import run_static_scan

app = typer.Typer(help="SentinelForge security scanner and risk grader.", invoke_without_command=False)


@app.callback()
def main():
    """SentinelForge security scanner and risk grader."""


@app.command()
def scan(
    target: str = typer.Option(..., "--target", help="Path to the authorized target repository."),
    mode: str = typer.Option("static", "--mode", help="Scan mode. v0.1 supports static only."),
    output_dir: str = typer.Option("reports", "--output-dir", help="Directory for reports."),
):
    """Run an authorized SentinelForge scan."""
    if mode != "static":
        raise typer.BadParameter("SentinelForge v0.1 only supports --mode static")
    report, md_path, json_path = run_static_scan(Path(target), Path(output_dir))
    typer.echo(f"SentinelForge scan complete: grade {report.summary.grade}, score {report.summary.score}")
    typer.echo(f"Markdown report: {md_path}")
    typer.echo(f"JSON report: {json_path}")


if __name__ == "__main__":
    app()
