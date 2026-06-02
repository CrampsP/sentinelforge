from typer.testing import CliRunner
from sentinelforge.cli import app

runner = CliRunner()


def test_cli_help_runs():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "SentinelForge" in result.output
