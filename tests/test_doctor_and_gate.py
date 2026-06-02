import json
from pathlib import Path

from typer.testing import CliRunner

from sentinelforge.cli import app
from sentinelforge.doctor import check_tools
from sentinelforge.gate import evaluate_gate

runner = CliRunner()


def test_doctor_check_tools_reports_all_expected_tools():
    results = check_tools()
    names = {result.name for result in results}
    assert {"semgrep", "bandit", "osv-scanner", "trivy", "gitleaks"}.issubset(names)
    assert all(result.status in {"available", "missing"} for result in results)


def test_gate_passes_when_grade_meets_minimum(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"summary": {"grade": "A", "automatic_fail_reasons": []}}))
    result = evaluate_gate(report, minimum_grade="B")
    assert result.passed is True
    assert result.exit_code == 0


def test_gate_fails_when_grade_below_minimum(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"summary": {"grade": "C", "automatic_fail_reasons": []}}))
    result = evaluate_gate(report, minimum_grade="B")
    assert result.passed is False
    assert result.exit_code == 1


def test_gate_fails_on_automatic_fail_reason_even_with_good_grade(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"summary": {"grade": "A", "automatic_fail_reasons": ["Real hardcoded secret"]}}))
    result = evaluate_gate(report, minimum_grade="B")
    assert result.passed is False
    assert "automatic fail" in result.message.lower()


def test_cli_doctor_runs():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "SentinelForge tool readiness" in result.output


def test_cli_gate_command_fails_below_threshold(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"summary": {"grade": "F", "automatic_fail_reasons": []}}))
    result = runner.invoke(app, ["gate", "--report", str(report), "--minimum-grade", "B"])
    assert result.exit_code == 1
    assert "failed" in result.output.lower()
