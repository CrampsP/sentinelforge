import json
from pathlib import Path
from typer.testing import CliRunner

from sentinelforge.cli import app
from sentinelforge.policy import load_policy
from sentinelforge.explain import explain_finding

runner = CliRunner()


def test_init_policy_and_ci_create_beginner_files(tmp_path):
    result = runner.invoke(app, ["init-policy", "--template", "ai-app", "--output", str(tmp_path / "policy.yaml")])
    assert result.exit_code == 0
    policy = load_policy(tmp_path / "policy.yaml")
    assert policy.minimum_grade == "B"
    assert policy.fail_on_kev is True

    ci = runner.invoke(app, ["init-ci", "--output-dir", str(tmp_path / ".github" / "workflows")])
    assert ci.exit_code == 0
    workflow = tmp_path / ".github" / "workflows" / "sentinelforge.yml"
    assert workflow.exists()
    assert "sentinelforge gate" in workflow.read_text()


def test_explain_finding_beginner_output(tmp_path):
    report = {
        "findings": [{
            "finding_id": "SF-X", "title": "Hardcoded API key", "severity": "high",
            "category": "Secrets", "description": "A key is inside the code.",
            "impact": "Someone could use it.", "remediation": "Move it to an environment variable.",
            "retest_steps": ["Run the scan again"], "location": {"file": "app.py", "line_start": 3}
        }]
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    text = explain_finding(path, "SF-X")
    assert "plain english" in text.lower()
    assert "Hardcoded API key" in text
    assert "Run the scan again" in text
