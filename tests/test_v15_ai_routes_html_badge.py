from pathlib import Path

from sentinelforge.agents.ai_app_agent import scan as scan_ai
from sentinelforge.agents.route_inventory_agent import scan as scan_routes
from sentinelforge.models import ScanSummary, SecurityReport
from sentinelforge.reporting import write_reports


def test_ai_app_agent_flags_risky_llm_tool_pattern(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("import openai\nresult = llm(prompt)\nsubprocess.run(result, shell=True)\n")
    findings = scan_ai(tmp_path)
    assert any("LLM output" in f.title for f in findings)


def test_route_inventory_flags_admin_route_without_auth(tmp_path):
    app = tmp_path / "app.py"
    app.write_text('@app.route("/admin", methods=["POST"])\ndef admin():\n    return "ok"\n')
    findings = scan_routes(tmp_path)
    assert any("admin" in f.title.lower() for f in findings)


def test_reports_include_html_and_badge(tmp_path):
    report = SecurityReport(target="fixture", scan_mode="static", summary=ScanSummary(score=100, grade="A+", ship_decision="Ship"), findings=[])
    md, js = write_reports(report, tmp_path)
    html = tmp_path / "latest_report.html"
    badge = tmp_path / "sentinelforge_badge.txt"
    assert Path(md).exists() and Path(js).exists()
    assert Path(html).read_text().startswith("<!doctype html>")
    assert "A+" in Path(badge).read_text()
