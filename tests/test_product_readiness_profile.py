import json
from pathlib import Path

from sentinelforge.scanner import run_static_scan


def test_ai_product_profile_detects_surfaces_and_next_steps(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        "import openai\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/api/generate', methods=['POST'])\n"
        "def generate():\n"
        "    return 'ok'\n"
    )
    (tmp_path / "requirements.txt").write_text("openai==1.0.0\nflask==3.0.0\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\n")
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text("name: ci\non: [push]\n")

    report, md, js = run_static_scan(tmp_path, tmp_path / "reports")

    assert report.product_profile.is_ai_powered is True
    assert "AI/LLM app" in report.product_profile.detected_surfaces
    assert "Web/API routes" in report.product_profile.detected_surfaces
    assert "Container packaging" in report.product_profile.detected_surfaces
    assert "CI/CD workflow" in report.product_profile.detected_surfaces
    assert any("ZAP" in step for step in report.product_profile.recommended_next_steps)

    data = json.loads(Path(js).read_text())
    assert data["product_profile"]["positioning"] == "AI product production-readiness check"

    markdown = Path(md).read_text()
    assert "AI Product Readiness Snapshot" in markdown
    assert "AI slop" in markdown
    assert "Methodology" in markdown
