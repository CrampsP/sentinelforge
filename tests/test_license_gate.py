from __future__ import annotations

import json
from types import SimpleNamespace

from typer.testing import CliRunner

from sentinelforge.cli import app
from sentinelforge.license import create_private_key_pem, generate_license_key, public_key_pem_from_private

runner = CliRunner()


def test_license_status_is_free_command_with_fresh_trial_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path / "sfhome"))

    result = runner.invoke(app, ["license-status"])

    assert result.exit_code == 0
    assert "Trial scan available" in result.output


def test_first_scan_uses_trial_and_second_scan_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path / "sfhome"))

    calls = []

    def fake_run_scan(*args, **kwargs):
        calls.append((args, kwargs))
        md = tmp_path / "latest_report.md"
        js = tmp_path / "latest_report.json"
        md.write_text("report")
        js.write_text("{}")
        return SimpleNamespace(summary=SimpleNamespace(grade="A", score=97.0)), md, js

    monkeypatch.setattr("sentinelforge.cli.run_scan", fake_run_scan)

    first = runner.invoke(app, ["scan", "--target", str(tmp_path), "--output-dir", str(tmp_path / "reports")])
    second = runner.invoke(app, ["scan", "--target", str(tmp_path), "--output-dir", str(tmp_path / "reports2")])

    assert first.exit_code == 0
    assert "Free trial scan used" in first.output
    assert second.exit_code != 0
    assert "free SentinelForge scan has already been used" in second.output
    assert len(calls) == 1


def test_activation_with_signed_license_allows_unlimited_scans(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path / "sfhome"))
    private_key_file = tmp_path / "license_private.pem"
    private_pem = create_private_key_pem()
    private_key_file.write_text(private_pem)
    monkeypatch.setenv("SENTINELFORGE_LICENSE_PUBLIC_KEY_PEM", public_key_pem_from_private(private_pem))
    key = generate_license_key(
        private_key_path=private_key_file,
        license_id="test-001",
        customer_email="buyer@example.com",
    )

    activate = runner.invoke(app, ["activate", key])
    assert activate.exit_code == 0
    assert "License activated" in activate.output

    calls = []

    def fake_run_scan(*args, **kwargs):
        calls.append((args, kwargs))
        md = tmp_path / f"report_{len(calls)}.md"
        js = tmp_path / f"report_{len(calls)}.json"
        md.write_text("report")
        js.write_text("{}")
        return SimpleNamespace(summary=SimpleNamespace(grade="A", score=97.0)), md, js

    monkeypatch.setattr("sentinelforge.cli.run_scan", fake_run_scan)

    first = runner.invoke(app, ["scan", "--target", str(tmp_path), "--output-dir", str(tmp_path / "reports")])
    second = runner.invoke(app, ["scan", "--target", str(tmp_path), "--output-dir", str(tmp_path / "reports2")])

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert len(calls) == 2


def test_bad_license_key_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path / "sfhome"))

    result = runner.invoke(app, ["activate", "SF1.not-a-real-license"])

    assert result.exit_code != 0
    assert "Invalid license key" in result.output


def test_license_file_does_not_store_raw_license_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path / "sfhome"))
    private_key_file = tmp_path / "license_private.pem"
    private_pem = create_private_key_pem()
    private_key_file.write_text(private_pem)
    monkeypatch.setenv("SENTINELFORGE_LICENSE_PUBLIC_KEY_PEM", public_key_pem_from_private(private_pem))
    key = generate_license_key(
        private_key_path=private_key_file,
        license_id="test-002",
        customer_email="buyer@example.com",
    )

    result = runner.invoke(app, ["activate", key])

    assert result.exit_code == 0
    state = json.loads((tmp_path / "sfhome" / "license.json").read_text())
    assert key not in json.dumps(state)
    assert state["activated"] is True
    assert "license_key_hash" in state
