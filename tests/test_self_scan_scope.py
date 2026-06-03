from pathlib import Path

from sentinelforge.scanner import run_static_scan


def test_repository_self_scan_excludes_its_own_test_fixtures_reports_and_progress(tmp_path):
    repo = Path(__file__).resolve().parents[1]

    report, _, _ = run_static_scan(repo, tmp_path)

    assert report.summary.score >= 95
    assert report.summary.grade in {"A", "A+"}
    assert report.summary.ship_decision == "Ship"
    assert not report.summary.automatic_fail_reasons
    scanned_files = [f.location.file or "" for f in report.findings]
    assert not any("tests/fixtures" in p for p in scanned_files)
    assert not any("reports/" in p for p in scanned_files)
    assert not any(".hermes_progress" in p for p in scanned_files)


def test_fixture_scan_still_finds_vulnerabilities(tmp_path):
    target = Path(__file__).parent / "fixtures" / "vulnerable_python_app"

    report, _, _ = run_static_scan(target, tmp_path)

    titles = {f.title for f in report.findings}
    assert "Shell command execution with shell=True" in titles
    assert any("hardcoded secret" in title.lower() for title in titles)
    assert report.summary.score < 95
