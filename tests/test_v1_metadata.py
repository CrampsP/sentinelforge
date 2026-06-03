from sentinelforge.models import ScanSummary, SecurityReport


def test_security_report_carries_v1_metadata_and_owasp_coverage():
    report = SecurityReport(
        target="fixture",
        scan_mode="static",
        summary=ScanSummary(score=100, grade="A+", ship_decision="Ship"),
    )

    assert report.sentinelforge_version.startswith("1.")
    assert "OWASP Top 10 2025" in report.security_standards
    assert "OWASP API Security Top 10 2023" in report.security_standards
    assert "OWASP LLM Top 10 2.0" in report.security_standards
