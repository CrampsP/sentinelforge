from sentinelforge.models import Finding, Location
from sentinelforge.scoring import score_findings


def f(severity, title="x", category="General"):
    return Finding(
        finding_id="SF-T", title=title, category=category, cwe_id=None, owasp_mapping=None,
        severity=severity, cvss_score=0, confidence="medium", status="open", source_agent="test",
        location=Location(), description="d", evidence="e", impact="i", remediation="r",
        safe_fix_suggestion=None, references=[], retest_steps=[]
    )


def test_no_findings_is_a_plus():
    result = score_findings([])
    assert result.score == 100
    assert result.grade == "A+"
    assert result.ship_decision == "Ship"


def test_severity_penalties():
    assert score_findings([f("critical")]).score == 70
    assert score_findings([f("high")]).score == 85
    assert score_findings([f("medium")]).score == 94
    assert score_findings([f("low")]).score == 98
    assert score_findings([f("info")]).score == 99.75


def test_secret_auto_fail():
    result = score_findings([f("high", title="Hardcoded API key", category="Secrets")])
    assert result.automatic_fail_reasons
    assert result.ship_decision == "Do Not Ship"
