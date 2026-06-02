from sentinelforge.models import Finding, Location
from sentinelforge.normalization import deduplicate_findings


def make(fid, severity):
    return Finding(
        finding_id=fid, title="Same", category="X", cwe_id="CWE-79", owasp_mapping=None,
        severity=severity, cvss_score=5, confidence="medium", status="open", source_agent="test",
        location=Location(file="app.py", line_start=1), description="d", evidence="e", impact="i",
        remediation="r", safe_fix_suggestion=None, references=[], retest_steps=[]
    )


def test_deduplicates_same_cwe_file_line_prefers_higher_severity():
    results = deduplicate_findings([make("1", "low"), make("2", "high")])
    assert len(results) == 1
    assert results[0].severity == "high"
