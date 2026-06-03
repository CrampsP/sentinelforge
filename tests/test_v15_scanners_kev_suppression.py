import json
from pathlib import Path

from sentinelforge.kev import enrich_with_kev
from sentinelforge.models import Finding, Location
from sentinelforge.suppression import apply_suppressions, load_suppressions
from sentinelforge.tools.generic import parse_json_findings


def make_finding(fid="SF-1", title="pkg CVE-2024-0001"):
    return Finding(
        finding_id=fid, title=title, category="Dependency", severity="medium", cvss_score=5,
        confidence="medium", source_agent="test", location=Location(file="requirements.txt"),
        description="dependency issue", evidence="CVE-2024-0001", impact="bad", remediation="upgrade"
    )


def test_kev_enrichment_marks_known_exploited():
    f = make_finding()
    enriched = enrich_with_kev([f], {"CVE-2024-0001": "Vendor Thing exploited"})
    assert enriched[0].known_exploited is True
    assert enriched[0].severity == "critical"
    assert "Known exploited" in enriched[0].title


def test_suppression_requires_reason_and_marks_status(tmp_path):
    sup = tmp_path / ".sentinelforgeignore"
    sup.write_text('SF-1 reason="test fixture only"\n')
    findings = apply_suppressions([make_finding("SF-1")], load_suppressions(sup))
    assert findings[0].status == "false_positive"
    assert "test fixture" in findings[0].suppression_reason


def test_parse_generic_scanner_json_to_normalized_findings():
    raw = json.dumps([{"title": "Bandit issue", "severity": "high", "file": "app.py", "line": 7, "cwe": "CWE-78"}])
    findings = parse_json_findings(raw, scanner="bandit")
    assert findings[0].source_agent == "bandit"
    assert findings[0].cwe_id == "CWE-78"
