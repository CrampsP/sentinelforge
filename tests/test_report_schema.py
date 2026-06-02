import json
from pathlib import Path
from sentinelforge.models import ScanSummary, SecurityReport
from sentinelforge.reporting import write_reports


def test_write_reports(tmp_path):
    report = SecurityReport(target="fixture", scan_mode="static", summary=ScanSummary(score=100, grade="A+", ship_decision="Ship"), findings=[])
    md, js = write_reports(report, tmp_path)
    assert Path(md).exists()
    assert Path(js).exists()
    data = json.loads(Path(js).read_text())
    assert data["summary"]["grade"] == "A+"
