from pathlib import Path
from sentinelforge.scanner import run_static_scan


def test_e2e_vulnerable_project_creates_reports(tmp_path):
    target = Path(__file__).parent / "fixtures" / "vulnerable_python_app"
    report, md, js = run_static_scan(target, tmp_path)
    assert Path(md).exists()
    assert Path(js).exists()
    assert report.findings
    assert report.summary.grade != "A+"
    assert "sk_liv...cdef" not in Path(md).read_text()
