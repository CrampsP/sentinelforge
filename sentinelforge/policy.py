from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml

GRADE_ORDER = {"F":0,"D":1,"C":2,"B":3,"A":4,"A+":5}

@dataclass
class Policy:
    minimum_grade: str = "B"
    fail_on_secrets: bool = True
    fail_on_kev: bool = True
    allow_missing_tools: bool = True
    max_high_findings: int = 0
    dynamic_scan_allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])


def default_policy(template: str = "ai-app") -> dict:
    return {
        "template": template,
        "minimum_grade": "B",
        "fail_on_secrets": True,
        "fail_on_kev": True,
        "allow_missing_tools": True,
        "max_high_findings": 0,
        "dynamic_scan_allowed_hosts": ["localhost", "127.0.0.1"],
        "notes": "Beginner-safe default: fail on secrets, known-exploited CVEs, and high-risk issues."
    }


def write_policy(path: str | Path, template: str = "ai-app") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(default_policy(template), sort_keys=False), encoding="utf-8")
    return path


def load_policy(path: str | Path | None = None) -> Policy:
    if path is None or not Path(path).exists():
        return Policy()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    allowed = {k: data[k] for k in Policy.__dataclass_fields__ if k in data}
    return Policy(**allowed)
