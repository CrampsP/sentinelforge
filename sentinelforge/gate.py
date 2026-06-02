from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

GRADE_ORDER = {
    "F": 0,
    "D": 1,
    "C": 2,
    "B": 3,
    "A": 4,
    "A+": 5,
}


@dataclass(frozen=True)
class GateResult:
    passed: bool
    exit_code: int
    message: str
    grade: str
    minimum_grade: str


def evaluate_gate(report_path: str | Path, minimum_grade: str = "B") -> GateResult:
    path = Path(report_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    summary = data.get("summary", {})
    grade = summary.get("grade")
    fail_reasons = summary.get("automatic_fail_reasons", []) or []

    if grade not in GRADE_ORDER:
        return GateResult(False, 1, f"Gate failed: report has unknown grade {grade!r}.", str(grade), minimum_grade)
    if minimum_grade not in GRADE_ORDER:
        return GateResult(False, 1, f"Gate failed: unknown minimum grade {minimum_grade!r}.", grade, minimum_grade)
    if fail_reasons:
        return GateResult(
            False,
            1,
            "Gate failed: report contains automatic fail conditions: " + "; ".join(str(r) for r in fail_reasons),
            grade,
            minimum_grade,
        )
    if GRADE_ORDER[grade] < GRADE_ORDER[minimum_grade]:
        return GateResult(False, 1, f"Gate failed: grade {grade} is below required {minimum_grade}.", grade, minimum_grade)
    return GateResult(True, 0, f"Gate passed: grade {grade} meets required {minimum_grade}.", grade, minimum_grade)
