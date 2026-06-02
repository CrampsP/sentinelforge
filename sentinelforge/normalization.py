from __future__ import annotations

from .models import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    chosen: dict[tuple, Finding] = {}
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    confidence_rank = {"low": 0, "medium": 1, "high": 2}

    for finding in findings:
        key = (
            finding.cwe_id,
            finding.location.file,
            finding.location.line_start,
            finding.location.endpoint,
            finding.location.package,
            finding.title.lower(),
        )
        if key not in chosen:
            chosen[key] = finding
            continue
        current = chosen[key]
        current_score = (confidence_rank[current.confidence], severity_rank[current.severity])
        new_score = (confidence_rank[finding.confidence], severity_rank[finding.severity])
        if new_score > current_score:
            chosen[key] = finding
    return list(chosen.values())
