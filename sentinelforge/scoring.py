from __future__ import annotations

from dataclasses import dataclass
from .models import Finding, ScanSummary

PENALTIES = {
    "critical": 30.0,
    "high": 15.0,
    "medium": 6.0,
    "low": 2.0,
    "info": 0.25,
}


def grade_for_score(score: float) -> str:
    if score >= 97:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _is_secret(finding: Finding) -> bool:
    text = f"{finding.title} {finding.category} {finding.description}".lower()
    return any(word in text for word in ["secret", "api key", "token", "private key", "credential"])


def automatic_fail_reasons(findings: list[Finding]) -> list[str]:
    reasons: list[str] = []
    for f in findings:
        text = f"{f.title} {f.category} {f.description} {f.impact}".lower()
        if getattr(f, "known_exploited", False):
            reasons.append(f"Known exploited vulnerability: {f.title}")
        if _is_secret(f) and f.status != "false_positive":
            reasons.append(f"Real or suspected hardcoded secret: {f.title}")
        if "auth bypass" in text or "unauthenticated admin" in text:
            reasons.append(f"Authentication/authorization blocker: {f.title}")
        if "remote code execution" in text or " rce" in text:
            reasons.append(f"Remote code execution risk: {f.title}")
        if "public writable database" in text:
            reasons.append(f"Public writable database risk: {f.title}")
        if "cross-user" in text or "cross user" in text:
            reasons.append(f"Cross-user private data access risk: {f.title}")
    return list(dict.fromkeys(reasons))


def score_findings(findings: list[Finding]) -> ScanSummary:
    score = 100.0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if finding.status == "false_positive":
            continue
        counts[finding.severity] += 1
        score -= PENALTIES[finding.severity]
        if _is_secret(finding):
            score -= 25.0
    score = max(0.0, min(100.0, score))
    grade = grade_for_score(score)
    fail_reasons = automatic_fail_reasons(findings)
    if fail_reasons or grade in {"D", "F"}:
        decision = "Do Not Ship"
    elif grade == "C":
        decision = "Fix Before Serious Users"
    elif grade == "B":
        decision = "Ship After Fixes If Public"
    else:
        decision = "Ship"
    return ScanSummary(
        score=score,
        grade=grade,
        ship_decision=decision,
        automatic_fail_reasons=fail_reasons,
        counts_by_severity=counts,
    )
