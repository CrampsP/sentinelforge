from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
Status = Literal["open", "fixed", "accepted_risk", "false_positive"]


class Location(BaseModel):
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    endpoint: str | None = None
    package: str | None = None
    container_layer: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    category: str
    cwe_id: str | None = None
    owasp_mapping: str | None = None
    severity: Severity
    cvss_score: float = Field(ge=0, le=10)
    confidence: Confidence
    status: Status = "open"
    source_agent: str
    location: Location = Field(default_factory=Location)
    description: str
    evidence: str
    impact: str
    remediation: str
    safe_fix_suggestion: str | None = None
    references: list[str] = Field(default_factory=list)
    retest_steps: list[str] = Field(default_factory=list)
    known_exploited: bool = False
    safe_to_auto_fix: bool = False
    suppression_reason: str | None = None


class ToolResult(BaseModel):
    name: str
    status: Literal["ok", "missing", "error", "skipped"]
    command: list[str] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None


class ScanSummary(BaseModel):
    score: float
    grade: str
    ship_decision: str
    automatic_fail_reasons: list[str] = Field(default_factory=list)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)



class SecurityReport(BaseModel):
    sentinelforge_version: str = "1.5.0"
    security_standards: list[str] = Field(default_factory=lambda: [
        "OWASP Top 10 2025",
        "OWASP API Security Top 10 2023",
        "OWASP LLM Top 10 2.0",
        "CISA Known Exploited Vulnerabilities Catalog",
    ])
    target: str
    scan_mode: str
    scan_started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_finished_at: datetime | None = None
    summary: ScanSummary
    tools_run: list[str] = Field(default_factory=list)
    tools_missing: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    blue_team_checklist: list[str] = Field(default_factory=list)
