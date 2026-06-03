from __future__ import annotations

from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from .models import Finding, Location

SECURITY_HEADERS = {
    "content-security-policy": "Content Security Policy is missing",
    "strict-transport-security": "HSTS header is missing",
    "x-content-type-options": "X-Content-Type-Options header is missing",
    "x-frame-options": "X-Frame-Options header is missing",
}

EXPOSED_PATHS = ("/.env", "/debug", "/swagger.json", "/openapi.json")


def _finding(idx: int, title: str, severity: str, url: str, evidence: str) -> Finding:
    cvss = {"high": 7.0, "medium": 5.0, "low": 2.0, "info": 0.0}[severity]
    return Finding(
        finding_id=f"SF-DAST-{idx:04d}",
        title=title,
        category="DAST",
        cwe_id=None,
        owasp_mapping="A02: Security Misconfiguration",
        severity=severity,
        cvss_score=cvss,
        confidence="medium",
        status="open",
        source_agent="dynamic_baseline",
        location=Location(endpoint=url),
        description="A safe dynamic baseline check found a web security hardening gap.",
        evidence=evidence,
        impact="Attackers may get extra information or abuse weak browser/server defaults.",
        remediation="Harden the web application configuration and rerun the baseline scan.",
        safe_fix_suggestion="Add the missing header or restrict the exposed endpoint, then add an integration test.",
        references=["https://owasp.org/www-project-top-ten/"],
        retest_steps=["Restart the local/staging app.", "Re-run SentinelForge standard scan."],
    )


def run_safe_dynamic_baseline(url: str, *, timeout_seconds: float = 5.0, max_requests: int = 8) -> list[Finding]:
    """Run only low-impact GET/HEAD-style checks against an authorized URL."""
    findings: list[Finding] = []
    idx = 1
    try:
        req = Request(url, headers={"User-Agent": "SentinelForge/1.0 safe-baseline"}, method="GET")
        with urlopen(req, timeout=timeout_seconds) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        findings.append(_finding(idx, "Dynamic baseline could not reach target", "info", url, str(exc)))
        return findings

    for header, title in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_finding(idx, title, "low", url, f"Missing header: {header}"))
            idx += 1

    for path in EXPOSED_PATHS[: max(0, max_requests - 1)]:
        candidate = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
        try:
            req = Request(candidate, headers={"User-Agent": "SentinelForge/1.0 safe-baseline"}, method="GET")
            with urlopen(req, timeout=timeout_seconds) as response:
                if response.status < 400:
                    findings.append(_finding(idx, f"Potentially exposed sensitive path: {path}", "medium", candidate, f"HTTP {response.status}"))
                    idx += 1
        except (HTTPError, URLError, TimeoutError, OSError):
            continue
    return findings
