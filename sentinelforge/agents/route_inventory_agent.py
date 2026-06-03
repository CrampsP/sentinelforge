from __future__ import annotations

import re
from pathlib import Path
from sentinelforge.models import Finding, Location
from sentinelforge.scan_config import should_skip_file

ROUTE_RE = re.compile(r"@(app|router)\.(route|get|post|put|patch|delete)\(['\"](?P<path>[^'\"]+)")
AUTH_HINT = re.compile(r"login_required|requires_auth|permission|Depends\(|Security\(", re.I)


def scan(target: Path) -> list[Finding]:
    findings=[]; idx=1
    for path in target.rglob("*.py"):
        if should_skip_file(target,path): continue
        lines=path.read_text(errors="ignore").splitlines()
        for n,line in enumerate(lines,1):
            m=ROUTE_RE.search(line)
            if not m: continue
            route=m.group("path")
            window="\n".join(lines[max(0,n-4):min(len(lines),n+4)])
            risky = any(x in route.lower() for x in ["admin","debug","upload","webhook"]) or "<" in route or "{" in route or m.group(2) in {"post","put","patch","delete"}
            if risky and not AUTH_HINT.search(window):
                findings.append(Finding(finding_id=f"SF-ROUTE-{idx:04d}", title=f"Risky route may need auth review: {route}", category="API Route Inventory", cwe_id="CWE-862", owasp_mapping="OWASP API1/API5", severity="medium", cvss_score=5.5, confidence="low", source_agent="route_inventory_agent", location=Location(file=str(path), line_start=n, endpoint=route), description="A route looks sensitive or state-changing and SentinelForge did not see nearby auth hints.", evidence=line.strip(), impact="Broken access control can allow users to access admin functions or other users' data.", remediation="Add explicit authentication/authorization middleware or document why the route is public.", safe_fix_suggestion="Require auth middleware/decorator and add an authorization test.", references=["https://owasp.org/API-Security/"], retest_steps=["Add auth checks.", "Re-run SentinelForge."]))
                idx+=1
    return findings
