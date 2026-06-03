from __future__ import annotations

import re
from pathlib import Path
from sentinelforge.models import Finding, Location
from sentinelforge.scan_config import should_skip_file

AI_IMPORTS = re.compile(r"\b(openai|anthropic|langchain|llama_index|litellm)\b", re.I)
DANGEROUS_AFTER_LLM = re.compile(r"(subprocess\.|eval\(|exec\(|execute\(|render_template_string)", re.I)


def _f(idx:int,title:str,severity:str,path:Path,line:int,evidence:str)->Finding:
    return Finding(finding_id=f"SF-AI-{idx:04d}", title=title, category="AI/LLM Security", cwe_id=None,
        owasp_mapping="OWASP LLM Top 10", severity=severity, cvss_score={"medium":5.5,"high":7.5}[severity], confidence="medium",
        source_agent="ai_app_agent", location=Location(file=str(path), line_start=line, line_end=line),
        description="SentinelForge found a risky AI application pattern.", evidence=evidence.strip()[:500],
        impact="Prompt injection or untrusted model output may trigger unsafe actions or leak sensitive data.",
        remediation="Constrain tools, validate model output, add allowlists, and enforce rate/time/token limits.",
        safe_fix_suggestion="Add a validation layer between model output and any shell, SQL, template, browser, file, or network action.",
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        retest_steps=["Add guardrails and tests.", "Re-run SentinelForge."])


def scan(target: Path) -> list[Finding]:
    findings=[]; idx=1
    for path in target.rglob("*.py"):
        if should_skip_file(target,path): continue
        lines=path.read_text(errors="ignore").splitlines()
        saw_ai=any(AI_IMPORTS.search(x) for x in lines)
        for n,line in enumerate(lines,1):
            lower=line.lower()
            if "re.compile(" in line:
                continue
            if saw_ai and DANGEROUS_AFTER_LLM.search(line):
                findings.append(_f(idx,"LLM output may reach a dangerous sink", "high", path,n,line)); idx+=1
            if saw_ai and ("max_tokens" not in "\n".join(lines)) and ("openai" in lower or "anthropic" in lower):
                findings.append(_f(idx,"AI call may be missing token/cost limits", "medium", path,n,line)); idx+=1
    return findings
