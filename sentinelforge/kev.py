from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.request import urlopen
from .models import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def load_kev_cache(path: str | Path | None = None) -> dict[str, str]:
    if path and Path(path).exists():
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    else:
        with urlopen(KEV_URL, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
    return {v.get("cveID", "").upper(): v.get("shortDescription", "Known exploited vulnerability") for v in data.get("vulnerabilities", [])}


def enrich_with_kev(findings: list[Finding], kev: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        text = " ".join([f.title, f.description, f.evidence, " ".join(f.references)])
        cves = {m.group(0).upper() for m in CVE_RE.finditer(text)}
        hit = next((c for c in cves if c in kev), None)
        if hit:
            f = f.model_copy(update={
                "known_exploited": True,
                "severity": "critical",
                "cvss_score": max(f.cvss_score, 9.0),
                "title": f"Known exploited: {f.title}",
                "impact": f"Known exploited in the wild ({hit}): {kev[hit]}. " + f.impact,
                "references": list(dict.fromkeys([*f.references, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"])),
            })
        out.append(f)
    return out
