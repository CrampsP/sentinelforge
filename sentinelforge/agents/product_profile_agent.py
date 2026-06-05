from __future__ import annotations

import re
from pathlib import Path

from sentinelforge.models import ProductProfile
from sentinelforge.scan_config import should_skip_file

AI_HINT = re.compile(r"\b(openai|anthropic|langchain|llama_index|litellm|ollama|gemini|mistral|claude)\b", re.I)
ROUTE_HINT = re.compile(r"@(app|router)\.(route|get|post|put|patch|delete)|FastAPI\(|Flask\(|express\(", re.I)

DEPENDENCY_FILES = {
    "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "go.mod", "Cargo.toml", "Gemfile.lock", "composer.lock",
}
IAC_FILES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}
CI_PARTS = (".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile")
SECRET_CONFIG_NAMES = (".env", ".env.local", ".env.production", "secrets.yaml", "secrets.yml")


def _add(profile: ProductProfile, surface: str, evidence: str) -> None:
    if surface not in profile.detected_surfaces:
        profile.detected_surfaces.append(surface)
    if evidence not in profile.evidence:
        profile.evidence.append(evidence)


def build_profile(target: Path) -> ProductProfile:
    """Detect product surfaces to make the report feel like a release-readiness audit.

    Methodology is inspired by mature scanner categories (SAST, SCA, secrets,
    IaC/container, DAST, AI security), but all detection logic here is original
    lightweight inventory code.
    """
    profile = ProductProfile()

    for path in target.rglob("*"):
        if not path.is_file() or should_skip_file(target, path):
            continue
        rel = path.relative_to(target).as_posix()
        name = path.name

        if name in DEPENDENCY_FILES:
            _add(profile, "Dependency/supply-chain manifest", rel)
        if name in IAC_FILES or path.suffix in {".tf", ".k8s", ".yaml", ".yml"} and "k8s" in rel.lower():
            _add(profile, "Container packaging", rel)
        if any(part in rel for part in CI_PARTS):
            _add(profile, "CI/CD workflow", rel)
        if name in SECRET_CONFIG_NAMES:
            _add(profile, "Sensitive configuration file", rel)

        if path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php"}:
            continue
        try:
            text = path.read_text(errors="ignore")[:250_000]
        except OSError:
            continue
        if AI_HINT.search(text):
            profile.is_ai_powered = True
            _add(profile, "AI/LLM app", rel)
        if ROUTE_HINT.search(text):
            _add(profile, "Web/API routes", rel)

    if any(surface in profile.detected_surfaces for surface in ["Web/API routes", "AI/LLM app"]):
        profile.recommended_next_steps.append("Run a safe authorized ZAP-style baseline against localhost or staging before production.")
    if "AI/LLM app" in profile.detected_surfaces:
        profile.recommended_next_steps.append("Review prompt-injection boundaries, tool permissions, model output validation, and spend/token limits.")
    if "Dependency/supply-chain manifest" in profile.detected_surfaces:
        profile.recommended_next_steps.append("Generate an SBOM and compare dependency vulnerabilities with OSV/Trivy-style sources.")
    if "Container packaging" in profile.detected_surfaces:
        profile.recommended_next_steps.append("Scan container/IaC settings for root users, exposed ports, latest tags, and missing health checks.")
    if "CI/CD workflow" in profile.detected_surfaces:
        profile.recommended_next_steps.append("Add SentinelForge gate checks to pull requests so AI-generated changes cannot ship without a grade.")

    if not profile.recommended_next_steps:
        profile.recommended_next_steps.append("Add a policy file, run the static scan, and manually review auth/business logic before launch.")

    return profile
