# SentinelForge v1.0 Product and Build Plan

> **Purpose:** Turn SentinelForge from a static MVP into a real v1.0 cybersecurity risk auditor, pentester, analyzer, grader, and remediation assistant for software the user owns or is explicitly authorized to test.

**Current State:** SentinelForge v0.1 exists as a working Python CLI static scanner. It can scan a local repository, detect simple static risks, grade the project, and produce Markdown + JSON reports.

**v1.0 Goal:** SentinelForge can safely evaluate an owned software project from code to dependencies to containers to local/staging runtime, then produce a trustworthy security grade, clear report, CI/CD gate result, and optional approved fix plan.

---

## 1. v1.0 Mission

SentinelForge v1.0 should answer this question:

> “Is this AI-built or human-built application safe enough to ship?”

It should help solo developers and small teams catch obvious and dangerous security issues before launching.

It should combine:

1. Static application security testing.
2. Dependency and supply-chain scanning.
3. Secret detection.
4. Docker and infrastructure security review.
5. Safe dynamic web/API testing against local or staging targets.
6. Authentication and authorization review.
7. Blue-team hardening review.
8. AI-application security review.
9. Scoring and grading.
10. Beginner-friendly reporting.
11. CI/CD gate support.
12. Approved remediation suggestions.

---

## 2. Non-Negotiable Safety Rules

SentinelForge must remain an authorized security tool, not an illegal hacking tool.

### Allowed

SentinelForge may scan:

- Local repositories.
- Local web apps.
- Local APIs.
- Local Docker containers.
- User-owned staging apps.
- User-owned CI/CD pipelines.
- User-owned cloud deployments.
- Explicitly authorized production targets, only with clear confirmation.

### Blocked

SentinelForge must not scan:

- Random public websites.
- Third-party companies.
- School systems.
- Employer systems without written permission.
- Government systems.
- Personal accounts not owned by the user.
- Production systems unless explicitly authorized.
- Any target where permission is unclear.

### Never Do

SentinelForge must never:

- Steal credentials.
- Exfiltrate data.
- Attempt persistence.
- Move laterally.
- Perform denial-of-service testing.
- Run destructive exploits.
- Modify production without approval.
- Auto-merge patches.
- Reveal full secrets in reports.

---

## 3. v1.0 Definition of Done

SentinelForge v1.0 is done when all of these are true:

1. `sentinelforge scan --target ./app --mode static` works reliably.
2. `sentinelforge scan --target ./app --url http://localhost:3000 --mode standard` works for local/staging apps.
3. Reports are generated in both Markdown and JSON.
4. Reports include:
   - Executive summary
   - Final grade
   - Risk score
   - Ship/no-ship decision
   - Critical blockers
   - Top 5 risks
   - Full findings
   - Fix plan
   - Retest plan
   - Blue-team checklist
   - CI/CD recommendation
5. Scanner output is normalized into one finding schema.
6. Secrets are redacted.
7. Findings are deduplicated.
8. Missing scanner tools do not crash the scan.
9. The scanner refuses unsafe dynamic targets by default.
10. CI gate command can fail builds below a configured grade.
11. Tests cover scoring, redaction, deduplication, schemas, CLI, report generation, and sample vulnerable apps.
12. README explains safety boundaries and usage clearly.

---

## 4. v1.0 Product Shape

### Main Commands

```bash
sentinelforge scan --target ./my-app --mode static
```

Runs local code/dependency/secrets/container checks.

```bash
sentinelforge scan --target ./my-app --url http://localhost:3000 --mode standard
```

Runs static scan plus safe dynamic tests against a local/staging URL.

```bash
sentinelforge gate --report reports/latest_report.json --minimum-grade B
```

Fails with non-zero exit code if the report does not meet policy.

```bash
sentinelforge init-policy --template ai-app
```

Creates a starter policy file.

```bash
sentinelforge doctor
```

Checks installed tools and tells the user what is missing.

```bash
sentinelforge explain --finding-id SF-2026-0001
```

Explains a finding in beginner-friendly language.

---

## 5. v1.0 Architecture

```text
User / Developer
      |
      v
CLI / Config / Policy
      |
      v
Security Orchestrator
      |
      |-------------------------------|
      |                               |
      v                               v
Static Analysis Agent          Dynamic Web/API Agent
      |                               |
      v                               v
Dependency Agent               Auth Testing Agent
      |                               |
      v                               v
Secrets Agent                  Blue Team Agent
      |                               |
      v                               v
Container/IaC Agent            AI Security Agent
      |                               |
      |---------------|---------------|
                      v
             Finding Normalizer
                      |
                      v
              Deduplication Engine
                      |
                      v
              Risk Scoring Engine
                      |
                      v
              Report Generator
                      |
                      v
Markdown Report / JSON Report / CI Gate / Fix Suggestions
```

---

## 6. v1.0 Agent Responsibilities

### 6.1 Security Orchestrator Agent

The Orchestrator coordinates the scan.

Responsibilities:

- Parse target input.
- Load policy.
- Confirm authorization.
- Decide which agents run.
- Enforce safe testing boundaries.
- Collect all findings.
- Normalize findings.
- Deduplicate findings.
- Score risk.
- Generate final reports.
- Decide ship/no-ship.

v1.0 requirement:

- Dynamic scans are disabled unless URL is localhost, private network, or explicitly allowed by policy.
- Production dynamic scans require explicit confirmation flag.

---

### 6.2 Static Analysis Agent

Purpose:

- Read source code without running the application.

Tools:

- Semgrep
- Bandit
- ESLint security plugin if JavaScript/TypeScript is present
- gosec if Go is present
- Built-in lightweight rules as fallback

Must detect:

- Hardcoded credentials
- Command injection
- SQL injection patterns
- Unsafe deserialization
- Weak cryptography
- Insecure randomness
- XSS risk patterns
- Path traversal
- Missing input validation
- Insecure file uploads
- Debug endpoints
- Frontend-only admin protection
- Weak JWT validation
- Missing auth middleware patterns

v1.0 requirement:

- Real Semgrep and Bandit integration should be wired, not only placeholder wrappers.

---

### 6.3 Dependency and Supply Chain Agent

Purpose:

- Find vulnerable, outdated, suspicious, or unpinned dependencies.

Tools:

- OSV-Scanner
- Trivy filesystem scan
- npm audit if Node project
- pip-audit if Python project
- cargo audit if Rust project

Must inspect:

- `package.json`
- lockfiles
- `requirements.txt`
- `pyproject.toml`
- `go.mod`
- `Cargo.toml`
- Docker base images
- GitHub Actions

v1.0 requirement:

- Findings include package, installed version, advisory/CVE, fixed version if available, severity, and remediation.

---

### 6.4 Secrets Detection Agent

Purpose:

- Find secrets in code, configs, docs, logs, and optionally git history.

Tools:

- Gitleaks
- TruffleHog optional
- Built-in regex fallback

Must detect:

- API keys
- JWT secrets
- database URLs
- OAuth secrets
- private keys
- cloud credentials
- webhook secrets
- `.env` leakage

v1.0 requirement:

- Never print the full secret.
- Report masked evidence.
- Distinguish likely placeholder vs likely real.
- Real-looking secrets trigger automatic fail.

---

### 6.5 Container and IaC Agent

Purpose:

- Review Docker, Docker Compose, Kubernetes, Terraform, and CI/CD config.

Tools:

- Trivy
- Checkov
- Hadolint

Must detect:

- Running as root
- `latest` tags
- privileged containers
- Docker socket mounts
- exposed sensitive ports
- missing health checks
- missing resource limits
- secrets in Compose
- unsafe GitHub Actions permissions
- public buckets if IaC exists
- overly broad IAM if IaC exists

v1.0 requirement:

- Dockerfile and Compose checks must be stable.
- Terraform/Kubernetes can be best-effort but should normalize findings.

---

### 6.6 Dynamic Web/API Agent

Purpose:

- Run safe runtime checks against local or staging apps.

Tools:

- HTTPX or requests-based custom probes
- OWASP ZAP baseline scan
- Nuclei safe templates only
- OpenAPI validator if schema exists

Allowed checks:

- Security headers
- Cookie flags
- CORS behavior
- error leakage
- directory listing
- unauthenticated protected routes
- exposed admin paths
- basic reflected input checks
- rate limiting presence
- OpenAPI route mismatch

Blocked checks:

- Destructive payloads
- DoS
- credential brute force
- persistence
- lateral movement
- exploit chains
- real data exfiltration

v1.0 requirement:

- Must require URL allowlist or confirmation.
- Must rate-limit requests.
- Must produce endpoint-specific findings.

---

### 6.7 Authentication and Authorization Agent

Purpose:

- Find broken login, session, role, and object-level access control problems.

Checks:

- Anonymous access to protected routes
- Normal user access to admin routes
- JWT verification mistakes
- insecure cookies
- password reset weakness
- client-side role trust
- route middleware gaps
- object ownership checks
- multi-tenant boundaries

v1.0 realistic scope:

- Static review of auth code.
- Dynamic route checks for anonymous vs authenticated only if test credentials are provided.
- Full IDOR testing can be v1.1.

---

### 6.8 Blue Team Defense Agent

Purpose:

- Evaluate whether the app is defensible.

Checks:

- Security headers
- CSP
- HSTS
- cookie flags
- rate limiting
- auth failure logging
- admin action logging
- error monitoring
- backups
- branch protection
- dependency updates
- incident response notes
- environment separation

v1.0 requirement:

- Generate a hardening checklist with “required before production” vs “recommended later.”

---

### 6.9 AI Application Security Agent

Purpose:

- Review AI-powered apps, RAG systems, and tool-using agents.

Checks:

- prompt injection risk
- tool permission scope
- shell/file/network access
- secrets in model context
- user data exposure
- RAG cross-user leakage
- missing approval gates
- missing audit logs
- spend/rate limits
- output validation
- sandboxing

v1.0 realistic scope:

- Static/config review for AI apps.
- Detect common AI-agent tool risks.
- Generate recommendations.

---

### 6.10 Report Generator Agent

Purpose:

- Convert technical findings into clear reports.

Must produce:

- Markdown report
- JSON report
- grade card
- top 5 risks
- critical blockers
- fix plan
- retest steps
- blue-team checklist
- CI/CD recommendation

v1.0 requirement:

- Reports must be useful to beginners and engineers.
- No full secrets.
- No “perfectly secure” claims.

---

### 6.11 Fix Agent

Purpose:

- Suggest safe fixes.

v1.0 scope:

- Generate patch suggestions and instructions.
- Do not apply patches by default.
- Optional `--suggest-fixes` mode can generate diff files under `reports/fixes/`.

Must not:

- Auto-merge.
- Deploy.
- Rotate real secrets without approval.
- Suppress findings without justification.
- Rewrite large code areas without explanation.

---

## 7. Standard Finding Schema

All findings must use this shape:

```json
{
  "finding_id": "SF-2026-0001",
  "title": "string",
  "category": "string",
  "cwe_id": "string or null",
  "owasp_mapping": "string or null",
  "severity": "info | low | medium | high | critical",
  "cvss_score": 0.0,
  "confidence": "low | medium | high",
  "status": "open | fixed | accepted_risk | false_positive",
  "source_agent": "string",
  "location": {
    "file": "string or null",
    "line_start": "number or null",
    "line_end": "number or null",
    "endpoint": "string or null",
    "package": "string or null",
    "container_layer": "string or null"
  },
  "description": "string",
  "evidence": "string",
  "impact": "string",
  "remediation": "string",
  "safe_fix_suggestion": "string or null",
  "references": ["string"],
  "retest_steps": ["string"]
}
```

---

## 8. Scoring Engine v1.0

Start at 100 points.

Subtract:

- Critical: -30
- High: -15
- Medium: -6
- Low: -2
- Info: -0.25

Additional penalties:

- Internet-facing high/critical: -10
- PII involved: -10
- No auth on sensitive route: -20
- Real secret exposed: -25
- Known exploited CVE: -20
- Production debug exposure: -20
- Public database exposure: -30
- Payment manipulation risk: -30
- Cross-user private data access: -25

Reductions:

- Dev-only dependency: reduce dependency penalty by 50%
- Unreachable dependency: reduce dependency penalty by 50%
- Strong compensating control: reduce penalty by 25%
- Confirmed false positive: remove penalty

Grades:

- A+: 97–100
- A: 90–96
- B: 80–89
- C: 70–79
- D: 60–69
- F: 0–59

Automatic fail:

- Real hardcoded secret
- Auth bypass
- Unauthenticated admin access
- SQL injection affecting sensitive data
- Remote code execution
- Public writable database
- Production debug console exposed
- Cross-user private data access
- Critical reachable dependency with known exploit
- Payment or billing manipulation flaw
- Privilege escalation
- Missing authorization on multi-tenant resources

---

## 9. v1.0 Build Phases

## Phase 1: Harden v0.1 Static Scanner

**Goal:** Make the current MVP reliable.

### Tasks

1. Add real Semgrep execution and parsing.
2. Add real Bandit execution and parsing.
3. Add real Gitleaks execution and parsing.
4. Add real OSV-Scanner execution and parsing.
5. Add real Trivy filesystem execution and parsing.
6. Keep built-in fallback checks.
7. Improve severity mapping.
8. Improve deduplication.
9. Improve report wording.
10. Add `sentinelforge doctor`.

### Acceptance Criteria

- External tools run when installed.
- Missing tools produce info findings, not crashes.
- Reports clearly separate tool-backed findings from fallback findings.
- Tests pass.

---

## Phase 2: Policy System and CI Gate

**Goal:** Make SentinelForge configurable and CI/CD friendly.

### Tasks

1. Implement policy loading from YAML.
2. Add default, strict, startup, and ai-app policies.
3. Add `sentinelforge init-policy`.
4. Add `sentinelforge gate`.
5. Add GitHub Actions example.
6. Add JSON schema validation.
7. Add report version field.

### Acceptance Criteria

- CI can fail if grade is below B.
- CI can fail on critical findings.
- CI can fail on real secrets.
- User can configure thresholds.

---

## Phase 3: Dynamic Safety Layer

**Goal:** Prepare safe runtime scanning without allowing reckless scans.

### Tasks

1. Add URL parser.
2. Allow dynamic scan only for localhost/private/staging allowlist by default.
3. Add `--confirm-authorized` for non-local targets.
4. Add rate limiter.
5. Add request timeout.
6. Add max request count.
7. Add audit log of dynamic requests.

### Acceptance Criteria

- Random public URLs are refused by default.
- Local URLs are allowed.
- Dynamic scan logs every request.
- No destructive tests exist.

---

## Phase 4: Basic Dynamic Web/API Scan

**Goal:** Find runtime misconfigurations.

### Tasks

1. Implement security headers check.
2. Implement cookie flag check.
3. Implement CORS check.
4. Implement common path exposure check.
5. Implement error leakage check.
6. Implement basic rate-limit smoke check.
7. Implement OpenAPI route inspection if schema exists.
8. Normalize dynamic findings.

### Acceptance Criteria

- Local app scan works.
- Missing headers are reported.
- Insecure cookies are reported.
- Broad CORS is reported.
- Exposed admin/common paths are reported without brute force.

---

## Phase 5: Auth and Access Control Review

**Goal:** Catch common AI-generated access-control mistakes.

### Tasks

1. Static review for auth middleware patterns.
2. Static review for client-side role trust.
3. Static review for decoded-but-unverified JWT.
4. Static review for missing owner/tenant scoping patterns.
5. Optional test account config.
6. Anonymous vs authenticated route comparison.
7. Normal user vs admin route comparison when credentials provided.

### Acceptance Criteria

- Missing server-side admin checks are flagged when obvious.
- Anonymous protected route access is flagged dynamically when detectable.
- Test credentials are never printed.

---

## Phase 6: Blue Team and AI Security Review

**Goal:** Make SentinelForge useful beyond vulnerability lists.

### Tasks

1. Add production hardening checklist.
2. Add AI-agent permission review.
3. Add RAG isolation review patterns.
4. Add prompt-injection defense checklist.
5. Add audit logging recommendations.
6. Add rate/spend limit recommendations.
7. Add backup and incident response checklist.

### Acceptance Criteria

- Reports explain missing defenses clearly.
- AI apps get AI-specific recommendations.
- Blue-team items are prioritized as production-blocking or recommended.

---

## Phase 7: Fix Suggestions

**Goal:** Help the user fix issues without unsafe automation.

### Tasks

1. Add `--suggest-fixes` option.
2. Generate patch suggestions under `reports/fixes/`.
3. Generate dependency upgrade suggestions.
4. Generate middleware snippets for headers/rate limits.
5. Generate Dockerfile hardening snippets.
6. Add retest instructions.

### Acceptance Criteria

- SentinelForge suggests fixes.
- It does not modify target files unless a future explicit mode is added.
- Every fix suggestion includes risk and retest steps.

---

## 10. Recommended v1.0 File Structure

```text
sentinelforge/
  README.md
  pyproject.toml

  sentinelforge/
    cli.py
    scanner.py
    policy.py
    scoring.py
    reporting.py
    redaction.py
    normalization.py
    safety.py
    gate.py
    doctor.py

    agents/
      orchestrator.py
      static_analysis_agent.py
      dependency_agent.py
      secrets_agent.py
      container_iac_agent.py
      dynamic_web_agent.py
      auth_agent.py
      blue_team_agent.py
      ai_security_agent.py
      fix_agent.py

    tools/
      base.py
      semgrep_runner.py
      bandit_runner.py
      gitleaks_runner.py
      osv_runner.py
      trivy_runner.py
      zap_runner.py
      nuclei_runner.py
      checkov_runner.py
      hadolint_runner.py

    schemas/
      finding.schema.json
      report.schema.json
      policy.schema.json

    policies/
      default_policy.yaml
      strict_policy.yaml
      startup_policy.yaml
      ai_app_policy.yaml

    prompts/
      orchestrator.md
      static_analysis_agent.md
      dependency_agent.md
      secrets_agent.md
      container_iac_agent.md
      dynamic_web_agent.md
      auth_agent.md
      blue_team_agent.md
      ai_security_agent.md
      report_agent.md
      fix_agent.md

  reports/
  tests/
    fixtures/
```

---

## 11. Monetizable v1.0 Angle

SentinelForge should be built with monetization in mind.

Possible paid users:

- Solo developers building with AI.
- Indie hackers launching SaaS apps.
- Small agencies shipping client apps.
- No-code/low-code builders.
- AI automation builders.

Potential v1.0 positioning:

> “Security grading for AI-built apps before you ship.”

Possible pricing:

- Free/local CLI for basic scans.
- $9/month for hosted report dashboard.
- $19/month for CI/CD scans and history.
- $49/month for teams/agencies.
- One-time $29 security launch checklist/report generator.

First realistic money path:

- Keep CLI open/local.
- Build a simple landing page.
- Offer “AI App Security Grade Report” as a service.
- Use SentinelForge manually/semiautomatically to audit small apps.
- Charge $29–$99 per report before building SaaS dashboard.

---

## 12. Immediate Next Tasks From Current v0.1

These are the next engineering steps after the current working MVP:

1. Add `doctor` command.
2. Install Semgrep and Bandit first because they are easiest.
3. Wire actual Semgrep JSON parsing.
4. Wire actual Bandit JSON parsing.
5. Improve report distinction between fallback findings and real scanner findings.
6. Add `gate` command.
7. Add policy loader.
8. Add dynamic scan safety module.
9. Add security header checks.
10. Create GitHub repo and push the project.

---

## 13. v1.0 Success Demo

A strong v1.0 demo should show:

1. A vulnerable AI-generated sample app.
2. Run:

```bash
sentinelforge scan --target ./sample-ai-app --url http://localhost:3000 --mode standard
```

3. SentinelForge finds:
   - hardcoded secret
   - vulnerable dependency
   - missing auth check
   - missing security headers
   - broad CORS
   - Docker root user
   - missing rate limiting
4. It gives a grade like D or F.
5. It explains the top 5 risks in beginner language.
6. It generates fix suggestions.
7. After fixes, rerun scan.
8. Grade improves to A or B.

That demo is the product story.

---

## 14. Final v1.0 Summary

SentinelForge v1.0 should be a practical, safe, local-first security auditor for AI-built software.

It does not need to be a full enterprise pentesting suite. It needs to reliably catch the obvious and dangerous things that solo builders and AI agents commonly miss:

- secrets
- vulnerable packages
- unsafe code patterns
- bad Docker config
- missing auth
- bad CORS
- missing security headers
- weak cookies
- missing rate limits
- missing logs
- risky AI-agent permissions

If it does those well, explains them clearly, grades them honestly, and helps fix them safely, v1.0 will be genuinely useful and potentially monetizable.
