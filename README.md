# SentinelForge

SentinelForge is a beginner-friendly security scanner for software you own or are clearly allowed to test.

If you know almost nothing about computers, start here:

- Read `BEGINNER_GUIDE.md`
- Run `sentinelforge doctor`
- Run `sentinelforge scan --target ./your-app --mode static`
- Open `reports/latest_report.md`

## Safety Rules

SentinelForge v1.0 blocks public dynamic scans by default and only allows low-impact local/staging baseline checks. It does not perform exploit chains, credential theft, persistence, lateral movement, denial-of-service testing, destructive payloads, or production scanning without explicit authorization flags.

## Version 1.5

SentinelForge v1.5 provides a packaged, beginner-friendly security audit baseline:

- Static code pattern checks
- Dependency risk checks
- Secrets detection with redaction
- Docker/IaC misconfiguration checks
- Safe local/staging dynamic baseline checks in `standard` mode
- AI/LLM app security checks
- API route inventory checks
- CISA KEV known-exploited enrichment support
- Policy files, suppression files, GitHub Actions setup, plain-English explanations
- HTML, Markdown, JSON, and badge report outputs
- Authorization guardrails for URL targets
- OWASP Top 10 2025, OWASP API Top 10 2023, OWASP LLM Top 10 2.0, and CISA KEV-aware reporting structure
- Risk score and A+ to F grade
- Markdown and JSON reports

## Run

SentinelForge v1.0 defaults to static local repository scans.

```bash
sentinelforge scan --target ./my-app --mode static
```

For a local or explicitly authorized staging web app, run the safe standard baseline:

```bash
sentinelforge scan --target ./my-app --mode standard --url http://localhost:3000
```

Public URL dynamic scans are blocked unless you explicitly confirm authorization:

```bash
sentinelforge scan --target ./my-app --mode standard --url https://staging.example.com --i-am-authorized --allow-public-target
```

Reports are written to:

- `reports/latest_report.md`
- `reports/latest_report.json`

## Program Core + Agent Layer

SentinelForge is designed as a reliable program first, with an agentic analyst layer on top.

The program core enforces safety, scanner execution, schema normalization, redaction, scoring, reports, and CI gates.

The agent layer explains findings, prioritizes fixes, reviews AI-specific risks, and suggests safe remediation. It must not override program safety controls.

## Useful Commands

Check scanner readiness:

```bash
sentinelforge doctor
```

Fail CI/CD if a report is below a minimum grade:

```bash
sentinelforge gate --report reports/latest_report.json --minimum-grade B
```

## External Scanner Tools

SentinelForge includes placeholders/wrappers for these tools and reports them as missing if not installed:

- Semgrep
- Bandit
- OSV-Scanner
- Trivy
- Gitleaks

The current v0.1 also includes built-in lightweight checks so it can produce useful output even before every external scanner is installed.

## Grade Meaning

- A+ / A: low risk detected by configured scanners
- B: some issues; fix before public launch if internet-facing
- C: moderate risk; fix before serious users
- D / F: do not ship

No scan proves software is perfectly secure. Manual review is still required for business logic, authorization, and abuse cases.
