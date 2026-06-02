# SentinelForge

SentinelForge is an authorized DevSecOps security scanner and risk grader for software you own or are explicitly allowed to test.

## Safety Rules

SentinelForge v0.1 only scans local directories. It does not perform dynamic attacks, exploit chains, credential theft, persistence, lateral movement, denial-of-service testing, or production scanning.

## Version 0.1

The first version provides a static MVP:

- Static code pattern checks
- Dependency risk checks
- Secrets detection with redaction
- Docker/IaC misconfiguration checks
- Risk score and A+ to F grade
- Markdown and JSON reports

## Run

```bash
sentinelforge scan --target ./my-app --mode static
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
