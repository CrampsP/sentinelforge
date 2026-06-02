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
python -m sentinelforge.cli scan --target ./my-app --mode static
```

Reports are written to:

- `reports/latest_report.md`
- `reports/latest_report.json`

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
