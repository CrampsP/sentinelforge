# SentinelForge v1.5.0 Release Notes

SentinelForge v1.5 is a packaged beginner-friendly security scanner for software you own or are allowed to test.

## Highlights

- Version bumped to 1.5.0.
- Adds AI/LLM app security checks.
- Adds API route inventory checks for risky routes.
- Adds starter policy command: `sentinelforge init-policy`.
- Adds GitHub Actions setup command: `sentinelforge init-ci`.
- Adds plain-English finding explanations: `sentinelforge explain`.
- Adds CISA KEV enrichment helpers for known-exploited CVEs.
- Adds suppression file support with required reasons via `.sentinelforgeignore`.
- Adds HTML report output and badge text output.
- Keeps safe dynamic scan guardrails for local/staging use.
- Keeps public URL scans blocked unless explicitly authorized.

## Package artifacts

The recommended release artifacts are:

- `dist/sentinelforge-1.5.0-py3-none-any.whl`
- `dist/sentinelforge-1.5.0.tar.gz`

## Recommended install

Use pipx:

```bash
pipx install https://github.com/OWNER/REPO/releases/download/v1.5.0/sentinelforge-1.5.0-py3-none-any.whl
```

Or uv:

```bash
uv tool install https://github.com/OWNER/REPO/releases/download/v1.5.0/sentinelforge-1.5.0-py3-none-any.whl
```

## Basic use

```bash
sentinelforge doctor
sentinelforge scan --target ./my-app --mode static
sentinelforge gate --report reports/latest_report.json --minimum-grade B
```
