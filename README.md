# SentinelForge

SentinelForge is a local-first security release checker for software you own or are clearly allowed to test.

It helps solo builders, freelancers, AI app developers, and small teams catch common security mistakes before shipping code.

It does not prove an app is perfectly secure. It gives you a practical first-pass security baseline, a risk score, and a plain-English report.

## Who this is for

- Solo founders shipping MVPs
- Freelancers handing projects to clients
- AI app builders using tools like Cursor, Claude Code, Replit, Lovable, Bolt, Windsurf, or Copilot
- Small agencies that want a lightweight client handoff check
- Small teams that want a simple CI security gate before launch

## What SentinelForge checks

SentinelForge v1.5 includes:

- Static code pattern checks
- Dependency risk checks
- Secrets detection with redaction
- Docker/IaC misconfiguration checks
- Safe local/staging dynamic baseline checks in `standard` mode
- AI/LLM app security checks
- API route inventory checks
- CISA KEV known-exploited enrichment support
- Policy files and suppression files
- GitHub Actions setup helper
- Plain-English finding explanations
- HTML, Markdown, JSON, and badge report outputs
- Authorization guardrails for URL targets
- OWASP Top 10 2025, OWASP API Top 10 2023, OWASP LLM Top 10 2.0, and CISA KEV-aware reporting structure
- Risk score and A+ to F grade

## Beginner start

If you know almost nothing about computers, start here:

1. Read `BEGINNER_GUIDE.md`
2. Install the package from the GitHub release
3. Run this command:

```bash
sentinelforge doctor
```

4. Scan a project you own:

```bash
sentinelforge scan --target ./your-app --mode static
```

5. Open the report:

```text
reports/latest_report.md
```

## Install

Download the latest wheel from the GitHub Releases page, then install it with `pipx` or `uv tool install`.

Example with `pipx`:

```bash
pipx install ./sentinelforge-1.5.1-py3-none-any.whl
```

Example with `uv`:

```bash
uv tool install ./sentinelforge-1.5.1-py3-none-any.whl
```

Full beginner install instructions are in:

```text
INSTALL_SENTINELFORGE_v1.5.md
```

## Run

SentinelForge includes free forever trust commands such as `--help`, `doctor`, `explain`, `init-policy`, `init-ci`, `license-status`, and `activate`.

You also get one full local scan trial. After the trial scan is used, continued full scans require an activated SentinelForge license.

Static local repository scan:

```bash
sentinelforge scan --target ./my-app --mode static
```

Safe local or explicitly authorized staging baseline:

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
- `reports/latest_report.html`

## Sample report

Want to see what a report looks like before installing?

Read:

```text
docs/SAMPLE_SECURITY_BASELINE_REPORT.md
```

Short example result:

```text
Score: 11.75 / 100
Grade: F
Decision: Do Not Ship
Top risks: shell command execution, suspected hardcoded secret, debug mode, outdated dependencies, risky Docker settings
```

## Security baseline reviews

SentinelForge can be used locally as a first-pass security release checker. If you want help applying it to your own app, client project, or AI-built codebase, Security Baseline Reviews may be available by request.

Good for:

- AI-built apps before launch
- Freelance/client handoff reports
- MVPs before public release
- Small SaaS projects
- Automation projects using API keys, webhooks, databases, or AI tools

A review can include:

- SentinelForge scan
- Plain-English executive summary
- Top risks and what they mean
- Fix checklist
- Release-readiness grade
- Optional GitHub Actions setup
- Optional walkthrough explaining the report

To request one, open a GitHub issue using the “Security Baseline Review Request” template.

Important: do not paste private code, passwords, API keys, tokens, `.env` files, or confidential client data into a public GitHub issue. The issue should only describe the project at a high level.

## Safety rules

Only scan software you own or have clear written permission to test.

SentinelForge blocks public dynamic scans by default and only allows low-impact local/staging baseline checks unless explicit authorization flags are provided.

SentinelForge does not perform exploit chains, credential theft, persistence, lateral movement, denial-of-service testing, destructive payloads, or unauthorized production scanning.

## What SentinelForge does not promise

SentinelForge does not guarantee that software is secure.

It does not replace:

- A professional penetration test
- A full manual code review
- A full compliance program
- Production monitoring
- Business-logic abuse testing by an expert

Correct promise:

```text
SentinelForge helps catch common and high-risk security mistakes before you ship.
```

## Useful commands

Check scanner readiness:

```bash
sentinelforge doctor
```

Create a starter policy file:

```bash
sentinelforge init-policy
```

Create a GitHub Actions workflow:

```bash
sentinelforge init-ci
```

Check trial/license status:

```bash
sentinelforge license-status
```

Activate a license key after receiving one from the maintainer:

```bash
sentinelforge activate YOUR-LICENSE-KEY
```

Explain one finding in plain English:

```bash
sentinelforge explain --report reports/latest_report.json --finding-id static-001
```

Fail CI/CD if a report is below a minimum grade:

```bash
sentinelforge gate --report reports/latest_report.json --minimum-grade B
```

## External scanner tools

SentinelForge includes wrappers for these tools and reports them as missing if not installed:

- Semgrep
- Bandit
- OSV-Scanner
- Trivy
- Gitleaks

Missing tools do not stop SentinelForge. Scans are stronger when the tools are installed.

## Grade meaning

- A+ / A: low risk detected by configured scanners
- B: some issues; fix before public launch if internet-facing
- C: moderate risk; fix before serious users
- D / F: do not ship

## License

MIT License. See `LICENSE`.
