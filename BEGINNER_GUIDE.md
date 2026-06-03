# SentinelForge v1.5 — Super Simple Guide

SentinelForge is a safety checker for software projects.

Think of it like this:

- Your app is a house.
- SentinelForge walks around the house and looks for unlocked doors, open windows, and risky wiring.
- It gives the app a score out of 100.
- It tells you if the app looks safe enough to ship.
- It gives you a report with plain-English fix steps.

Important: SentinelForge is only for software you own or are allowed to test.

---

## What SentinelForge does

SentinelForge checks for things like:

- Secret keys accidentally saved in code
- Dangerous code patterns
- Old risky dependencies
- Docker/container mistakes
- Missing scanner tools
- Risky AI/LLM app patterns
- Admin or upload routes that may need login protection
- Basic website security settings for local or staging apps
- Known-exploited vulnerability labels when CISA KEV data is used

It creates these files after a scan:

- reports/latest_report.md — easy-to-read text report
- reports/latest_report.json — machine-readable report
- reports/latest_report.html — simple web page report
- reports/sentinelforge_badge.txt — short score badge text

---

## The easiest way to use it on this VPS

Go to the project folder:

```bash
cd /root/sentinelforge
```

Run a scan on the current project:

```bash
.venv/bin/sentinelforge scan --target . --mode static
```

Read the report:

```bash
less reports/latest_report.md
```

Check if the project passes the safety gate:

```bash
.venv/bin/sentinelforge gate --report reports/latest_report.json --minimum-grade B
```

If it says “Gate passed,” the project met the chosen safety score.

---

## How to scan another app

Replace `/path/to/my-app` with the folder of the app you want to check:

```bash
sentinelforge scan --target /path/to/my-app --mode static
```

Static mode means:

- SentinelForge reads files in the project folder.
- It does not attack a website.
- It does not try passwords.
- It does not change the project.

---

## How to scan a local website safely

If your app is running on your own computer, like this:

```text
http://localhost:3000
```

Run:

```bash
sentinelforge scan --target /path/to/my-app --mode standard --url http://localhost:3000
```

Standard mode means:

- It does the normal file scan.
- It also checks safe web basics, like missing security headers.
- It uses low-impact checks only.

---

## Public websites are blocked by default

SentinelForge will not scan random public websites by default.

Only scan a public/staging website if you own it or have clear permission.

If you are sure you are allowed, use:

```bash
sentinelforge scan --target /path/to/my-app --mode standard --url https://staging.example.com --i-am-authorized --allow-public-target
```

---

## What the score means

- A+ or A: Looks good based on configured checks
- B: Some things to fix, especially before a public launch
- C: Risky; fix before serious users
- D or F: Do not ship yet

No scanner can promise perfect safety. SentinelForge helps catch obvious and dangerous problems before launch.

---

## Helpful commands

Check installed security tools:

```bash
sentinelforge doctor
```

Create a starter safety policy:

```bash
sentinelforge init-policy --template ai-app
```

Create a GitHub Actions safety check:

```bash
sentinelforge init-ci
```

Explain one finding in plain English:

```bash
sentinelforge explain --report reports/latest_report.json --finding-id SF-STATIC-0001
```

Fail a build if the grade is too low:

```bash
sentinelforge gate --report reports/latest_report.json --minimum-grade B
```

---

## Installing the packaged app

The recommended beginner install path is pipx.

Why pipx?

- It installs command-line apps cleanly.
- It keeps SentinelForge away from other Python packages.
- It makes uninstalling easy.

After a GitHub release exists, install the wheel like this:

```bash
pipx install https://github.com/OWNER/REPO/releases/download/v1.5.0/sentinelforge-1.5.0-py3-none-any.whl
```

If you use uv:

```bash
uv tool install https://github.com/OWNER/REPO/releases/download/v1.5.0/sentinelforge-1.5.0-py3-none-any.whl
```

For this local build, the package files are in:

```text
dist/
```

---

## Removing SentinelForge

If installed with pipx:

```bash
pipx uninstall sentinelforge
```

If installed with uv:

```bash
uv tool uninstall sentinelforge
```
