# Sample SentinelForge Security Baseline Report

This is a safe public sample report generated from an intentionally vulnerable demo app.

Do not copy the demo app into production. It contains fake mistakes on purpose so SentinelForge has something to find.

## Executive summary

SentinelForge scanned a small demo Python web app in static mode.

Result:

```text
Score: 11.75 / 100
Grade: F
Decision: Do Not Ship
```

Plain-English meaning:

This app should not be launched yet. SentinelForge found several serious problems that could make the app unsafe if they existed in a real product.

## Top risks found

1. Shell command execution with `shell=True`
2. Suspected hardcoded API key
3. Debug mode enabled
4. Outdated dependencies
5. Risky Docker settings

## Example finding: shell command execution

Severity: high

Why this matters:

The app appears to run a shell command using input that could come from a user. If this were a real app, an attacker might be able to make the server run commands it was never supposed to run.

What to do:

- Do not pass user input directly into shell commands.
- Use safe library calls instead of shell strings.
- Validate and limit all user input.
- Re-run SentinelForge after fixing it.

## Example finding: suspected hardcoded secret

Severity: high

Why this matters:

A credential-like value appears to be stored inside the code. If this were a real key, someone with access to the code could use it to access private systems or spend money on your account.

What to do:

- Move secrets into environment variables or a secret manager.
- Remove the key from code.
- Rotate the key if it may have been real.
- Re-run SentinelForge and a dedicated secret scanner.

## Example finding: debug mode enabled

Severity: medium

Why this matters:

Debug mode can show private error details and may expose dangerous developer features. It should not be enabled in production.

What to do:

- Turn off debug mode for production.
- Use proper logging instead.
- Re-run the scan.

## Example finding: outdated dependencies

Severity: medium

Why this matters:

Old packages may have known security problems. Attackers often search for apps running old vulnerable versions.

What to do:

- Upgrade dependencies.
- Check advisories from OSV, NVD, and package maintainers.
- Re-run SentinelForge.

## Example finding: risky Docker settings

Severity: medium/low

Why this matters:

The demo container uses broad or risky defaults, such as an unpinned base image and no non-root user.

What to do:

- Pin base image versions.
- Avoid exposing sensitive ports.
- Run containers as a non-root user when possible.
- Re-run SentinelForge.

## What a customer gets from a paid review

A paid Security Baseline Review turns this kind of scanner output into a plain-English handoff:

- What is risky
- Why it matters
- What to fix first
- Whether it looks safe enough to ship
- A checklist the builder or client can understand

## Important limitation

SentinelForge does not guarantee that software is secure. It helps catch common and high-risk mistakes before launch.
