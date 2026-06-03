# SentinelForge v1.5.1 Release Notes

SentinelForge v1.5.1 adds the first licensing/trial gate while keeping trust-building commands free.

## What changed

- Adds one full local scan trial for new installs.
- Adds `sentinelforge license-status`.
- Adds `sentinelforge activate YOUR-LICENSE-KEY`.
- Keeps trust commands free forever: help, doctor, explain, init-policy, init-ci, license-status, and activate.
- Blocks additional full scans after the trial unless a signed license is activated.
- Stores local trial/license state in `~/.sentinelforge/license.json`.
- Stores only a hash of the activated license key locally, not the raw key.
- Adds signed Ed25519 license key verification.
- Adds tests for trial use, blocked second scan, activation, invalid keys, and raw-key storage prevention.

## Business model note

The public repository does not list prices. The current recommended model is manual payment plus manual license delivery while early demand is tested. Upgrade to automatic Stripe Checkout and webhook license generation after 30 paid customers.

## Safety note

The private license signing key is not in this repository. Only the public verification key is embedded in the CLI.

## Artifacts

- `dist/sentinelforge-1.5.1-py3-none-any.whl`
- `dist/sentinelforge-1.5.1.tar.gz`
- `dist/SHA256SUMS.txt`
