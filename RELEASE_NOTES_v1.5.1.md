# SentinelForge v1.5.1 Release Notes

SentinelForge v1.5.1 adds local trial/license enforcement while keeping trust-building commands available.

## Added

- One full local scan trial for new installs.
- `sentinelforge license-status`.
- `sentinelforge activate YOUR-LICENSE-KEY`.
- Signed Ed25519 license key verification.
- Local state stored in `~/.sentinelforge/license.json`.
- Only a hash of the activated license key is stored locally.
- Tests for trial use, blocked second scan, activation, invalid keys, and raw-key storage prevention.

## Security note

The private license signing key is not included in this repository. Only the public verification key is embedded in the CLI.
