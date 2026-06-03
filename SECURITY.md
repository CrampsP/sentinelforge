# SentinelForge Security Policy

## Supported version

The current supported public version is SentinelForge v1.5.x.

## Responsible use

SentinelForge is for authorized security checking only.

Only scan:

- Code you own
- Code your employer has authorized you to test
- Client code you have written permission to test
- Local or staging systems you control

Do not use SentinelForge for unauthorized scanning, exploit attempts, credential theft, denial-of-service testing, persistence, lateral movement, or production testing without explicit written permission.

## Reporting a vulnerability in SentinelForge

If you find a vulnerability in SentinelForge itself, please open a GitHub issue with a high-level description.

Do not include:

- Real API keys
- Passwords
- Tokens
- `.env` files
- Private client code
- Working exploit payloads against real third-party systems

If sensitive details are needed, first open a minimal issue asking for a private disclosure path.

## No security guarantee

SentinelForge helps catch common security mistakes, but no scanner can prove software is perfectly secure.

Use SentinelForge as a first-pass baseline, not as a replacement for professional security review when risk is high.
