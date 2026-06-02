from __future__ import annotations

import re

SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"]?([^'\"\s]{8,})"),
]


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    prefix = value[:6]
    suffix = value[-4:]
    return f"{prefix}{'*' * max(4, len(value) - 10)}{suffix}"


def redact_text(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        def repl(match: re.Match) -> str:
            if match.lastindex and match.lastindex >= 2:
                return f"{match.group(1)}={mask_secret(match.group(2))}"
            return mask_secret(match.group(0))
        redacted = pattern.sub(repl, redacted)
    return redacted
