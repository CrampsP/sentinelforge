from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse


class TargetKind(StrEnum):
    LOCAL_PATH = "local_path"
    LOCALHOST_URL = "localhost_url"
    PRIVATE_NETWORK_URL = "private_network_url"
    PUBLIC_URL = "public_url"
    INVALID = "invalid"


@dataclass(frozen=True)
class TargetClassification:
    raw: str
    kind: TargetKind
    host: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class TargetDecision:
    allowed: bool
    classification: TargetClassification
    reason: str


def _host_kind(host: str | None) -> TargetKind:
    if not host:
        return TargetKind.INVALID
    lowered = host.lower()
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return TargetKind.LOCALHOST_URL
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return TargetKind.PUBLIC_URL
    if ip.is_loopback:
        return TargetKind.LOCALHOST_URL
    if ip.is_private:
        return TargetKind.PRIVATE_NETWORK_URL
    return TargetKind.PUBLIC_URL


def classify_target(raw: str) -> TargetClassification:
    path = Path(raw)
    if path.exists():
        return TargetClassification(raw=raw, kind=TargetKind.LOCAL_PATH, reason="Existing local filesystem path")
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"}:
        kind = _host_kind(parsed.hostname)
        return TargetClassification(raw=raw, kind=kind, host=parsed.hostname, reason=f"URL host classified as {kind.value}")
    return TargetClassification(raw=raw, kind=TargetKind.INVALID, reason="Target is not an existing local path or http(s) URL")


def validate_dynamic_target(raw: str, *, i_am_authorized: bool = False, allow_public_target: bool = False) -> TargetDecision:
    classification = classify_target(raw)
    if classification.kind == TargetKind.LOCALHOST_URL:
        return TargetDecision(True, classification, "Localhost dynamic targets are allowed by default.")
    if classification.kind == TargetKind.PRIVATE_NETWORK_URL:
        if i_am_authorized:
            return TargetDecision(True, classification, "Private-network target allowed because authorization was confirmed.")
        return TargetDecision(False, classification, "Private-network dynamic targets require --i-am-authorized.")
    if classification.kind == TargetKind.PUBLIC_URL:
        if i_am_authorized and allow_public_target:
            return TargetDecision(True, classification, "Public target allowed because both authorization flags were provided.")
        return TargetDecision(False, classification, "Public dynamic targets are blocked unless --i-am-authorized and --allow-public-target are both provided.")
    return TargetDecision(False, classification, classification.reason)
