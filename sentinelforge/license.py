from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

LICENSE_PREFIX = "SF1"
PAYMENT_OR_CONTACT_TEXT = "contact the maintainer for a license"

# Public key only. The matching private signing key must stay outside the public repo.
# A real production key can be swapped in by setting SENTINELFORGE_LICENSE_PUBLIC_KEY_PEM.
DEFAULT_LICENSE_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqtFn0Y1xEJC1ZgLiwoGy8Tbnr7u6Rj0ap+IGrls+Isg=
-----END PUBLIC KEY-----
"""


@dataclass(frozen=True)
class LicenseStatus:
    activated: bool
    trial_used: bool
    license_id: str | None = None
    customer_email: str | None = None
    trial_used_at: str | None = None

    @property
    def can_scan(self) -> bool:
        return self.activated or not self.trial_used


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def license_home() -> Path:
    configured = os.environ.get("SENTINELFORGE_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".sentinelforge"


class LicenseError(ValueError):
    pass


class LicenseManager:
    def __init__(self, home: Path | None = None, public_key_pem: str | None = None):
        self.home = home or license_home()
        self.state_path = self.home / "license.json"
        self.public_key_pem = public_key_pem or os.environ.get("SENTINELFORGE_LICENSE_PUBLIC_KEY_PEM") or DEFAULT_LICENSE_PUBLIC_KEY_PEM

    def status(self) -> LicenseStatus:
        state = self._read_state()
        return LicenseStatus(
            activated=bool(state.get("activated", False)),
            trial_used=bool(state.get("trial_used", False)),
            license_id=state.get("license_id"),
            customer_email=state.get("customer_email"),
            trial_used_at=state.get("trial_used_at"),
        )

    def ensure_scan_allowed(self) -> tuple[bool, str | None]:
        status = self.status()
        if status.activated:
            return False, None
        if not status.trial_used:
            return True, None
        raise LicenseError(
            "Your one free SentinelForge scan has already been used. "
            f"Continued use requires a license; {PAYMENT_OR_CONTACT_TEXT}. "
            "After you receive a key, run: sentinelforge activate YOUR-LICENSE-KEY"
        )

    def mark_trial_used(self) -> None:
        state = self._read_state()
        if state.get("activated") or state.get("trial_used"):
            return
        state.update({
            "trial_used": True,
            "trial_used_at": _utc_now(),
            "install_id": state.get("install_id") or str(uuid4()),
            "activated": False,
        })
        self._write_state(state)

    def activate(self, license_key: str) -> LicenseStatus:
        payload = self.verify_license_key(license_key)
        state = self._read_state()
        state.update({
            "activated": True,
            "activated_at": _utc_now(),
            "license_id": payload["license_id"],
            "customer_email": payload.get("customer_email"),
            "license_key_hash": hashlib.sha256(license_key.encode("utf-8")).hexdigest(),
            "install_id": state.get("install_id") or str(uuid4()),
        })
        state.pop("raw_license_key", None)
        self._write_state(state)
        return self.status()

    def verify_license_key(self, license_key: str) -> dict[str, Any]:
        try:
            prefix, payload_part, signature_part = license_key.split(".", 2)
        except ValueError as exc:
            raise LicenseError("Invalid license key format.") from exc
        if prefix != LICENSE_PREFIX:
            raise LicenseError("Invalid license key prefix.")

        payload_raw = _b64url_decode(payload_part)
        signature = _b64url_decode(signature_part)
        public_key = serialization.load_pem_public_key(self.public_key_pem.encode("utf-8"))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise LicenseError("Invalid configured license public key.")
        try:
            public_key.verify(signature, payload_raw)
        except InvalidSignature as exc:
            raise LicenseError("Invalid license key signature.") from exc

        payload = json.loads(payload_raw.decode("utf-8"))
        if payload.get("product") != "sentinelforge":
            raise LicenseError("Invalid license product.")
        if not payload.get("license_id"):
            raise LicenseError("License key is missing a license id.")
        return payload

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"activated": False, "trial_used": False, "install_id": str(uuid4())}
        return json.loads(self.state_path.read_text())

    def _write_state(self, state: dict[str, Any]) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.home.chmod(0o700)
        self.state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        self.state_path.chmod(0o600)


def generate_license_key(private_key_path: str | Path, license_id: str, customer_email: str | None = None) -> str:
    private_bytes = Path(private_key_path).read_bytes()
    private_key = serialization.load_pem_private_key(private_bytes, password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise LicenseError("License private key must be an Ed25519 private key.")
    payload = {
        "product": "sentinelforge",
        "license_id": license_id,
        "customer_email": customer_email,
        "issued_at": _utc_now(),
    }
    payload_raw = _canonical_json(payload)
    signature = private_key.sign(payload_raw)
    return f"{LICENSE_PREFIX}.{_b64url_encode(payload_raw)}.{_b64url_encode(signature)}"


def create_private_key_pem() -> str:
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def public_key_pem_from_private(private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise LicenseError("License private key must be an Ed25519 private key.")
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
