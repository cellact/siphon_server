"""Identity label helpers. Auth/mapping live in GCP /auth + /route."""

from __future__ import annotations

import re
from typing import Any


class IdentityError(Exception):
    def __init__(self, status_code: int, message: str, code: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def _sip_user(value: Any) -> str:
    """URI local-part. No product knowledge."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.lower().startswith("sip:"):
        raw = raw[4:]
    raw = raw.split(";", 1)[0]
    raw = raw.split("@", 1)[0]
    if "." in raw:
        raw = raw.split(".", 1)[0]
    return raw


def normalize_phone_label(value: Any) -> str:
    """Digits-only when the label is a phone. Opaque handles (letters) stay non-phones."""
    raw = _sip_user(value)
    if not raw:
        return ""
    if raw.startswith("*"):
        raw = raw[1:]
    raw = raw.lstrip("+")
    if re.search(r"[A-Za-z]", raw):
        return ""
    normalized = re.sub(r"\D", "", raw)
    return normalized if normalized.isdigit() else ""


def derive_web2_identity(identity: Any) -> str:
    return normalize_phone_label(identity)


def identity_label(identity: Any) -> str:
    if not identity or not isinstance(identity, str):
        return str(identity or "")
    return _sip_user(identity) or identity.strip()


def callkit_handle(raw: Any) -> str:
    """Wire from/label: no leading '+'. Star codes and opaque ids unchanged."""
    s = identity_label(raw)
    if not s:
        return ""
    if s.startswith("*"):
        return s
    digits = normalize_phone_label(s)
    return digits or s.lstrip("+")
