"""STUN/TURN list for the in-process peer. The Node worker is gone."""

from __future__ import annotations

import os
import socket
from typing import Any

from siphon import log

_GOOGLE_STUN = (
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
)


def _ice_url_host(url: str) -> str:
    body = str(url or "").split(":", 1)[-1]
    return body.split("?")[0].split(":")[0].strip()


def _ice_host_ok(host: str) -> bool:
    if not host:
        return False
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def ice_servers() -> list[dict[str, Any]]:
    """Cellact STUN/TURN plus Google STUN. Skip URLs whose host does not resolve."""
    stun_url = os.environ.get("WEBRTC_STUN_URL", "stun:t1.cellact.nl:3478")
    turn_url = os.environ.get("WEBRTC_TURN_URL", "turn:t1.cellact.nl:3478")
    turn_user = os.environ.get("WEBRTC_TURN_USERNAME", "test")
    turn_cred = os.environ.get("WEBRTC_TURN_CREDENTIAL", "test")
    extra = [
        u.strip()
        for u in str(os.environ.get("WEBRTC_EXTRA_STUN_URLS") or "").split(",")
        if u.strip()
    ]
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in (stun_url, *_GOOGLE_STUN, *extra):
        if url in seen:
            continue
        seen.add(url)
        host = _ice_url_host(url)
        if not _ice_host_ok(host):
            log.warn(f"ICE: skip STUN {url!r} (DNS fail host={host!r})")
            continue
        out.append({"urls": url})
    if _ice_host_ok(_ice_url_host(turn_url)):
        out.append({"urls": turn_url, "username": turn_user, "credential": turn_cred})
    else:
        log.warn(f"ICE: skip TURN {turn_url!r} (DNS fail)")
    return out
