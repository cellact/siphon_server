"""Client HTTPS /notify ingress. Listen port maps to a logic wrapper (auth pin).

Orchestrates auth -> route -> SBC (rtpengine+SIP) or webrtc (notify+bridge).
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import array
import math
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from typing import Any, Optional


def _pin_stdlib_http() -> None:
    """Force stdlib http.* into sys.modules (siphon-http shadows the name)."""
    stdlib = os.path.dirname(os.__file__)
    http_dir = os.path.join(stdlib, "http")
    init_py = os.path.join(http_dir, "__init__.py")
    if not os.path.isfile(init_py):
        return

    for key in list(sys.modules):
        if key == "http" or key.startswith("http."):
            del sys.modules[key]

    spec = importlib.util.spec_from_file_location(
        "http",
        init_py,
        submodule_search_locations=[http_dir],
    )
    if spec is None or spec.loader is None:
        return
    pkg = importlib.util.module_from_spec(spec)
    sys.modules["http"] = pkg
    spec.loader.exec_module(pkg)

    for sub in ("client", "server", "cookies", "cookiejar"):
        sub_path = os.path.join(http_dir, f"{sub}.py")
        if not os.path.isfile(sub_path):
            continue
        sub_name = f"http.{sub}"
        sub_spec = importlib.util.spec_from_file_location(sub_name, sub_path)
        if sub_spec is None or sub_spec.loader is None:
            continue
        sub_mod = importlib.util.module_from_spec(sub_spec)
        sys.modules[sub_name] = sub_mod
        setattr(pkg, sub, sub_mod)
        sub_spec.loader.exec_module(sub_mod)


_pin_stdlib_http()

# requests-dependent modules BEFORE siphon.http (which re-shadows sys.modules['http']).
import identity
import notify_push
import policy
import logic_client
import extension_hunt
import webrtc_pc

from siphon import log, proxy
import siphon as _siphon

siphon_http = _siphon.http
_pin_stdlib_http()

# Alias used by route handlers / Response constructors (local name only).
http = siphon_http

# ── Session table ────────────────────────────────────────────────────────────
_sessions: dict[str, dict[str, Any]] = {}
_sessions_lock = threading.RLock()
# alias -> attempt storage keys (workerSessionId), newest last.
# Never collapse every alias onto one session dict.
_pair_index: dict[str, list[str]] = {}
_worker_index: dict[str, str] = {}
_nonce_index: dict[str, str] = {}
# Ice that arrives before the offer has a session. Keyed by callId and ufrag.
_held_ice: dict[str, tuple[float, list[Any]]] = {}
_direction_epoch: dict[str, int] = {}
# SIP Call-ID → sessionId (SBC→WebRTC inbound)
_sip_call_index: dict[str, str] = {}
# IVR DID → product session (REFER is on the B-leg; that Call-ID is not indexed)
_xfer_did_index: dict[str, str] = {}
# Seat DID → parked REFER so siphon's terminate INVITE can wake the seat
_pending_xfer: dict[str, dict[str, Any]] = {}

WEBRTC_WAIT_SECS = int(os.environ.get("WEBRTC_ANSWER_TIMEOUT_SECS", "60") or "60")
# RING on a live DC. Zero messages from that peer → HTTP invite. A reply keeps the 60s answer wait.
DC_RING_SILENCE_HTTP_SECS = 8.0
# Hangup-party leftover on the *callee* DC (not pc1). Caller RING is never
# suppressed — that is a real redial.
SOFT_END_CALLEE_RING_SUPPRESS_SECS = float(
    os.environ.get("SOFT_END_CALLEE_RING_SUPPRESS_SECS", "3") or "3"
)
SBC_INVITE_TIMEOUT_MS = int(os.environ.get("SBC_INVITE_TIMEOUT_MS", "60000") or "60000")


async def _await_threading_event(
    event: threading.Event, timeout: float, *, interval: float = 0.05
) -> bool:
    """Wait without blocking siphon's Python executor (stall_abort_secs=30)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if event.is_set():
            return True
        remaining = deadline - loop.time()
        if remaining <= 0:
            return event.is_set()
        await asyncio.sleep(min(interval, remaining))

# Hairpin /notify → local B2BUA → SBC. proxy.send_request() resolves on the first
# SIP response (often 100 Trying), so INVITE finals must ride call.dial instead.
SBC_HAIRPIN_USER = "__arnacon_sbc_ingress"
SBC_HAIRPIN_HEADER = "X-Arnacon-Sbc-Ingress"
SBC_HAIRPIN_NUMBER_HEADER = "X-Arnacon-Sbc-Number"
SBC_HAIRPIN_ADDRESS_HEADER = "X-Arnacon-Sbc-Address"
SBC_HAIRPIN_NG_HEADER = "X-Arnacon-Sbc-Ng"  # "1" => media owned by NG pre-offer
_hairpin_waiters: dict[str, asyncio.Future] = {}
_hairpin_lock = threading.Lock()
# ingress_id → {call_id, from_tag, session_id} pinned at rtpengine offer time
_hairpin_ng_keys: dict[str, dict[str, str]] = {}
_hairpin_ng_lock = threading.Lock()
_pending_ivr_transfers: dict[str, dict[str, Any]] = {}
_pending_ivr_lock = threading.Lock()

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-sign, x-data, X-Sign, X-Data",
}


# ── Minimal rtpengine NG client (HTTP-originated media; no SIP Call object) ──
def _bencode(value: Any) -> bytes:
    if isinstance(value, bool):
        raise TypeError("bool")
    if isinstance(value, int):
        return f"i{value}e".encode()
    if isinstance(value, bytes):
        return f"{len(value)}:".encode() + value
    if isinstance(value, str):
        encoded = value.encode()
        return f"{len(encoded)}:".encode() + encoded
    if isinstance(value, list):
        return b"l" + b"".join(_bencode(item) for item in value) + b"e"
    if isinstance(value, dict):
        parts = [b"d"]
        for key in sorted(value.keys(), key=lambda k: k if isinstance(k, bytes) else str(k).encode()):
            k = key if isinstance(key, bytes) else str(key).encode()
            parts.append(_bencode(k))
            parts.append(_bencode(value[key]))
        parts.append(b"e")
        return b"".join(parts)
    raise TypeError(type(value))


def _bdecode(data: bytes, index: int = 0) -> tuple[Any, int]:
    if data[index : index + 1] == b"i":
        end = data.index(b"e", index)
        return int(data[index + 1 : end]), end + 1
    if data[index : index + 1] == b"l":
        result = []
        index += 1
        while data[index : index + 1] != b"e":
            value, index = _bdecode(data, index)
            result.append(value)
        return result, index + 1
    if data[index : index + 1] == b"d":
        result = {}
        index += 1
        while data[index : index + 1] != b"e":
            key, index = _bdecode(data, index)
            val, index = _bdecode(data, index)
            if isinstance(key, bytes):
                key = key.decode(errors="replace")
            result[key] = val
        return result, index + 1
    colon = data.index(b":", index)
    length = int(data[index:colon])
    start = colon + 1
    return data[start : start + length], start + length


PROFILES = {
    "webrtc_to_sbc": {
        "offer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "DTLS": "off",
            "replace": ["origin", "session-connection"],
            "direction": ["local", "pub"],
            "rtcp-mux": ["demux"],
            "flags": [
                "SIP-source-address",
                "endpoint-learning=immediate",
                "codec-mask-OPUS",
                "transcode-PCMU",
                "transcode-PCMA",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
        "answer": {
            "transport-protocol": "UDP/TLS/RTP/SAVPF",
            "ICE": "force",
            "DTLS": "passive",
            "replace": ["origin", "session-connection"],
            "direction": ["pub", "local"],
            "rtcp-mux": ["offer"],
            # trust-address NOT SIP-source-address: SBC answer has no ICE and raw NG
            # has no received-from → SIP-source-address makes fill_endpoint fail
            # ("Incomplete SDP specification").
            "flags": [
                "SDES-off",
                "trust-address",
                "endpoint-learning=immediate",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
    },
    # Carrier INVITE as plain RTP, then a loopback answer. No DTLS. Play omits
    # to-tag so the greeting goes to the carrier, not the loopback socket.
    "voicemail_plain": {
        "offer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "DTLS": "off",
            "replace": ["origin", "session-connection"],
            # pub is the carrier (A). local is the loopback (B). The 200 must
            # carry A's socket, which is what the answer command returns.
            "direction": ["pub", "local"],
            "rtcp-mux": ["demux"],
            "flags": [
                "trust-address",
                "endpoint-learning=immediate",
                "codec-mask-OPUS",
                "transcode-PCMA",
                "transcode-telephone-event",
            ],
        },
        # Loopback leg. Plain RTP to 127.0.0.1, so this call is two legs and
        # play has one egress toward the carrier. No session-connection replace:
        # that would overwrite the loopback address.
        "answer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "DTLS": "off",
            "replace": ["origin"],
            "rtcp-mux": ["demux"],
            "flags": ["trust-address"],
        },
    },
    # PC2 (aiortc) ↔ rtpengine on the same host. Keep DTLS on the WebRTC leg —
    # DTLS=off on offer was leaving ICE up but connectionState=failed (DTLS dead).
    "pc2_to_sbc": {
        "offer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "replace": ["origin", "session-connection"],
            "direction": ["local", "pub"],
            "rtcp-mux": ["demux"],
            "flags": [
                "SDES-off",
                "trust-address",
                "endpoint-learning=immediate",
                "codec-mask-OPUS",
                "transcode-PCMU",
                "transcode-PCMA",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
        "answer": {
            "transport-protocol": "UDP/TLS/RTP/SAVPF",
            "ICE": "force",
            # See siphon.yaml pc2_to_sbc: aiortc DTLS-client vs rtpengine passive
            # dies (ice=completed, connectionState=failed). Prefer DTLS active.
            "DTLS": "active",
            "replace": ["origin", "session-connection"],
            "direction": ["pub", "local"],
            "rtcp-mux": ["require"],
            "flags": [
                "SDES-off",
                "trust-address",
                "endpoint-learning=immediate",
                "detect-dtmf",
            ],
        },
    },
    "webrtc_to_webrtc": {
        "offer": {
            "transport-protocol": "UDP/TLS/RTP/SAVPF",
            "ICE": "force",
            "DTLS": "passive",
            "replace": ["origin", "session-connection"],
            "rtcp-mux": ["offer"],
            "flags": [
                "SDES-off",
                "SIP-source-address",
                "endpoint-learning=immediate",
                "detect-dtmf",
            ],
        },
        "answer": {
            "transport-protocol": "UDP/TLS/RTP/SAVPF",
            "ICE": "force",
            "DTLS": "passive",
            "replace": ["origin", "session-connection"],
            "rtcp-mux": ["offer"],
            "flags": [
                "SDES-off",
                "SIP-source-address",
                "endpoint-learning=immediate",
                "detect-dtmf",
            ],
        },
    },
    # SBC plain RTP → WebRTC (inbound). Raw NG copy of Kamailio
    # RELAY_FROM_SBC offer / MANAGE_REPLY_FROM_SBC answer — nothing else.
    "sbc_to_webrtc": {
        "offer": {
            "transport-protocol": "UDP/TLS/RTP/SAVPF",
            "ICE": "force",
            "DTLS": "passive",
            "replace": ["origin", "session-connection"],
            "rtcp-mux": ["offer"],
            "flags": ["SDES-off", "transcode-telephone-event", "detect-dtmf"],
        },
        "answer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "replace": ["origin", "session-connection"],
            "flags": ["transcode-telephone-event", "detect-dtmf"],
        },
    },
    # IVR transfer: siphon re-INVITEs PSTN (or stitches via its own NG).
    # Learn the real RTP source; the park INVITE c-line is siphon itself.
    "sbc_to_webrtc_xfer": {
        "offer": {
            "transport-protocol": "UDP/TLS/RTP/SAVPF",
            "ICE": "force",
            "DTLS": "passive",
            "replace": ["origin", "session-connection"],
            "rtcp-mux": ["offer"],
            "flags": [
                "SDES-off",
                "trust-address",
                "endpoint-learning=immediate",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
        "answer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "replace": ["origin", "session-connection"],
            "flags": [
                "trust-address",
                "endpoint-learning=immediate",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
    },
    # PSTN A-leg ↔ local xfer_park B-leg stitch (replaces OpenAI B-leg on existing
    # a_leg rtpengine session without re-INVITEing Cellact).
    # B-side is localloop to xfer_park, so direction is ["pub", "local"] on offer
    # and ["local", "pub"] on answer (same local VPC IP 172.31.6.219 so packets
    # don't hairpin through the AWS NAT IGW).
    "sbc_to_sbc_xfer": {
        "offer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "replace": ["origin", "session-connection"],
            "direction": ["pub", "local"],
            "flags": [
                "SDES-off",
                "trust-address",
                "transcode-PCMA",
                "transcode-PCMU",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
        "answer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "replace": ["origin", "session-connection"],
            "direction": ["local", "pub"],
            "flags": [
                "SDES-off",
                "trust-address",
                "transcode-PCMA",
                "transcode-PCMU",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
    },
    # Local xfer_park WebRTC (pc1) ↔ local a_leg B-side stitch.
    # Both sides of xfer_park live on 172.31.6.219 ("local"), without
    # endpoint-learning=immediate so rtpengine sends immediately on the local NIC.
    "pc2_to_sbc_local": {
        "offer": {
            "transport-protocol": "RTP/AVP",
            "ICE": "remove",
            "replace": ["origin", "session-connection"],
            "direction": ["local", "local"],
            "rtcp-mux": ["demux"],
            "flags": [
                "SDES-off",
                "trust-address",
                "codec-mask-OPUS",
                "transcode-PCMU",
                "transcode-PCMA",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
        "answer": {
            "transport-protocol": "UDP/TLS/RTP/SAVPF",
            "ICE": "force",
            "DTLS": "active",
            "replace": ["origin", "session-connection"],
            "direction": ["local", "local"],
            "rtcp-mux": ["require"],
            "flags": [
                "SDES-off",
                "trust-address",
                "transcode-telephone-event",
                "detect-dtmf",
            ],
        },
    },
}


def _rtpengine_addr() -> tuple[str, int]:
    raw = os.environ.get("RTPENGINE_ADDRESS", "127.0.0.1:22222")
    host, _, port = raw.partition(":")
    return host or "127.0.0.1", int(port or "22222")


def _ng_command(payload: dict[str, Any], timeout: float = 2.0) -> dict[str, Any]:
    cookie = uuid.uuid4().hex[:16]
    body = _bencode(payload)
    packet = cookie.encode() + b" " + body
    host, port = _rtpengine_addr()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    # response: "<cookie> <bencode>"
    space = data.find(b" ")
    raw = data[space + 1 :] if space >= 0 else data
    decoded, _ = _bdecode(raw)
    if not isinstance(decoded, dict):
        raise RuntimeError("rtpengine NG: non-dict response")
    result = decoded.get("result")
    if isinstance(result, bytes):
        result = result.decode(errors="replace")
    if result not in ("ok", b"ok"):
        err = decoded.get("error-reason") or decoded.get("error") or result
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        raise RuntimeError(f"rtpengine NG error: {err}")
    return decoded


def _flags_dict(profile: str, side: str) -> dict[str, Any]:
    flags = dict(PROFILES[profile][side])
    out: dict[str, Any] = {}
    for key, value in flags.items():
        # Kamailio answer has no flags= — omit empty lists so NG matches.
        if isinstance(value, list) and not value:
            continue
        out[key] = value
    return out


def _rtpengine_media_address() -> str:
    """Public media IP for raw NG (no SIP message → SIP-source-address is useless)."""
    media_addr = (os.environ.get("SIPHON_BIND_IP") or "").strip()
    if not media_addr:
        try:
            media_addr = str(policy.local_bind_ip() or "").strip()
        except Exception:  # noqa: BLE001
            media_addr = ""
    if media_addr in ("0.0.0.0", "127.0.0.1"):
        return ""
    return media_addr


def ensure_pc2_answer_rtcp_mux(sdp: str) -> str:
    """PC2 offer always has a=rtcp-mux; aiortc rejects answers without it.

    Siphon/rtpengine sometimes returns split RTCP (a=rtcp:PORT, component-2
    candidates) and omits a=rtcp-mux → setRemoteDescription: 'RTCP mux is not enabled'.
    """
    text = str(sdp or "")
    if not text.strip():
        return text
    ending = "\r\n" if "\r\n" in text else "\n"
    body = text.replace("\r\n", "\n")
    had_mux = bool(re.search(r"^a=rtcp-mux\s*$", body, re.M))
    # Drop RTCP-only ICE candidates (component 2) even when mux is already present.
    kept: list[str] = []
    dropped_comp2 = 0
    for line in body.split("\n"):
        if line.startswith("a=candidate:"):
            parts = line.split()
            # a=candidate:<foundation> <component> ...
            if len(parts) >= 2 and parts[1] == "2":
                dropped_comp2 += 1
                continue
        kept.append(line)
    body = "\n".join(kept)
    if not had_mux:
        if re.search(r"^a=rtcp:", body, re.M):
            body = re.sub(
                r"(^a=rtcp:[^\n]*\n)", r"\1a=rtcp-mux\n", body, count=1, flags=re.M
            )
        else:
            body = re.sub(
                r"(^m=audio[^\n]*\n)",
                r"\1a=rtcp-mux\n",
                body,
                count=1,
                flags=re.M,
            )
        log.info("PC2: injected a=rtcp-mux into answer SDP")
    elif dropped_comp2:
        log.info(f"PC2: dropped {dropped_comp2} RTCP component-2 candidates")
    out = body.replace("\n", ending)
    if text.endswith("\r\n") and not out.endswith("\r\n"):
        out += "\r\n"
    return out


def ensure_pc2_answer_ice_lite(sdp: str) -> str:
    """rtpengine is ICE-lite; aiortc is happier when the answer says so."""
    text = str(sdp or "")
    if not text.strip() or re.search(r"^a=ice-lite\s*$", text.replace("\r\n", "\n"), re.M):
        return text
    ending = "\r\n" if "\r\n" in text else "\n"
    body = text.replace("\r\n", "\n")
    if re.search(r"^a=ice-ufrag:", body, re.M):
        body = re.sub(
            r"(^a=ice-ufrag:[^\n]*\n)",
            r"a=ice-lite\n\1",
            body,
            count=1,
            flags=re.M,
        )
    else:
        body = body.rstrip("\n") + "\na=ice-lite\n"
    out = body.replace("\n", ending)
    if text.endswith("\r\n") and not out.endswith("\r\n"):
        out += "\r\n"
    log.info("PC2: injected a=ice-lite into answer SDP")
    return out


def _sdp_m_sections(sdp: str) -> tuple[str, list[str]]:
    text = str(sdp or "").replace("\r\n", "\n").replace("\r", "\n")
    parts = re.split(r"(?=^m=)", text, flags=re.M)
    if not parts:
        return "", []
    return parts[0], [part for part in parts[1:] if part.startswith("m=")]


def _section_mid(section: str) -> str:
    match = re.search(r"^a=mid:(\S+)", section, re.M)
    return match.group(1).strip() if match else ""


_ANSWER_TRANSPORT_PREFIXES = (
    "a=ice-",
    "a=fingerprint:",
    "a=setup:",
    "a=candidate:",
    "a=end-of-candidates",
    "a=rtcp-mux",
    "a=rtcp:",
)

# str0m rejects an m-line that omits this. siphon-rtp defaults the same
# omission to sendrecv and then does not print the attribute.
_SDP_DIRECTIONS = frozenset(("a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"))
_ANSWER_DIRECTION = {
    "a=sendonly": "a=recvonly",
    "a=recvonly": "a=sendonly",
    "a=inactive": "a=inactive",
    "a=sendrecv": "a=sendrecv",
}


def _sdp_direction(section: str) -> str:
    for line in str(section or "").split("\n"):
        attr = line.strip()
        if attr in _SDP_DIRECTIONS:
            return attr
    return ""


def _accepted_answer_direction(offer_session: str, offer_section: str) -> str:
    """RFC 3264 answer direction when the answer left it off.

    A missing attribute is sendrecv (RFC 4566). sendonly/recvonly flip,
    because the answer describes the answerer, not the offerer.
    """
    offered = _sdp_direction(offer_section) or _sdp_direction(offer_session)
    return _ANSWER_DIRECTION.get(offered, "a=sendrecv")


def align_pc2_answer_to_offer(offer: str, answer: str) -> str:
    """Make an rtpengine answer acceptable to str0m.

    rtpengine collapses a BUNDLE offer (datachannel + audio) into one
    ``m=audio`` and stamps the first mid on it, with no ``a=group``. str0m
    rejects that (``Session attribute a=group missing``), then rejects a
    group whose mids are not the offer m-lines in order. Rebuild the answer
    in offer order. The audio line keeps rtpengine's port, ICE, DTLS, and
    codecs, with the offer's audio mid. The first bundled mid is the ICE
    transport, so it gets that same port. Later non-audio lines stay in
    the group at port 0 and carry the same ICE.
    """
    _offer_session, offer_medias = _sdp_m_sections(offer)
    answer_session, answer_medias = _sdp_m_sections(answer)
    if not offer_medias or not answer_medias:
        return answer
    answer_audio = next((part for part in answer_medias if part.startswith("m=audio ")), "")
    if not answer_audio:
        return answer

    def nonempty(section: str) -> list[str]:
        return [line for line in section.split("\n") if line]

    transport = [
        line
        for line in nonempty(answer_audio)
        if line.startswith(_ANSWER_TRANSPORT_PREFIXES)
    ]

    def bundled_other(section: str, mid: str, *, port: str) -> str:
        first, _, _rest = section.partition("\n")
        bits = first.split(" ")
        if len(bits) >= 2:
            bits[1] = port
        lines = [" ".join(bits), f"a=mid:{mid}"]
        for line in nonempty(section):
            if line.startswith(("a=sctp-port:", "a=max-message-size:", "a=sctpmap:")):
                lines.append(line)
        lines.extend(transport)
        return "\n".join(lines) + "\n"

    def retarget_audio(section: str, mid: str, *, offer_audio_sec: str = "") -> str:
        lines: list[str] = []
        replaced = False
        has_mid_ext = False
        for line in section.split("\n"):
            if line.startswith("a=mid:"):
                lines.append(f"a=mid:{mid}")
                replaced = True
            else:
                if line.startswith("a=extmap:") and "urn:ietf:params:rtp-hdrext:sdes:mid" in line:
                    has_mid_ext = True
                lines.append(line)
        while lines and lines[-1] == "":
            lines.pop()
        if mid and not replaced:
            lines.insert(1, f"a=mid:{mid}")
        if not has_mid_ext and offer_audio_sec:
            for oline in nonempty(offer_audio_sec):
                if oline.startswith("a=extmap:") and "urn:ietf:params:rtp-hdrext:sdes:mid" in oline:
                    lines.append(oline)
                    break
        if not any(line.strip() in _SDP_DIRECTIONS for line in lines):
            direction = _accepted_answer_direction(_offer_session, offer_audio_sec)
            lines.append(direction)
            log.info(f"PC2: answer mid {mid or '-'} had no direction; stamped {direction}")
        return "\n".join(lines) + "\n"

    audio_port = answer_audio.split("\n", 1)[0].split(" ")
    tagged_port = audio_port[1] if len(audio_port) >= 2 and audio_port[1] not in ("", "0") else "9"
    rebuilt: list[str] = []
    bundle: list[str] = []
    for section in offer_medias:
        mid = _section_mid(section)
        if not mid:
            return answer
        bundle.append(mid)
        if section.startswith("m=audio "):
            rebuilt.append(retarget_audio(answer_audio, mid, offer_audio_sec=section))
        else:
            # First bundled mid is the ICE transport. Port 0 there is a reject.
            port = tagged_port if not rebuilt else "0"
            rebuilt.append(bundled_other(section, mid, port=port))

    group = "a=group:BUNDLE " + " ".join(bundle)
    session_lines = [
        line for line in answer_session.split("\n") if line and not line.startswith("a=group:")
    ]
    inserted = False
    session_out: list[str] = []
    for line in session_lines:
        session_out.append(line)
        if line.startswith("t=") and not inserted:
            session_out.append(group)
            inserted = True
    if not inserted:
        session_out.append(group)
    ending = "\r\n" if "\r\n" in str(answer) else "\n"
    text = ("\n".join(session_out) + "\n" + "".join(rebuilt)).replace("\n", ending)
    log.info(
        f"PC2: aligned rtpengine answer to offer bundle={' '.join(bundle)} "
        f"mlines={len(rebuilt)} tagged={tagged_port}"
    )
    return text


def localize_pc2_answer_sdp(sdp: str) -> str:
    """Normalize rtpengine answer for aiortc PC2.

    Default: keep rtpengine's advertised media IP (usually pub/host). Rewriting
    to 127.0.0.1 made ICE complete while DTLS failed (socket bound to pub).
    Opt-in loopback: SIPHON_PC2_LOCALIZE=1.
    """
    text = ensure_pc2_answer_ice_lite(ensure_pc2_answer_rtcp_mux(str(sdp or "")))
    if not text.strip():
        return text
    if os.environ.get("SIPHON_PC2_LOCALIZE", "").strip() not in ("1", "true", "yes"):
        return text
    pub = _rtpengine_media_address()
    if not pub:
        return text
    ending = "\r\n" if "\r\n" in text else "\n"
    body = text.replace("\r\n", "\n")
    body = re.sub(
        rf"^c=IN IP4 {re.escape(pub)}$",
        "c=IN IP4 127.0.0.1",
        body,
        flags=re.M,
    )
    body = re.sub(
        rf"(a=candidate:[^\n]*\s){re.escape(pub)}(\s)",
        r"\g<1>127.0.0.1\2",
        body,
    )
    out = body.replace("\n", ending)
    if text.endswith("\r\n") and not out.endswith("\r\n"):
        out += "\r\n"
    log.info(f"PC2: localized NG answer media {pub} → 127.0.0.1 (SIPHON_PC2_LOCALIZE)")
    return out


def localize_pc1_answer_for_ng(sdp: str) -> str:
    """Rewrite PC1 host candidates pub→127.0.0.1 before rtpengine answer.

    Opt-in only (SIPHON_PC1_LOCALIZE=1). Default off — pub hairpin already
    completes ICE/DTLS; rewriting can desync where rtpengine sends vs binds.
    """
    text = str(sdp or "")
    if not text.strip():
        return text
    if os.environ.get("SIPHON_PC1_LOCALIZE", "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return text
    pub = _rtpengine_media_address()
    if not pub:
        return text
    ending = "\r\n" if "\r\n" in text else "\n"
    body = text.replace("\r\n", "\n")
    before = body
    body = re.sub(
        rf"^c=IN IP4 {re.escape(pub)}$",
        "c=IN IP4 127.0.0.1",
        body,
        flags=re.M,
    )
    body = re.sub(
        rf"(a=candidate:[^\n]*\s){re.escape(pub)}(\s)",
        r"\g<1>127.0.0.1\2",
        body,
    )
    if body == before:
        return text
    out = body.replace("\n", ending)
    if text.endswith("\r\n") and not out.endswith("\r\n"):
        out += "\r\n"
    log.info(f"PC1: localized NG answer media {pub} → 127.0.0.1 (same-host rtpengine)")
    return out


def rtpengine_offer(
    call_id: str,
    from_tag: str,
    sdp: str,
    profile: str,
    *,
    received_from: str = "",
    to_tag: str = "",
) -> str:
    """Raw NG offer. Prefer siphon rtpengine.offer(call) when a Call exists.

    `received_from` uses NG key ``received from`` (space) — hyphen is ignored.
    Do NOT send ``address``/``media address`` here: ``media address`` overrides
    the *remote* SDP endpoint (would replace SBC 185.62.121.12 with our pub IP).
    """
    payload = {
        "command": "offer",
        "call-id": call_id,
        "from-tag": from_tag,
        "sdp": sdp,
        **_flags_dict(profile, "offer"),
    }
    if to_tag:
        payload["to-tag"] = to_tag
    src = str(received_from or "").strip()
    if src:
        fam = "IP6" if ":" in src else "IP4"
        payload["received from"] = [fam, src]
    resp = _ng_command(payload)
    sdp_out = resp.get("sdp")
    if isinstance(sdp_out, bytes):
        return sdp_out.decode(errors="replace")
    if not sdp_out:
        raise RuntimeError("rtpengine offer returned empty SDP")
    return str(sdp_out)


def rtpengine_answer(call_id: str, from_tag: str, to_tag: str, sdp: str, profile: str) -> str:
    """Raw NG answer. No ``media address`` — must not clobber SBC endpoint."""
    flags = _flags_dict(profile, "answer")
    # ng docs: direction on answer is meaningless / ignored
    flags.pop("direction", None)
    payload = {
        "command": "answer",
        "call-id": call_id,
        "from-tag": from_tag,
        "to-tag": to_tag,
        "sdp": sdp,
        **flags,
    }
    resp = _ng_command(payload)
    sdp_out = resp.get("sdp")
    if isinstance(sdp_out, bytes):
        return sdp_out.decode(errors="replace")
    if not sdp_out:
        raise RuntimeError("rtpengine answer returned empty SDP")
    return str(sdp_out)


def _aleg_far_loopback_sdp(call_id: str, from_tag: str, template_sdp: str) -> str:
    """SDP aimed at the far socket Cellact's call already has.

    `offer` on that call-id deletes it and binds a new near port. Cellact
    keeps sending to the old one. `checkpoint` is read-only and names the
    far local port the seat has to send into.
    """
    resp = _ng_command(
        {"command": "checkpoint", "call-id": call_id, "from-tag": from_tag},
        timeout=1.5,
    )
    raw = resp.get("snapshot")
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    if not raw:
        raise RuntimeError(f"rtpengine checkpoint empty call_id={call_id}")
    snap = json.loads(raw)
    far = snap.get("far") if isinstance(snap, dict) else None
    if not isinstance(far, dict):
        raise RuntimeError(f"rtpengine checkpoint has no far leg call_id={call_id}")
    rtp_local = str(far.get("rtp_local") or "").strip()
    if ":" not in rtp_local:
        raise RuntimeError(
            f"rtpengine checkpoint far.rtp_local={rtp_local!r} call_id={call_id}"
        )
    bound_ip, port = rtp_local.rsplit(":", 1)
    if not port.isdigit():
        raise RuntimeError(
            f"rtpengine checkpoint far port={port!r} call_id={call_id}"
        )
    advertised = str(far.get("advertised_ip") or "").strip() or bound_ip
    text = _body_text(template_sdp)
    rewritten = re.sub(
        r"^c=IN IP4\s+\S+",
        f"c=IN IP4 {advertised}",
        text,
        count=1,
        flags=re.M,
    )
    rewritten = re.sub(
        r"^m=audio\s+\d+",
        f"m=audio {port}",
        rewritten,
        count=1,
        flags=re.M,
    )
    if rewritten == text:
        raise RuntimeError(
            f"xfer far SDP rewrite missed c=/m= call_id={call_id}"
        )
    log.info(
        f"NOTIFY/INBOUND: xfer far socket call_id={call_id} "
        f"{advertised}:{port} (bound {rtp_local})"
    )
    return rewritten


# Static RTP/AVP payload types (RFC 3551) — TBSIP answers often omit a=rtpmap.
_STATIC_RTPMAP = {
    "0": "PCMU/8000",
    "8": "PCMA/8000",
    "9": "G722/8000",
    "18": "G729/8000",
    "101": "telephone-event/8000",
}


def sbc_sdp_missing_static_rtpmap(sdp: str) -> bool:
    """True when m=audio lists a static PT (0/8/101/…) with no a=rtpmap.

    Israeli hairpin 200s do this. Dutch and a normal SBC user do not.
    """
    text = _body_text(sdp).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.startswith("m=audio "):
            i += 1
            continue
        pts = line.split()[3:]
        have: set[str] = set()
        i += 1
        while i < len(lines) and not lines[i].startswith("m="):
            if lines[i].startswith("a=rtpmap:"):
                have.add(lines[i][len("a=rtpmap:") :].split("/", 1)[0].split()[0])
            i += 1
        for pt in pts:
            if pt in _STATIC_RTPMAP and pt not in have:
                return True
    return False


def _m_audio_pts(sdp: str) -> list[str]:
    for line in _body_text(sdp).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith("m=audio "):
            return [pt for pt in line.split()[3:] if pt.isdigit()]
    return []


def fit_plain_sdp_to_sbc_offer(plain: str, invite: str) -> str:
    """UAS 200 payloads must be a subset of the SBC INVITE.

    pc2_to_sbc transcodes PCMU and telephone-event/126 into the answer.
    TBSIP offered 8 and 101, accepted `8 0 126`, then sent no RTP.
    """
    offered = _m_audio_pts(invite)
    if not offered:
        return plain
    offered_set = set(offered)
    text = _body_text(plain)
    if not text.strip():
        return plain
    ending = "\r\n" if "\r\n" in text else "\n"
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    changed = False
    session_c = ""
    media_c = ""
    seen_m = False
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("c=IN ") and not seen_m and not session_c:
            session_c = line
        if line.startswith("m=audio "):
            seen_m = True
            parts = line.split()
            if len(parts) < 4:
                out.append(line)
                continue
            kept = [pt for pt in parts[3:] if pt in offered_set]
            if not kept:
                return plain
            if kept != parts[3:]:
                changed = True
                line = " ".join(parts[:3] + kept)
            out.append(line)
            continue
        if seen_m and line.startswith("c=IN ") and not media_c:
            media_c = line
        if line.startswith("a=rtcp:"):
            changed = True
            continue
        if line.startswith("a=rtpmap:") or line.startswith("a=fmtp:"):
            pt = line.split(":", 1)[1].split()[0].split("/", 1)[0]
            if pt.isdigit() and pt not in offered_set:
                changed = True
                continue
        out.append(line)
    invite_body = _body_text(invite).replace("\r\n", "\n").replace("\r", "\n")
    te_lines = [
        line
        for line in invite_body.split("\n")
        if line.startswith("a=rtpmap:") and "telephone-event" in line
    ]
    te_pts = []
    for line in te_lines:
        pt = line.split(":", 1)[1].split()[0].split("/", 1)[0]
        if pt.isdigit():
            te_pts.append(pt)
    if te_pts:
        rebuilt: list[str] = []
        for line in out:
            if line.startswith("m=audio "):
                parts = line.split()
                extra = [pt for pt in te_pts if pt not in set(parts[3:])]
                if extra:
                    line = " ".join(parts + extra)
                    changed = True
            rebuilt.append(line)
        inserted_te: list[str] = []
        injected = False
        for line in rebuilt:
            inserted_te.append(line)
            if injected or not line.startswith("a=rtpmap:"):
                continue
            have_all = "\n".join(rebuilt)
            for te_line in te_lines:
                pt = te_line.split(":", 1)[1].split()[0].split("/", 1)[0]
                if f"a=rtpmap:{pt} " not in have_all:
                    inserted_te.append(te_line)
                    changed = True
            injected = True
        out = inserted_te
    invite_ptime = ""
    for line in _body_text(invite).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith("a=ptime:"):
            invite_ptime = line
            break
    if invite_ptime and not any(line.startswith("a=ptime:") for line in out):
        out.append(invite_ptime)
        changed = True
    if not session_c and media_c:
        inserted: list[str] = []
        placed = False
        for line in out:
            if not placed and line.startswith("t="):
                inserted.append(media_c)
                placed = True
            inserted.append(line)
        if placed:
            out = inserted
            changed = True
    if not changed:
        return plain
    fitted = ending.join(out) + ending
    log.info(
        f"NOTIFY/INBOUND: fitted SBC 200 payloads to invite "
        f"offered={','.join(offered)} kept={','.join(_m_audio_pts(fitted))}"
    )
    return fitted


def strip_webrtc_attrs_for_sbc_uas(sdp: str) -> str:
    """Strip WebRTC leftovers from rtpengine answer before UAS 200 to SBC.

    rtpengine often leaves mid/msid/ssrc/end-of-candidates on RTP/AVP answers.
    Some SBCs then accept 200 but never send RTP (PC1.in=0).
    """
    text = _body_text(sdp)
    if not text.strip():
        return ""
    ending = "\r\n" if "\r\n" in text else "\n"
    strip_prefixes = (
        "a=mid:",
        "a=msid",
        "a=ssrc",
        "a=end-of-candidates",
        "a=extmap",
        "a=fingerprint",
        "a=setup:",
        "a=ice-",
        "a=candidate",
        "a=group:BUNDLE",
        "a=rtcp-rsize",
        "a=rtcp-fb",
        "a=sctp-port",
        "a=max-message-size",
    )
    out: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line.strip():
            continue
        if any(line.startswith(p) for p in strip_prefixes):
            continue
        out.append(line)
    return ending.join(out) + ending


def normalize_sbc_answer_sdp(sdp: str) -> str:
    """Make bare carrier 200 SDP digestible for rtpengine answer.

    Prod SBC answers can be just:
      m=audio PORT RTP/AVP 8
    with no rtpmap/sendrecv. Enrich static maps + ensure CRLF.
    """
    text = _body_text(sdp).replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return ""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        if line.startswith("m=audio "):
            parts = line.split()
            pts = parts[3:] if len(parts) > 3 else []
            # Consume existing media attrs; track what we already have.
            j = i + 1
            media_attrs: list[str] = []
            while j < len(lines) and not lines[j].startswith("m="):
                media_attrs.append(lines[j])
                j += 1
            have_rtpmap = {
                a[len("a=rtpmap:") :].split("/", 1)[0].split()[0]
                for a in media_attrs
                if a.startswith("a=rtpmap:")
            }
            have_send = any(
                a.startswith("a=sendrecv")
                or a.startswith("a=sendonly")
                or a.startswith("a=recvonly")
                or a.startswith("a=inactive")
                for a in media_attrs
            )
            for attr in media_attrs:
                out.append(attr)
            for pt in pts:
                if pt in have_rtpmap:
                    continue
                name = _STATIC_RTPMAP.get(pt)
                if name:
                    out.append(f"a=rtpmap:{pt} {name}")
            te_pts = [
                a[len("a=rtpmap:") :].split(None, 1)[0]
                for a in out
                if a.startswith("a=rtpmap:") and "telephone-event" in a.lower()
            ]
            have_fmtp = {
                a[len("a=fmtp:") :].split(None, 1)[0]
                for a in media_attrs
                if a.startswith("a=fmtp:")
            }
            for te_pt in te_pts:
                if te_pt and te_pt not in have_fmtp:
                    out.append(f"a=fmtp:{te_pt} 0-15")
            if not have_send:
                out.append("a=sendrecv")
            i = j
            continue
        i += 1
    return "\r\n".join(out) + "\r\n"


def _rtpengine_unknown_call(exc: BaseException) -> bool:
    return "unknown call" in str(exc).lower()


def _rtpengine_delete_once(call_id: str, from_tag: str = "") -> None:
    cmd: dict[str, Any] = {"command": "delete", "call-id": call_id}
    if from_tag:
        cmd["from-tag"] = from_tag
    _ng_command(cmd, timeout=1.5)


def rtpengine_delete(call_id: str, from_tag: str = "") -> None:
    # siphon-rtp's delete requires from-tag. A tagless retry is
    # "missing or invalid key: from-tag", not a successful cleanup.
    tag = str(from_tag or "").strip()
    if not tag and call_id:
        tag, _to = _rtpengine_aleg_tags(call_id, "", "")
        tag = str(tag or "").strip()
    if not tag:
        log.info(f"rtpengine delete skipped (no from-tag) call_id={call_id}")
        return
    try:
        _rtpengine_delete_once(call_id, tag)
    except Exception as exc:  # noqa: BLE001
        if _rtpengine_unknown_call(exc):
            log.info(f"rtpengine delete already gone call_id={call_id} from_tag={tag}")
            return
        log.warn(f"rtpengine delete failed call_id={call_id} from_tag={tag}: {exc}")


def _rtpengine_aleg_tags(
    call_id: str, fallback_from: str = "", fallback_to: str = ""
) -> tuple[str, str]:
    """Query rtpengine for (A-leg from-tag, B-leg to-tag) on call_id sorted by creation time."""
    try:
        # siphon-rtp rejects a query that has no from-tag. Classic rtpengine
        # did not. The tag we already stored on the A-leg is the one to send.
        cmd: dict[str, Any] = {"command": "query", "call-id": call_id}
        known = str(fallback_from or "").strip()
        if known:
            cmd["from-tag"] = known
        res = _ng_command(cmd, timeout=1.5)
        tags = res.get("tags") or res.get(b"tags")
        if isinstance(tags, dict):
            candidates: list[tuple[int, str]] = []
            for raw_tag, info in tags.items():
                tag = (
                    raw_tag.decode(errors="replace")
                    if isinstance(raw_tag, bytes)
                    else str(raw_tag or "")
                ).strip()
                if not tag:
                    continue
                created = 0
                if isinstance(info, dict):
                    c_val = info.get("created") or info.get(b"created") or 0
                    try:
                        created = int(c_val)
                    except (TypeError, ValueError):
                        created = 0
                candidates.append((created, tag))
            if candidates:
                candidates.sort(key=lambda item: item[0])
                names = [tag for _, tag in candidates]
                if known and known in names:
                    chosen_from = known
                    others = [tag for tag in names if tag != known]
                    chosen_to = others[0] if others else fallback_to
                else:
                    chosen_from = candidates[0][1]
                    chosen_to = (
                        candidates[1][1] if len(candidates) >= 2 else fallback_to
                    )
                log.info(
                    f"NOTIFY/INBOUND: rtpengine query call_id={call_id} "
                    f"aleg_from_tag={chosen_from!r} aleg_to_tag={chosen_to!r} "
                    f"(fallback_from={fallback_from!r} all={[t for _, t in candidates]})"
                )
                return chosen_from, chosen_to
    except Exception as exc:  # noqa: BLE001
        log.warn(f"rtpengine query failed call_id={call_id}: {exc}")
    return fallback_from, fallback_to


def _rtpengine_aleg_from_tag(call_id: str, fallback: str = "") -> str:
    """Query rtpengine for the first (A-leg) tag on call_id so re-offers keep P_aleg."""
    chosen_from, _ = _rtpengine_aleg_tags(call_id, fallback, "")
    return chosen_from


def _delete_session_rtpengine(session: dict[str, Any], fallback_id: str = "") -> None:
    call_id = str(
        session.get("sbcNgCallId") or session.get("mediaCallId") or fallback_id or "unknown"
    )
    from_tag = str(session.get("sbcNgFromTag") or session.get("fromTag") or "")
    rtpengine_delete(call_id, from_tag)
    vm_cid = str(session.get("voicemailMediaCallId") or "").strip()
    if vm_cid and vm_cid != call_id:
        rtpengine_delete(vm_cid, str(session.get("voicemailFromTag") or ""))
    if session.get("xferPark"):
        aleg = str(session.get("b2buaCallId") or "").strip()
        if aleg and aleg != call_id:
            rtpengine_delete(aleg, str(session.get("alegFromTag") or ""))
        park_cid = str(session.get("parkCallId") or "").strip()
        if park_cid and park_cid not in (call_id, aleg):
            rtpengine_delete(park_cid, "")


def rtpengine_inject_dtmf(
    call_id: str,
    from_tag: str,
    digit: Any,
    duration_ms: Any = 200,
    volume: Any = 8,
    to_tag: str = "",
) -> None:
    """Play DTMF on the siphon-rtp call (after /action forward).

    siphon-rtp plays toward the offerer unless to-tag (or from-tag) is the
    call's to-tag. Pass the SBC to-tag so the digit goes to the carrier.
    """
    code = str(digit if digit is not None else "").strip()
    if not call_id or not from_tag or not code:
        raise RuntimeError("inject DTMF needs call-id, from-tag, digit")
    try:
        dur = int(duration_ms or 200)
    except (TypeError, ValueError):
        dur = 200
    try:
        vol = int(volume or 8)
    except (TypeError, ValueError):
        vol = 8
    # NG command is "play DTMF". Volume is dBm0, negative.
    vol = -abs(max(0, min(abs(vol), 36)))
    payload: dict[str, Any] = {
        "command": "play DTMF",
        "call-id": str(call_id),
        "from-tag": str(from_tag),
        "code": code[0],
        "duration": max(100, min(dur, 5000)),
        "volume": vol,
    }
    if to_tag:
        payload["to-tag"] = str(to_tag)
    _ng_command(payload, timeout=1.5)


# ── Session helpers ──────────────────────────────────────────────────────────
def _stable_key(from_id: str, to_id: str) -> str:
    """Node wireSessionId: sort(to, identityLabel(from)) — order-independent pair key."""
    a = identity.identity_label(str(from_id or "").lower())
    b = identity.identity_label(str(to_id or "").lower())
    if not a:
        return b
    if not b:
        return a
    return "|".join(sorted([a, b]))


def _storage_key(session: Optional[dict[str, Any]]) -> str:
    if not isinstance(session, dict):
        return ""
    return str(session.get("workerSessionId") or session.get("sessionId") or "").strip()


def _directional_key(from_id: str, to_id: str) -> str:
    """Unsorted from|to. Opposite offers must not share this alias alone."""
    a = identity.identity_label(str(from_id or ""))
    b = identity.identity_label(str(to_id or ""))
    if a and b:
        return f"{a}|{b}"
    return _stable_key(from_id, to_id)


def _pair_ids_locked(key: str) -> list[str]:
    raw = _pair_index.get(key)
    if isinstance(raw, list):
        return [str(x) for x in raw if x]
    if isinstance(raw, str) and raw:
        return [raw]
    return []


def _pair_append_locked(key: str, storage: str) -> None:
    key = str(key or "").strip()
    storage = str(storage or "").strip()
    if not key or not storage:
        return
    ids = [x for x in _pair_ids_locked(key) if x != storage]
    ids.append(storage)
    _pair_index[key] = ids


def _pair_discard_locked(key: str, storage: str) -> None:
    key = str(key or "").strip()
    if not key:
        return
    ids = [x for x in _pair_ids_locked(key) if x != storage]
    if ids:
        _pair_index[key] = ids
    else:
        _pair_index.pop(key, None)


def _alloc_direction_epoch(from_id: str, to_id: str) -> int:
    key = _directional_key(from_id, to_id)
    with _sessions_lock:
        epoch = int(_direction_epoch.get(key) or 0) + 1
        _direction_epoch[key] = epoch
        return epoch


def _lookup_locked(session_id: str) -> Optional[dict[str, Any]]:
    """Exact storage key, worker id, SIP Call-ID, or a unique pair alias."""
    sid = str(session_id or "").strip()
    if not sid:
        return None
    found = _sessions.get(sid)
    if found is not None:
        return found
    mapped = _worker_index.get(sid)
    if mapped and mapped in _sessions:
        return _sessions[mapped]
    sip = _sip_call_index.get(sid)
    if sip and sip in _sessions:
        return _sessions[sip]
    ids = [i for i in _pair_ids_locked(sid) if i in _sessions]
    if len(ids) == 1:
        return _sessions[ids[0]]
    hits = [
        s
        for s in _sessions.values()
        if sid in {
            str(s.get("sessionId") or ""),
            str(s.get("workerSessionId") or ""),
        }
    ]
    if len(hits) == 1:
        return hits[0]
    return None


def _get_session(session_id: str) -> Optional[dict[str, Any]]:
    with _sessions_lock:
        return _lookup_locked(session_id)


def _session_for_worker(worker_id: str) -> Optional[dict[str, Any]]:
    with _sessions_lock:
        return _lookup_locked(worker_id)


def _notify_identities(route: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for item in route.get("targets") or []:
        if isinstance(item, dict):
            ident = str(item.get("notifyIdentity") or item.get("ensName") or item.get("number") or "")
        else:
            ident = str(item)
        if ident:
            out.append(ident)
    ident = str(route.get("notifyIdentity") or route.get("ensName") or "")
    if ident:
        out.append(ident)
    return list(dict.fromkeys(out))


def _sip_index_ids(session: dict[str, Any]) -> list[str]:
    """Every SIP Call-ID that must resolve to this WebRTC session.

    PSTN BYE arrives on the A-leg ARNACON id. Transfer used to index only
    `{id}-xfer`, so hangup never cancelled the ringing seat.
    """
    out: list[str] = []
    for key in (
        "mediaCallId",
        "b2buaCallId",
        "parkCallId",
        "siphonActorId",
        "voicemailMediaCallId",
    ):
        cid = str(session.get(key) or "").strip()
        if cid and cid not in out:
            out.append(cid)
        if cid.endswith("-xfer"):
            base = cid[: -len("-xfer")]
            if base and base not in out:
                out.append(base)
    return out


def _bind_session_aliases(session: dict[str, Any]) -> None:
    storage = _storage_key(session)
    if not storage:
        return
    from_id = session.get("from") or ""
    cli = identity.identity_label(
        (session.get("route") or {}).get("callerId") or session.get("callerId") or ""
    )
    caller_ids = [from_id]
    if cli and identity.identity_label(cli) not in {
        identity.identity_label(from_id),
        "",
    }:
        caller_ids.append(cli)
    aliases = []
    dest = session.get("to") or ""
    for src in caller_ids:
        aliases.append(_stable_key(src, dest))
        aliases.append(_directional_key(src, dest))
        caller = identity.identity_label(src)
        for ident in _notify_identities(session.get("route") or {}):
            aliases.append(_stable_key(src, ident))
            aliases.append(_directional_key(src, ident))
            callee = identity.identity_label(ident)
            if caller and callee:
                aliases.append("|".join(sorted([caller, callee])))
    session["_aliasKeys"] = [k for k in dict.fromkeys(aliases) if k]
    with _sessions_lock:
        for key in session["_aliasKeys"]:
            _pair_append_locked(key, storage)
        for sip_cid in _sip_index_ids(session):
            prev = _sip_call_index.get(sip_cid)
            if prev and prev != storage and prev in _sessions:
                prev_sess = _sessions.get(prev) or {}
                if not _is_product_leg(prev_sess) and not session.get("xferPark"):
                    log.warn(
                        f"NOTIFY: SIP Call-ID {sip_cid} already bound to {prev}, "
                        f"not stealing for {storage}"
                    )
                    continue
                log.info(
                    f"NOTIFY: SIP Call-ID {sip_cid} rebinding {prev} -> {storage} "
                    f"(xfer_park={bool(session.get('xferPark'))})"
                )
            _sip_call_index[sip_cid] = storage


def _put_session(session: dict[str, Any]) -> None:
    route = session.get("route") or {}
    cli = str(route.get("callerId") or session.get("callerId") or "").strip()
    if cli:
        session["callerId"] = cli
    storage = _storage_key(session)
    if not storage:
        return
    with _sessions_lock:
        _sessions[storage] = session
        wid = str(session.get("workerSessionId") or "").strip()
        if wid:
            _worker_index[wid] = storage
        for nonce in _attempt_ids(session)["nonces"]:
            _nonce_index[nonce] = storage
    _bind_session_aliases(session)


def _pop_session(session_id: str) -> Optional[dict[str, Any]]:
    """Pop one attempt. A shared pair alias with several attempts is not a pop."""
    sid = str(session_id or "").strip()
    if not sid:
        return None
    with _sessions_lock:
        session = _sessions.get(sid)
        storage = sid if session is not None else ""
        if session is None:
            mapped = _worker_index.get(sid)
            if mapped and mapped in _sessions:
                storage = mapped
                session = _sessions[mapped]
        if session is None:
            ids = [i for i in _pair_ids_locked(sid) if i in _sessions]
            if len(ids) == 1:
                storage = ids[0]
                session = _sessions[storage]
            elif len(ids) > 1:
                log.info(
                    f"NOTIFY: refuse pop ambiguous pair session={sid} attempts={ids}"
                )
                return None
        if session is None:
            hits = [
                ( _storage_key(s), s)
                for s in _sessions.values()
                if sid == str(s.get("sessionId") or "")
            ]
            if len(hits) == 1:
                storage, session = hits[0]
            elif len(hits) > 1:
                log.info(
                    f"NOTIFY: refuse pop ambiguous wire session={sid} n={len(hits)}"
                )
                return None
        if session is None or not storage:
            return None
        _sessions.pop(storage, None)
        wire = str(session.get("sessionId") or "")
        if wire and wire != storage and _sessions.get(wire) is session:
            _sessions.pop(wire, None)
        wid = str(session.get("workerSessionId") or "").strip()
        if wid:
            _worker_index.pop(wid, None)
        for nonce in _attempt_ids(session)["nonces"]:
            if _nonce_index.get(nonce) == storage:
                _nonce_index.pop(nonce, None)
        for key in list(session.get("_aliasKeys") or []):
            _pair_discard_locked(key, storage)
            if wire and wire != storage:
                _pair_discard_locked(key, wire)
        for extra in (
            _stable_key(session.get("from") or "", session.get("to") or ""),
            _directional_key(session.get("from") or "", session.get("to") or ""),
        ):
            _pair_discard_locked(extra, storage)
        for sip_cid in _sip_index_ids(session):
            if _sip_call_index.get(sip_cid) == storage:
                _sip_call_index.pop(sip_cid, None)
        for did, mapped in list(_xfer_did_index.items()):
            if mapped in (storage, wire, sid):
                _xfer_did_index.pop(did, None)
        return session


_ICE_UFRAG_SDP_RE = re.compile(r"^a=ice-ufrag:(\S+)", re.M)
_ICE_UFRAG_CAND_RE = re.compile(r"\bufrag\s+(\S+)")


def _sdp_ufrag(sdp: Any) -> str:
    m = _ICE_UFRAG_SDP_RE.search(str(sdp or ""))
    return m.group(1).strip() if m else ""


def _request_ids(payload: Optional[dict[str, Any]]) -> tuple[str, str]:
    """(callNonce, callId) the client put on this request. Either may be ''.

    iOS sends callNonce. Android sends an integer callId (0 = none).
    """
    payload = payload or {}
    nonce = str(payload.get("callNonce") or "").strip()
    raw = payload.get("callId")
    call_id = "" if raw is None or isinstance(raw, bool) else str(raw).strip()
    if call_id == "0":
        call_id = ""
    return nonce, call_id


def _offer_ids(payload: Optional[dict[str, Any]], sdp: Any = "") -> dict[str, str]:
    """Ids that arrive on an offer: callNonce, Android callId, ICE ufrag."""
    nonce, call_id = _request_ids(payload)
    ufrag = str((payload or {}).get("offerUfrag") or "").strip() or _sdp_ufrag(sdp)
    return {"nonce": nonce, "call_id": call_id, "ufrag": ufrag}


def _remember_attempt_ids(
    session: dict[str, Any],
    *,
    nonce: str = "",
    call_id: str = "",
    ufrag: str = "",
    fresh: bool = False,
) -> None:
    """Remember ids for THIS attempt. Internal key; never sent to clients.

    fresh=True starts a new call presentation on a reused session, so ids from
    the previous call can no longer name it.
    """
    if not isinstance(session, dict):
        return
    storage = _storage_key(session)
    with _sessions_lock:
        old = session.get("_attemptIds") or {}
        if fresh:
            for n in old.get("nonces") or []:
                if _nonce_index.get(n) == storage:
                    _nonce_index.pop(n, None)
            old = {}
        ids = {k: list(old.get(k) or []) for k in ("nonces", "callIds", "ufrags")}
        current = session.get("callNonce")
        for kind, val in (
            ("nonces", current),
            ("nonces", nonce),
            ("callIds", call_id),
            ("ufrags", ufrag),
        ):
            val = str(val or "").strip()
            if val and val not in ids[kind]:
                ids[kind].append(val)
        session["_attemptIds"] = ids
        if storage and _sessions.get(storage) is session:
            for n in ids["nonces"]:
                _nonce_index[n] = storage


def _set_call_nonce(session: dict[str, Any], nonce: str = "", *, fresh: bool = False) -> str:
    """Set the nonce pushed to callees ('' = mint one).

    Unless fresh, nonces this attempt already handed out stay valid.
    """
    if not fresh:
        _remember_attempt_ids(session)
    nonce = str(nonce or "").strip() or str(uuid.uuid4())
    session["callNonce"] = nonce
    _remember_attempt_ids(session, fresh=fresh)
    return nonce


def _attempt_ids(session: dict[str, Any]) -> dict[str, set[str]]:
    """Every id that names this attempt: offer ids, minted nonces, ring callIds."""
    ids = (session or {}).get("_attemptIds") or {}
    nonces = {str(x) for x in ids.get("nonces") or [] if x}
    call_ids = {str(x) for x in ids.get("callIds") or [] if x}
    ufrags = {str(x) for x in ids.get("ufrags") or [] if x}
    cur = str((session or {}).get("callNonce") or "").strip()
    if cur:
        nonces.add(cur)
    for key, val in list((session or {}).items()):
        if key in ("activeCallId", "activeCallIdRaw") or key.startswith("ringCallId:"):
            sval = "" if val is None or isinstance(val, bool) else str(val).strip()
            if sval and sval != "0":
                call_ids.add(sval)
    pc1_ufrag = str((session or {}).get("pc1RemoteUfrag") or "").strip()
    if pc1_ufrag:
        ufrags.add(pc1_ufrag)
    return {"nonces": nonces, "callIds": call_ids, "ufrags": ufrags}


def _ids_name_attempt(session: dict[str, Any], nonce: str, call_id: str) -> bool:
    ids = _attempt_ids(session)
    if nonce:
        return nonce in ids["nonces"]
    return bool(call_id) and call_id in ids["callIds"]


def _request_ufrags(payload: Optional[dict[str, Any]]) -> set[str]:
    payload = payload or {}
    out: set[str] = set()
    for key in ("offerUfrag", "ufrag", "usernameFragment"):
        val = str(payload.get(key) or "").strip()
        if val:
            out.add(val)
    for cand in payload.get("candidates") or []:
        if isinstance(cand, dict):
            val = str(cand.get("usernameFragment") or "").strip()
            if val:
                out.add(val)
            cand = cand.get("candidate")
        m = _ICE_UFRAG_CAND_RE.search(str(cand or ""))
        if m:
            out.add(m.group(1).strip())
    return out


def _hold_early_ice(payload: Optional[dict[str, Any]]) -> int:
    """Keep a batch whose callId does not name a session yet.

    Android trickles before the offer finishes auth. Dropping that batch
    leaves the handshake with candidates=0 and the phone retries.
    """
    payload = payload or {}
    cands = [c for c in (payload.get("candidates") or []) if c]
    if not cands:
        return 0
    _, call_id = _request_ids(payload)
    keys = []
    if call_id:
        keys.append(f"call:{call_id}")
    for ufrag in _request_ufrags(payload):
        keys.append(f"ufrag:{ufrag}")
    if not keys:
        return 0
    now = time.time()
    with _sessions_lock:
        for key, (ts, _) in list(_held_ice.items()):
            if now - ts > 45:
                _held_ice.pop(key, None)
        for key in keys:
            prev = _held_ice.get(key)
            merged = list(prev[1]) if prev else []
            merged.extend(cands)
            _held_ice[key] = (now, merged)
    return len(cands)


def _take_held_ice(*, call_id: str = "", ufrag: str = "") -> list[Any]:
    keys = []
    if call_id:
        keys.append(f"call:{call_id}")
    if ufrag:
        keys.append(f"ufrag:{ufrag}")
    out: list[Any] = []
    seen: set[str] = set()
    with _sessions_lock:
        for key in keys:
            item = _held_ice.pop(key, None)
            if not item:
                continue
            for cand in item[1]:
                text = cand.get("candidate") if isinstance(cand, dict) else cand
                mark = str(text or "")
                if not mark or mark in seen:
                    continue
                seen.add(mark)
                out.append(cand)
    return out


def _attempt_connected(session: dict[str, Any]) -> bool:
    """Callee picked up / SIP answered on this attempt (not just PC1 up).

    pc1Connected/pc2Connected/mediaBridged are not used: the caller PC and a
    reused callee DC are up while still ringing. Soft-ended = no live call.
    """
    if not isinstance(session, dict) or session.get("softEnded"):
        return False
    if session.get("multiringWinner") or session.get("calleeAnsweredOnce"):
        return True
    if session.get("sbcAnswered") or session.get("inboundSipAnswered"):
        return True
    return str(session.get("state") or "") in ("callee-audio-up", "answered", "sbc-answered")


def _notify_nonce_ok(session: dict[str, Any], payload: dict[str, Any]) -> bool:
    """Drop leftover answer/reject/cancel from a previous ring on the same pair."""
    nonce, call_id = _request_ids(payload)
    if not nonce and not call_id:
        return True
    return _ids_name_attempt(session, nonce, call_id)


def _attempts_for_keys(*keys: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    with _sessions_lock:
        for key in keys:
            key = str(key or "").strip()
            if not key:
                continue
            direct = _lookup_locked(key)
            if direct is not None:
                storage = _storage_key(direct)
                if storage and storage not in seen:
                    seen.add(storage)
                    found.append(direct)
            for storage in _pair_ids_locked(key):
                sess = _sessions.get(storage)
                if sess is None or storage in seen:
                    continue
                seen.add(storage)
                found.append(sess)
    return found


def _epoch_key(session: dict[str, Any]) -> tuple[int, float]:
    return (int(session.get("dialogEpoch") or 0), float(session.get("createdAt") or 0))


def _select_attempt(
    from_id: str,
    to_id: str,
    session_id: Optional[str],
    payload: Optional[dict[str, Any]],
    *,
    role: str,
) -> tuple[Optional[dict[str, Any]], str]:
    """Bind signaling to one attempt.

    An id on the request (callNonce, or callId for cancel/reject/ice) names
    exactly one attempt. An id that names nothing is stale: no-op, never fall
    through onto another attempt. Answers also accept callId, but only as a
    positive match against ids recorded for an attempt; an unmatched answer
    callId is ignored (not stale) so Android's local callId still falls through.

    Without an id: cancel = sender placed the offer, reject = sender was
    invited, and only an attempt that has NOT connected may be taken (sender's
    newest one). A connected attempt is never ended by an id-less
    cancel/reject: reason "connected". ICE with several open attempts is
    routed by ufrag; no ufrag match = ignore.
    """
    payload = payload or {}
    nonce, call_id = _request_ids(payload)
    sid = str(session_id or "").strip()
    pool = _attempts_for_keys(
        sid,
        _stable_key(from_id, to_id),
        _directional_key(from_id, to_id),
        _directional_key(to_id, from_id),
    )
    if role == "answer" and call_id:
        # Accept callId on answers only as a positive match against ids the
        # server recorded for an attempt (offer callId, ring callIds, etc.).
        # Android's local callId matches nothing — ignore it (do not treat as
        # stale) and fall through to callNonce / id-less behaviour.
        if not any(_ids_name_attempt(s, "", call_id) for s in pool):
            call_id = ""
    if nonce or call_id:
        if nonce:
            with _sessions_lock:
                nonce_storage = _nonce_index.get(nonce)
                nonce_sess = _sessions.get(nonce_storage) if nonce_storage else None
            if nonce_sess is not None and all(
                _storage_key(nonce_sess) != _storage_key(s) for s in pool
            ):
                pool.append(nonce_sess)
        matched = [s for s in pool if _ids_name_attempt(s, nonce, call_id)]
        if not matched:
            return None, "stale"
        if len(matched) == 1:
            return matched[0], "nonce" if nonce else "callId"
        pool = matched

    def _party_labels(*raws: Any) -> set[str]:
        # identity_label keeps a leading '+'. callkit_handle is the form on the
        # wire. A cover DID and the seat that owns it are the same party.
        out: set[str] = set()
        for raw in raws:
            lab = identity.identity_label(raw)
            if lab:
                out.add(lab)
            handle = identity.callkit_handle(raw)
            if handle:
                out.add(handle)
        out.discard("")
        return out

    from_labels = _party_labels(from_id)
    to_labels = _party_labels(to_id)

    def _caller_labels(sess: dict[str, Any]) -> set[str]:
        route = sess.get("route") or {}
        return _party_labels(
            sess.get("from"),
            route.get("callerId"),
            sess.get("callerId"),
        )

    def _callees(sess: dict[str, Any]) -> set[str]:
        # Dialed callee plus every rung seat (multiring / hunt).
        return _party_labels(
            sess.get("to"),
            *list((sess.get("ringLegs") or {}).keys()),
        )

    def _outgoing(sess: dict[str, Any]) -> bool:
        return bool(from_labels & _caller_labels(sess)) and (
            not to_labels or bool(to_labels & _callees(sess))
        )

    def _incoming(sess: dict[str, Any]) -> bool:
        return bool(from_labels & _callees(sess)) and (
            not to_labels or bool(to_labels & _caller_labels(sess))
        )

    outgoing = [s for s in pool if _outgoing(s)]
    incoming = [s for s in pool if _incoming(s)]
    if role == "cancel":
        # Caller abandon only. Do not fall through onto the reverse attempt.
        pool = outgoing
    elif role == "reject":
        pool = incoming
    elif role == "answer":
        pool = incoming or outgoing
    elif role == "ice":
        pool = list({_storage_key(s): s for s in outgoing + incoming}.values())
    if not pool:
        return None, "missing"
    open_ones = [
        s
        for s in pool
        if not s.get("clientEnded") and not s.get("callerCancelForwarded")
    ]
    use = open_ones or pool
    if role in ("cancel", "reject") and not (nonce or call_id):
        unconnected = [s for s in use if not _attempt_connected(s)] or [
            s for s in pool if not _attempt_connected(s)
        ]
        if not unconnected:
            return None, "connected"
        return max(unconnected, key=_epoch_key), "newest-unconnected"
    if len(use) == 1:
        return use[0], "ok"
    if role == "ice" and not (nonce or call_id):
        want = _request_ufrags(payload)
        hits = [s for s in use if want & _attempt_ids(s)["ufrags"]]
        if len(hits) == 1:
            return hits[0], "ufrag"
        return None, "ambiguous"
    return max(use, key=_epoch_key), "newest-epoch"


def _same_direction_attempt(from_id: str, to_id: str) -> Optional[dict[str, Any]]:
    """Newest attempt this caller placed toward this callee. Not the reverse offer."""
    from_label = identity.identity_label(from_id)
    to_label = identity.identity_label(to_id)
    pool = [
        s
        for s in _attempts_for_keys(
            _stable_key(from_id, to_id),
            _directional_key(from_id, to_id),
        )
        if _dialog_originator(s) == from_label
        and (not to_label or identity.identity_label(s.get("to") or "") == to_label)
    ]
    if not pool:
        return None
    return max(pool, key=_epoch_key)


def _resolve_session_id(from_id: str, to_id: str, session_id: Optional[str]) -> str:
    """Storage key when the pair has a single attempt. Does not pick among glare attempts."""
    sid = str(session_id or "").strip()
    if sid:
        found = _get_session(sid)
        if found is not None and (
            sid == _storage_key(found) or sid == str(found.get("workerSessionId") or "")
        ):
            return _storage_key(found)
        hits = _attempts_for_keys(sid)
        if len(hits) == 1:
            return _storage_key(hits[0])
    hits = _attempts_for_keys(
        _stable_key(from_id, to_id),
        "|".join(
            sorted(
                x
                for x in (
                    identity.identity_label(from_id),
                    identity.identity_label(to_id),
                )
                if x
            )
        ),
    )
    if len(hits) == 1:
        return _storage_key(hits[0])
    return sid or _stable_key(from_id, to_id)


def get_session_by_sip_call_id(call_id: str) -> Optional[dict[str, Any]]:
    cid = str(call_id or "").strip()
    if not cid:
        return None
    with _sessions_lock:
        sid = _sip_call_index.get(cid)
        if sid:
            sess = _sessions.get(sid)
            if sess is not None:
                return sess
        for sess in _sessions.values():
            if cid in _sip_index_ids(sess):
                return sess
    return None


def session_handles_dtmf(session: Optional[dict[str, Any]]) -> bool:
    """Any live media session: inbound-to-seat, hunt, SBC, product/IVR."""
    if not session:
        return False
    if session.get("productKind") or logic_client.is_product_route(session.get("route")):
        return True
    rk = str(
        session.get("routeKind") or (session.get("route") or {}).get("route") or ""
    ).strip().lower()
    return rk in ("sbc", "inbound", "webrtc", "webrtc-multiring")


def find_session_for_dtmf(call_id: str, from_tag: str = "") -> Optional[dict[str, Any]]:
    """DTMF NG call-id may be A-leg, B2BUA id, or rtpengine id."""
    sess = get_session_by_sip_call_id(call_id)
    if sess:
        return sess
    cid = str(call_id or "").strip()
    tag = str(from_tag or "").strip()
    with _sessions_lock:
        for session in _sessions.values():
            if not session_handles_dtmf(session):
                continue
            ids = (
                session.get("sessionId"),
                session.get("mediaCallId"),
                session.get("voicemailMediaCallId"),
                session.get("b2buaCallId"),
                session.get("parkCallId"),
                (session.get("inboundCall") or {}).get("callId"),
            )
            if cid and cid in {str(x or "") for x in ids}:
                return session
            tags = (
                session.get("fromTag"),
                session.get("toTag"),
                session.get("alegFromTag"),
                session.get("alegToTag"),
                session.get("voicemailFromTag"),
            )
            if tag and tag in {str(t or "") for t in tags if t}:
                return session
    return None


def _reply_header(reply: Any, name: str) -> str:
    fn = getattr(reply, "get_header", None)
    if not callable(fn):
        return ""
    for key in (name, name.lower(), name.title()):
        try:
            val = fn(key)
        except Exception:  # noqa: BLE001
            val = None
        if val:
            return str(val)
    return ""


def remember_aleg_dialog(call_id: str, call: Any) -> None:
    """Keep the answered A-leg To-tag so a later REFER reuses the rtpengine dialog."""
    cid = str(call_id or "").strip()
    if not cid:
        return
    sess = get_session_by_sip_call_id(cid)
    if not sess or not sess.get("inviteSdp"):
        return
    tag = _uas_local_tag(call)
    if tag:
        sess["toTag"] = tag
    sess["aLegCall"] = call
    log.info(f"XFER: remembered A-leg to_tag={tag!r} a_leg={cid}")


def remember_bleg_dialog(call_id: str, reply: Any) -> None:
    """B-leg 200 so IVR can BYE OpenAI without touching Cellact."""
    cid = str(call_id or "").strip()
    if not cid:
        return
    sess = get_session_by_sip_call_id(cid)
    if not sess or not sess.get("inviteSdp"):
        return
    from_h = _reply_header(reply, "From") or _reply_header(reply, "f")
    to_h = _reply_header(reply, "To") or _reply_header(reply, "t")
    if not from_h or not to_h:
        log.warn(f"XFER: B-leg 200 missing From/To a_leg={cid}")
        return
    sess["blegLocalFrom"] = from_h
    sess["blegRemoteTo"] = to_h
    sess["blegRemoteTag"] = _sip_header_tag(to_h)
    sess["blegLocalTag"] = _sip_header_tag(from_h)
    sess["blegContact"] = _reply_header(reply, "Contact") or _reply_header(reply, "m")
    sess["blegCSeq"] = _reply_header(reply, "CSeq")
    log.info(
        f"XFER: remembered B-leg dialog a_leg={cid} "
        f"remote_tag={sess['blegRemoteTag']!r} local_tag={sess['blegLocalTag']!r} "
        f"contact={sess.get('blegContact') or '-'}"
    )


def _bye_openai_after_xfer(session: dict[str, Any]) -> None:
    """Drop the OpenAI B-leg only. siphon Call has no bye()/hangup() — log that.

    terminate() BYEs PSTN too. Prefer siphon-terminated REFER answering a park
    INVITE so the engine BYEs OpenAI itself.
    """
    refer = session.get("referCall") or (
        session.get("sipCall") if session.get("referTransfer") else None
    )
    if refer is None:
        log.warn(
            f"NOTIFY/INBOUND: OpenAI BYE skipped — no referCall "
            f"session={session.get('sessionId')} "
            f"referTransfer={bool(session.get('referTransfer'))}"
        )
        return
    names = [n for n in ("bye", "hangup") if callable(getattr(refer, n, None))]
    if not names:
        have = [n for n in dir(refer) if not n.startswith("_")]
        log.warn(
            f"NOTIFY/INBOUND: OpenAI BYE skipped — Call has no bye/hangup "
            f"session={session.get('sessionId')} methods={have[:24]}"
        )
        return
    for name in names:
        fn = getattr(refer, name)
        try:
            fn()
            log.info(
                f"NOTIFY/INBOUND: BYE OpenAI B-leg via call.{name} "
                f"session={session.get('sessionId')}"
            )
            return
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/INBOUND: OpenAI {name} failed: {exc}")


_xfer_wake_dids: set[str] = set()


def mark_xfer_wake(to_id: str) -> None:
    did = policy.strip_plus_and_domain_suffix(str(to_id or ""))
    if did:
        _xfer_wake_dids.add(did)


def clear_xfer_wake(to_id: str) -> None:
    did = policy.strip_plus_and_domain_suffix(str(to_id or ""))
    if did:
        _xfer_wake_dids.discard(did)


def xfer_wake_running(to_id: str) -> bool:
    did = policy.strip_plus_and_domain_suffix(str(to_id or ""))
    return bool(did and did in _xfer_wake_dids)


def _reject_inbound_sip(session: dict[str, Any], code: int, reason: str) -> None:
    """UAS reject/hangup for SBC→WebRTC inbound (no hairpin).

    Early (180, no 200): call.reject. Confirmed: BYE via terminate.
    b2buaCallId is the SIP Call-ID even while ringing — do not treat it as confirmed.
    """
    call = session.get("sipCall")
    try:
        if _session_sip_confirmed(session):
            from siphon import b2bua as _b2bua

            terminate = getattr(_b2bua, "terminate", None)
            bye_ids: list[str] = []
            for key in ("b2buaCallId", "mediaCallId"):
                cid = str(session.get(key) or "").strip()
                if cid and cid not in bye_ids:
                    bye_ids.append(cid)
            if callable(terminate) and bye_ids:
                ok_any = False
                for cid in bye_ids:
                    ok = terminate(cid, reason)
                    ok_any = ok_any or bool(ok)
                    log.info(
                        f"NOTIFY/INBOUND: BYE via b2bua.terminate call_id={cid} ok={ok}"
                    )
            # terminate queues a BYE on the accepted socket and returns before
            # it is sent. That socket is gone after the pool idle timeout, so
            # also BYE the INVITE Contact on a new connection.
            _schedule_coro(_bye_inbound_peer(session))
            return
        if call is None:
            return
        reject_code = int(code) if int(code) >= 400 else 486
        call.reject(reject_code, str(reason or "Busy Here")[:64])
        session["sipRejected"] = True
        log.info(
            f"NOTIFY/INBOUND: reject {reject_code} {reason} "
            f"session={session.get('sessionId')}"
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/INBOUND: SIP reject/BYE failed: {exc}")


def _uas_progress(call: Any, code: int = 180, reason: str = "Ringing") -> bool:
    """Send provisional. Deployed siphon may lack call.progress — log clearly."""
    progress = getattr(call, "progress", None)
    if not callable(progress):
        log.warn(
            "NOTIFY/INBOUND: call.progress missing on this siphon build — "
            "no 180 Ringing (rebuild siphon image for UAS provisionals)"
        )
        return False
    try:
        progress(code, reason)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/INBOUND: progress {code} failed: {exc}")
        return False
    # siphon logs ERROR "no live B2BUA call" but still returns Ok(()) — 180
    # never went out and local_tag stays empty.
    if not _uas_local_tag(call):
        log.info(
            f"NOTIFY/INBOUND: progress {code} no-op (UAS already gone, likely CANCEL)"
        )
        return False
    log.info(f"NOTIFY/INBOUND: progress {code} {reason}")
    return True


def _uas_local_tag(call: Any) -> str:
    """A-leg UAS To-tag (sb-…) after progress/answer — must match NG to-tag."""
    tag = getattr(call, "local_tag", None)
    if callable(tag):
        try:
            tag = tag()
        except Exception:  # noqa: BLE001
            tag = None
    text = str(tag or "").strip()
    return text


def _uas_answer(call: Any, body: str) -> None:
    """Send UAS 200 with SDP. Raises if answer API missing; logs if send may no-op."""
    answer = getattr(call, "answer", None)
    if not callable(answer):
        raise RuntimeError(
            "call.answer missing on this siphon build — cannot complete inbound UAS"
        )
    # Prefer kwargs (current siphon); fall back to positional.
    try:
        answer(200, "OK", body=body, content_type="application/sdp")
    except TypeError:
        answer(200, "OK", body)
    contact_host = _rtpengine_media_address() or os.environ.get("SIPHON_BIND_IP", "")
    to_tag = _uas_local_tag(call)
    log.info(
        f"NOTIFY/INBOUND: call.answer(200) invoked plain_bytes={len(body or '')} "
        f"contact_host={contact_host or '-'} local_tag={to_tag or '-'} "
        "(UAS Contact from advertised BIND_IP:5061/tls)"
    )


def _sms_author_payload(payload: Any) -> Any:
    """la-sms-client-outbound reads author/recipient. The message uses from/to."""
    obj = payload
    if isinstance(obj, str):
        text = obj.strip()
        if not text or text[0] not in "{[":
            return payload
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return payload
    if not isinstance(obj, dict):
        return payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
    if not obj.get("author") and obj.get("from"):
        obj["author"] = obj["from"]
    if not obj.get("recipient") and obj.get("to"):
        obj["recipient"] = obj["to"]
    return json.dumps(obj, separators=(",", ":"))


def _contract_notify_body(raw: dict[str, Any], req) -> dict[str, Any]:
    """Body la-sms-client-outbound requires: x-sign, x-data, payload, serviceProvider. Protocol stays off this JSON."""
    xsign = raw.get("x-sign") or raw.get("xsign")
    xdata = raw.get("x-data") or raw.get("xdata")
    service_provider = str(raw.get("serviceProvider") or raw.get("service_provider") or "").strip()
    try:
        xsign = xsign or req.header("x-sign") or req.header("xsign")
        xdata = xdata or req.header("x-data") or req.header("xdata")
    except Exception:  # noqa: BLE001
        pass
    payload = _sms_author_payload(raw.get("payload"))
    body = {"x-sign": xsign, "x-data": xdata, "payload": payload}
    if service_provider:
        body["serviceProvider"] = service_provider
    return body


async def _forward_plaintext(req, payload: dict[str, Any], contract_body: dict[str, Any]):
    """Auth, then POST the contract body to this provider's smsUrl."""
    import requests

    notify_port, port_src = logic_client.resolve_notify_port(req)
    port_provider = policy.logic_provider_for_notify_port(notify_port)
    port_sp = str((port_provider or {}).get("id") or "")
    logic_sp, named = _auth_logic_sp(payload, port_sp)
    log.info(
        f"NOTIFY plaintext auth begin from={payload.get('from')!r} to={payload.get('to')!r} "
        f"port={notify_port if notify_port is not None else '-'} portSrc={port_src} "
        f"sp={logic_sp or 'fan-out'} serviceProvider={payload.get('serviceProvider') or '-'}"
    )
    auth = await _authenticate_notify(payload, logic_sp, fallback=named)
    sp = str(auth.get("logicSp") or logic_sp or "").strip().lower()
    provider = policy.logic_provider(sp) or {}
    sms_url = str(provider.get("smsUrl") or "").strip()
    log.info(f"NOTIFY plaintext auth ok sp={sp} smsUrl={bool(sms_url)}")
    if not sms_url:
        return _json_response(500, {"error": "smsUrl not configured", "logicSp": sp})
    timeout_s = max(0.5, int(provider.get("timeoutMs") or 15000) / 1000.0)

    def _post():
        return requests.post(
            sms_url,
            json=contract_body,
            headers={"Content-Type": "application/json"},
            timeout=timeout_s,
        )

    resp = await asyncio.to_thread(_post)
    text = resp.text or ""
    try:
        body = resp.json()
    except ValueError:
        body = {"body": text}
    log.info(f"NOTIFY plaintext forward sp={sp} status={resp.status_code}")
    return _json_response(int(resp.status_code or 502), body)


def _json_response(status: int, body: Any) -> Any:
    headers = {"Content-Type": "application/json", **CORS_HEADERS}
    return http.Response(status=status, headers=headers, body=json.dumps(body).encode())


def _merge_headers(payload: dict[str, Any], req) -> dict[str, Any]:
    header_xsign = req.header("x-sign") or req.header("xsign")
    header_xdata = req.header("x-data") or req.header("xdata")
    # iOS signs the HTTP x-data header. Nested JSON xdata is a different nonce —
    # posting that to GCP /auth recovers the wrong signer and 403s.
    if header_xsign:
        payload["xsign"] = header_xsign
        payload.pop("x-sign", None)
    if header_xdata:
        payload["xdata"] = header_xdata
        payload.pop("x-data", None)
    return payload


def _loads_notify_body(raw_text: str) -> dict[str, Any]:
    """Accept a normal JSON envelope, or one whose payload is raw {{MESSAGE}}.

    The plan writes `"payload":"{{MESSAGE}}"`. The message is inserted as-is,
    including into FCM data.body. A JSON offer then makes the outer body invalid
    JSON. Slice the payload value out and parse that on its own.
    """
    text = raw_text.lstrip("\ufeff").strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = _loads_raw_message_body(text)
    if not isinstance(parsed, dict):
        raise ValueError("JSON object required")
    return parsed


def _loads_raw_message_body(text: str) -> dict[str, Any]:
    key = '"payload"'
    idx = text.find(key)
    if idx < 0:
        raise ValueError("JSON object required")
    i = idx + len(key)
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n or text[i] != ":":
        raise ValueError("JSON object required")
    i += 1
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n:
        raise ValueError("JSON object required")
    decoder = json.JSONDecoder()
    start = i
    if text[i] == '"':
        nxt = i + 1
        while nxt < n and text[nxt] in " \t\r\n":
            nxt += 1
        if nxt < n and text[nxt] in "{[":
            payload, end = decoder.raw_decode(text, nxt)
            if end < n and text[end] == '"':
                end += 1
        else:
            payload, end = decoder.raw_decode(text, i)
    elif text[i] in "{[":
        payload, end = decoder.raw_decode(text, i)
    else:
        raise ValueError("JSON object required")
    try:
        envelope = json.loads(text[:start] + "null" + text[end:])
    except json.JSONDecodeError as exc:
        raise ValueError("JSON object required") from exc
    if not isinstance(envelope, dict):
        raise ValueError("JSON object required")
    envelope["payload"] = payload
    return envelope


def _notify_protocol(raw: dict[str, Any], req) -> str:
    proto = str(raw.get("protocol") or "").strip().lower()
    if proto:
        return proto
    try:
        return str(req.header("protocol") or "").strip().lower()
    except Exception:  # noqa: BLE001
        return ""


def _as_object(value: Any) -> Optional[dict[str, Any]]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode()
        except Exception:  # noqa: BLE001
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text or text[0] not in "{[":
            return None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _auth_logic_sp(payload: dict[str, Any], port_sp: str) -> tuple[str, bool]:
    """Return (auth sp, named). An unknown serviceProvider fans out instead of 400."""
    requested = str(payload.get("serviceProvider") or "").strip().lower()
    if not requested:
        return str(port_sp or "").strip().lower(), False
    if policy.logic_provider(requested) is None:
        log.info(f"NOTIFY auth serviceProvider={requested!r} unknown → fan-out")
        return "", True
    return requested, True


async def _authenticate_notify(
    payload: dict[str, Any], auth_sp: str, *, fallback: bool
) -> dict[str, Any]:
    """Try the named wrapper first. On failure, fan out, then surface that error."""
    if not auth_sp:
        return await logic_client.authenticate_offer(payload, origin="client", logic_sp="")
    try:
        return await logic_client.authenticate_offer(
            payload, origin="client", logic_sp=auth_sp
        )
    except identity.IdentityError as exc:
        if not fallback:
            raise
        log.info(f"NOTIFY auth pin failed sp={auth_sp} → fan-out: {exc}")
        return await logic_client.authenticate_offer(payload, origin="client", logic_sp="")


def _first_key(sources: list[Any], keys: list[str]) -> Any:
    for obj in sources:
        if not isinstance(obj, dict):
            continue
        for key in keys:
            val = obj.get(key)
            if val is not None and val != "":
                return val
    return None


def _normalize_notify_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Match Node SignalingPipeline.normalizeNotifyPayload (unwrap nested wrappers)."""
    nested = _as_object(raw.get("payload"))
    body = _as_object(raw.get("body"))
    data = _as_object(raw.get("data"))
    data_body = _as_object(data.get("body")) if data else None
    normalized: dict[str, Any]
    if nested:
        normalized = dict(nested)
    elif body:
        normalized = dict(body)
    elif data_body:
        normalized = dict(data_body)
    elif data and data.get("type"):
        normalized = dict(data)
    else:
        normalized = dict(raw)

    auth_sources = [raw, data, nested, body, data_body, normalized]
    xsign = _first_key(auth_sources, ["xsign", "x-sign"])
    xdata = _first_key(auth_sources, ["xdata", "x-data"])
    if xsign and not normalized.get("xsign") and not normalized.get("x-sign"):
        normalized["xsign"] = xsign
    if xdata and not normalized.get("xdata") and not normalized.get("x-data"):
        normalized["xdata"] = xdata
    service_provider = _first_key(auth_sources, ["serviceProvider", "service_provider"])
    if service_provider and not normalized.get("serviceProvider"):
        normalized["serviceProvider"] = service_provider

    # Case-insensitive top-level aliases clients sometimes send.
    if not normalized.get("from"):
        alt_from = _first_key(
            [normalized, raw],
            ["From", "caller", "fromIdentity", "fromEns", "author"],
        )
        if alt_from:
            normalized["from"] = alt_from
    if not normalized.get("to"):
        alt_to = _first_key(
            [normalized, raw],
            ["To", "callee", "toIdentity", "toEns", "recipient"],
        )
        if alt_to:
            normalized["to"] = alt_to
    return normalized


def _clip(value: Any, limit: int = 120) -> str:
    text = str(value if value is not None else "")
    if len(text) <= limit:
        return text
    return text[:limit] + f"...(+{len(text) - limit})"


def _summarize_notify(raw: dict[str, Any], payload: dict[str, Any], raw_len: int) -> str:
    sdp = payload.get("sdp")
    sdp_len = len(sdp) if isinstance(sdp, (str, bytes, bytearray)) else 0
    candidates = payload.get("candidates")
    cand_n = len(candidates) if isinstance(candidates, list) else 0
    types = ""
    try:
        sdp_text = sdp.decode(errors="replace") if isinstance(sdp, (bytes, bytearray)) else str(sdp or "")
        merged = webrtc_pc.merge_ice_array_and_sdp(
            sdp_text, candidates if isinstance(candidates, list) else []
        )
        if merged:
            types = f" types[{webrtc_pc.candidate_type_counts(merged)}]"
    except Exception:  # noqa: BLE001
        types = ""
    return (
        f"raw_keys={sorted(raw.keys())} norm_keys={sorted(payload.keys())} "
        f"raw_bytes={raw_len} type={payload.get('type')!r} "
        f"from={_clip(payload.get('from'))!r} to={_clip(payload.get('to'))!r} "
        f"sessionId={_clip(payload.get('sessionId'), 64)!r} "
        f"serviceId={payload.get('serviceId')!r} "
        f"has_xdata={bool(payload.get('xdata') or payload.get('x-data'))} "
        f"has_xsign={bool(payload.get('xsign') or payload.get('x-sign'))} "
        f"protocol={payload.get('protocol') or raw.get('protocol') or '-'!r} "
        f"sdp_len={sdp_len} candidates={cand_n}{types}"
    )


def _body_text(sdp: Any) -> str:
    if sdp is None:
        return ""
    if isinstance(sdp, bytes):
        return sdp.decode(errors="replace")
    return str(sdp)


def _log_sdp(label: str, sdp: str) -> None:
    text = _body_text(sdp)
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    mline = next((ln for ln in lines if ln.startswith("m=audio")), "-")
    te = [
        ln.split(":", 1)[1].strip()
        for ln in lines
        if ln.lower().startswith("a=rtpmap:") and "telephone-event" in ln.lower()
    ]
    width = max(2, len(str(max(len(lines), 1))))
    body = "\n".join(f"  {i:>{width}}  {ln}" for i, ln in enumerate(lines, 1))
    if not body.strip():
        body = "  (empty SDP)"
    log.info(
        f"\n======== {label} ========\n"
        f"  bytes={len(text)}  lines={len(lines)}  te={bool(te)}\n"
        f"  {mline}\n"
        f"  telephone-event: {', '.join(te) or 'none'}\n"
        f"{body}\n"
        f"======== end {label} ========"
    )


def _register_hairpin_waiter(ingress_id: str) -> asyncio.Future:
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    with _hairpin_lock:
        prior = _hairpin_waiters.pop(ingress_id, None)
        _hairpin_waiters[ingress_id] = fut
    if prior is not None and not prior.done():
        prior.set_exception(RuntimeError("superseded hairpin waiter"))
    return fut


def _pop_hairpin_waiter(ingress_id: str) -> Optional[asyncio.Future]:
    with _hairpin_lock:
        return _hairpin_waiters.pop(ingress_id, None)


def complete_sbc_hairpin_answer(ingress_id: str, answer_sdp: str) -> None:
    """Called from B2BUA on_answer when the hairpin A-leg is answered."""
    fut = _pop_hairpin_waiter(ingress_id)
    if fut is None or fut.done():
        return
    body = _body_text(answer_sdp)

    def _set() -> None:
        if not fut.done():
            fut.set_result(body)

    fut_loop = fut.get_loop()
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    try:
        if running is fut_loop:
            _set()
        elif fut_loop.is_running():
            fut_loop.call_soon_threadsafe(_set)
        else:
            _set()
    except Exception as exc:  # noqa: BLE001
        log.warn(f"SBC_HAIRPIN: complete waiter failed ingress={ingress_id}: {exc}")


def fail_sbc_hairpin(ingress_id: str, message: str) -> None:
    """Fail the hairpin waiter (thread-safe — DC callbacks may not be on the loop)."""
    fut = _pop_hairpin_waiter(ingress_id)
    if fut is None or fut.done():
        return
    exc = RuntimeError(message)

    def _set() -> None:
        if not fut.done():
            fut.set_exception(exc)

    fut_loop = fut.get_loop()
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    try:
        if running is fut_loop:
            _set()
        elif fut_loop.is_running():
            fut_loop.call_soon_threadsafe(_set)
        else:
            _set()
    except Exception as exc2:  # noqa: BLE001
        log.warn(f"SBC_HAIRPIN: fail waiter failed ingress={ingress_id}: {exc2}")


def _store_hairpin_ng_keys(
    ingress_id: str, *, call_id: str, from_tag: str, session_id: str
) -> None:
    with _hairpin_ng_lock:
        _hairpin_ng_keys[str(ingress_id)] = {
            "call_id": str(call_id or ""),
            "from_tag": str(from_tag or ""),
            "session_id": str(session_id or ""),
        }
    session = _get_session(str(session_id or ""))
    if session is None:
        return
    session["sbcNgCallId"] = str(call_id or "")
    session["sbcNgFromTag"] = str(from_tag or "")


def _peek_hairpin_ng_keys(ingress_id: str) -> dict[str, str]:
    with _hairpin_ng_lock:
        raw = _hairpin_ng_keys.get(str(ingress_id))
        return dict(raw) if raw else {}


def _pop_hairpin_ng_keys(ingress_id: str) -> Optional[dict[str, str]]:
    with _hairpin_ng_lock:
        return _hairpin_ng_keys.pop(str(ingress_id), None)


def _map_ring_fail_reason(error: Any) -> str:
    msg = str(error or "")
    msg_l = msg.lower()
    if "callee declined" in msg_l or "declined before pickup" in msg_l:
        return "callee-declined"
    if "sbc invite failed" in msg_l or " 603 " in f" {msg} " or msg_l.endswith("603 decline"):
        return "sbc-decline"
    if "603" in msg and "decline" in msg_l and "callee" not in msg_l:
        return "sbc-decline"
    if "408" in msg or "timed out" in msg_l or "timeout" in msg_l:
        return "ring-timeout"
    if "internal" in msg_l:
        return "internal-error"
    if "remote-bye" in msg_l:
        return "remote-bye"
    if "abandoned" in msg_l or "cancel" in msg_l:
        return "cancelled"
    return "ring-failed"


def _session_sip_confirmed(session: dict[str, Any]) -> bool:
    # hadConfirmedSip survives soft-end. That path clears sbcAnswered before
    # _mark_never_connected_fail, and a confirmed SIP leg was then treated as
    # never answered, so the next invite cold-pushed instead of RING on the DC.
    return bool(
        session.get("sbcAnswered")
        or session.get("inboundSipAnswered")
        or session.get("hadConfirmedSip")
    )


def _live_callee_legs(session: dict[str, Any]) -> list[Any]:
    """Callee PCs with an open data channel. A ringing invite PC is not one."""
    kept: list[Any] = []
    for leg in (session.get("ringLegs") or {}).values():
        if leg is None:
            continue
        try:
            if leg.dc_reusable():
                kept.append(leg)
        except Exception:  # noqa: BLE001
            continue
    return kept


def _caller_stopped(session: dict[str, Any], reason: str) -> bool:
    return reason == "cancelled" or bool(session.get("callerCancelForwarded"))


async def _keep_callee_pcs(session: dict[str, Any], session_id: str) -> None:
    """Drop the caller SIP/pc1 leg. Leave each callee PC registered."""
    if session.get("mediaBridged"):
        try:
            await webrtc_pc.unbridge_media(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"NOTIFY: keep-callee unbridge failed session={session_id}: {exc}"
            )
    _schedule_recording_upload(session)
    try:
        await webrtc_pc.close_inbound_sip_pc(session)
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY: keep-callee close sip pc failed session={session_id}: {exc}"
        )
    try:
        _delete_session_rtpengine(session, session_id)
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY: keep-callee rtpengine delete failed session={session_id}: {exc}"
        )
    session["skipCalleeDcReuse"] = False
    session["clientEnded"] = False
    webrtc_pc.reset_soft_end_for_reuse(session)
    for leg in _live_callee_legs(session):
        try:
            leg.attach_kept_callee()
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"NOTIFY: attach kept callee failed session={session_id}: {exc}"
            )
    session["failureCleanupDone"] = True
    idents = [str(getattr(leg, "ident", "") or "") for leg in _live_callee_legs(session)]
    log.info(
        f"NOTIFY: keep callee PC session={session_id} legs={idents}"
    )


def _mark_never_connected_fail(session: dict[str, Any]) -> None:
    """Callee never picked up — don't RING their leftover incoming PC.

    Do not block the *caller's* pc1 DC. Next outbound RING on the same DC is
    a new call; hunt cold-invites the callee if their DC is gone.
    """
    if _session_sip_confirmed(session):
        return
    session["skipCalleeDcReuse"] = True


def callee_ring_suppressed_after_soft_end(session: dict[str, Any]) -> bool:
    until = float(session.get("calleeRingSuppressUntil") or 0)
    return until > 0.0 and time.monotonic() < until


def _sdp_ios_split_leftover_audio(sdp: str) -> bool:
    """Post-hangup iOS: old m-line recvonly/inactive plus a new send* m-line."""
    text = str(sdp or "").replace("\r\n", "\n")
    sections = re.split(r"(?=^m=)", text, flags=re.M)
    audio = [s for s in sections if s.startswith("m=audio ")]
    if len(audio) < 2:
        return False
    dirs: list[str] = []
    for section in audio:
        if re.search(r"^a=inactive", section, re.M):
            dirs.append("inactive")
        elif re.search(r"^a=recvonly", section, re.M):
            dirs.append("recvonly")
        elif re.search(r"^a=sendonly", section, re.M):
            dirs.append("sendonly")
        elif re.search(r"^a=sendrecv", section, re.M):
            dirs.append("sendrecv")
    dead = "recvonly" in dirs or "inactive" in dirs
    live = "sendrecv" in dirs or "sendonly" in dirs
    return dead and live


def _signal_dc_end(session: dict[str, Any], reason: str) -> bool:
    """Send CallKit/DC hangup. Only True when bytes went out."""
    if session.get("clientEnded") or session.get("endCallSent"):
        return bool(session.get("endCallSent"))
    sent = bool(webrtc_pc.send_dc_end_call(session, reason))
    if sent:
        session["endCallSent"] = True
    return sent


def _is_product_leg(session: dict[str, Any]) -> bool:
    return str(session.get("state") or "") == "product"


def _resolve_fail_session(
    session: Optional[dict[str, Any]] = None,
    session_id: str = "",
    ingress_id: str = "",
) -> tuple[Optional[dict[str, Any]], str]:
    if isinstance(session, dict):
        return session, _storage_key(session) or str(session.get("sessionId") or session_id or "")
    sid = str(session_id or "").strip()
    if not sid and ingress_id:
        sid = str(_peek_hairpin_ng_keys(ingress_id).get("session_id") or "").strip()
    if sid:
        return _get_session(sid), sid
    return None, sid


_pinned_loop: asyncio.AbstractEventLoop | None = None


def pin_event_loop(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Keep the siphon asyncio loop so UDP/DTMF threads can schedule coros."""
    global _pinned_loop
    if loop is None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
    if loop is not None and loop.is_running():
        _pinned_loop = loop


def _schedule_coro(coro: Any) -> None:
    """Fire-and-forget coroutine from sync or async context."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
        pin_event_loop(loop)
        return
    except RuntimeError:
        pass
    loop = _pinned_loop
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, loop)
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(coro, loop)
            pin_event_loop(loop)
            return
    except Exception:  # noqa: BLE001
        pass
    log.warn("NOTIFY: _schedule_coro could not find a running event loop")


def _start_task_on_session_loop(session: dict[str, Any], coro: Any) -> asyncio.Task[Any]:
    """Create a Task on the loop that owns the WebRTC PC / ring futures.

    HTTP /notify can run on a different asyncio loop than SIP inbound. Driving
    RingLeg there waits on SIP-loop futures and then close() kills the PC.
    """
    target = session.get("eventLoop") if isinstance(session, dict) else None
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if target is None:
        if running is None:
            raise RuntimeError("no event loop for session task")
        session["eventLoop"] = running
        return running.create_task(coro)
    if running is target:
        return target.create_task(coro)
    holder: dict[str, Any] = {}
    done = threading.Event()

    def _create() -> None:
        try:
            holder["task"] = target.create_task(coro)
        except Exception as exc:  # noqa: BLE001
            holder["err"] = exc
        done.set()

    target.call_soon_threadsafe(_create)
    if not done.wait(timeout=5.0):
        try:
            coro.close()
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError("session loop did not accept task")
    err = holder.get("err")
    if err is not None:
        try:
            coro.close()
        except Exception:  # noqa: BLE001
            pass
        raise err
    return holder["task"]


async def _await_on_session_loop(session: dict[str, Any], coro: Any) -> Any:
    """Run a coroutine on the PC's loop when HTTP notify is elsewhere."""
    target = session.get("eventLoop") if isinstance(session, dict) else None
    running = asyncio.get_running_loop()
    if target is None or target is running:
        return await coro
    cfut = asyncio.run_coroutine_threadsafe(coro, target)
    try:
        return await asyncio.wrap_future(cfut)
    except asyncio.CancelledError:
        cfut.cancel()
        raise


def _recording_did(session: dict[str, Any]) -> str:
    route = session.get("route") or {}
    inbound = session.get("inboundCall") if isinstance(session.get("inboundCall"), dict) else {}
    for cand in (
        session.get("recordingDid"),
        route.get("number"),
        inbound.get("toNumber"),
        route.get("targetValue"),
        session.get("dialedTo"),
        session.get("originTo"),
        session.get("to"),
    ):
        digits = "".join(ch for ch in str(cand or "") if ch.isdigit())
        if len(digits) >= 8:
            return digits
    return str(
        session.get("recordingDid")
        or route.get("number")
        or inbound.get("toNumber")
        or session.get("dialedTo")
        or session.get("to")
        or ""
    ).strip()


def _apply_recording_policy(session: dict[str, Any], src: Optional[dict[str, Any]]) -> None:
    """Copy wrapper recording fields onto the session. Siphon does not decide."""
    if not isinstance(session, dict) or not isinstance(src, dict):
        return
    if "callRecordingEnabled" in src:
        session["callRecordingEnabled"] = bool(src.get("callRecordingEnabled"))
    if isinstance(src.get("recordingSps"), list):
        session["recordingSps"] = [
            str(item).strip().lower()
            for item in src.get("recordingSps") or []
            if str(item or "").strip()
        ]
    sys_id = str(src.get("systemId") or "").strip()
    if sys_id:
        session["systemId"] = sys_id
    digits = "".join(ch for ch in str(src.get("number") or src.get("targetValue") or "") if ch.isdigit())
    if len(digits) >= 8:
        session["recordingDid"] = digits
    elif not session.get("recordingDid"):
        origin = "".join(ch for ch in str(session.get("originTo") or session.get("dialedTo") or "") if ch.isdigit())
        if len(origin) >= 8:
            session["recordingDid"] = origin


def _reset_recording_state(session: dict[str, Any]) -> None:
    """Clear per-call recording state so reused sessions can record and upload again."""
    if not isinstance(session, dict):
        return
    session.pop("recordingUploadScheduled", None)
    session.pop("recordingWav", None)
    session.pop("recordingStartedAt", None)
    session.pop("recordingEndedAt", None)
    session.pop("callRecorder", None)


def _schedule_recording_upload(session: dict[str, Any]) -> None:
    """Finalize tee and POST wav to the logic wrapper. Does not talk to GCS."""
    if session.get("recordingUploadScheduled"):
        log.info(f"RECORD: skip (already scheduled) session={session.get('sessionId')}")
        return
    sid = session.get("sessionId")
    task = session.get("voicemailRecordTask")
    if (
        isinstance(task, asyncio.Task)
        and not task.done()
        and task is not asyncio.current_task()
    ):
        log.info(f"RECORD: defer (voicemail pcap still open) session={sid}")
        return
    if not webrtc_pc.session_should_record(session):
        log.info(f"RECORD: skip (disabled) session={sid}")
        return
    wav = webrtc_pc.finalize_recording(session)
    if not wav:
        log.info(f"RECORD: skip (empty wav) session={sid}")
        return
    if not (
        session.get("sbcAnswered")
        or session.get("inboundSipAnswered")
        or session.get("mediaBridged")
        or session.get("recordingStartedAt")
        or session.get("recordingWav")
    ):
        log.info(f"RECORD: skip (never answered) session={sid}")
        return
    session["recordingUploadScheduled"] = True
    route = session.get("route") or {}
    did = _recording_did(session)
    system_id = str(session.get("systemId") or route.get("systemId") or "").strip()
    call_id = str(
        session.get("mediaCallId") or session.get("sessionId") or uuid.uuid4()
    ).strip()
    winner = str(session.get("multiringWinner") or session.get("to") or "").strip()
    started = session.get("recordingStartedAt")
    ended = session.get("recordingEndedAt") or time.time()
    headers = {
        "x-call-id": call_id,
        "x-did": did,
        "x-number": did,
        "x-system-id": system_id,
        "x-winner": winner,
        "x-from": str(session.get("from") or ""),
        "x-session-id": str(session.get("sessionId") or ""),
    }
    rec_kind = str(session.get("recordingKind") or "").strip().lower()
    if rec_kind:
        headers["x-recording-kind"] = rec_kind
    if started:
        headers["x-started-at"] = str(int(float(started)))
        headers["x-ended-at"] = str(int(float(ended)))
        headers["x-duration-ms"] = str(max(0, int((float(ended) - float(started)) * 1000)))
    log_rows = session.get("dtmfLog") if isinstance(session.get("dtmfLog"), list) else []
    xfer_rows = session.get("transferLog") if isinstance(session.get("transferLog"), list) else []
    headers["x-dtmf-log"] = json.dumps(log_rows, separators=(",", ":"), ensure_ascii=True)
    headers["x-transfer-log"] = json.dumps(xfer_rows, separators=(",", ":"), ensure_ascii=True)
    headers = {k: v for k, v in headers.items() if v}
    sps: list[str] = []
    raw_sps = session.get("recordingSps")
    if not isinstance(raw_sps, list):
        raw_sps = route.get("recordingSps")
    if isinstance(raw_sps, list):
        for item in raw_sps:
            sid = str(item or "").strip().lower()
            if sid and sid not in sps:
                sps.append(sid)
    if not sps:
        fallback = str(session.get("logicSp") or route.get("logicSp") or "").strip().lower()
        if fallback:
            sps.append(fallback)
    if not sps:
        log.warn("RECORD: upload skipped (no logicSp)")
        session["recordingWav"] = None
        return
    session["recordingWav"] = None
    log.info(
        f"RECORD: scheduling upload session={session.get('sessionId')} "
        f"bytes={len(wav)} did={did!r} callId={call_id!r} sps={sps}"
    )
    for sp in sps:
        _schedule_coro(_upload_recording(sp, headers, wav))


async def _upload_recording(sp: str, headers: dict[str, str], wav: bytes) -> None:
    provider = policy.logic_provider(sp)
    if not provider:
        log.warn(f"RECORD: upload skipped (no logic provider sp={sp!r})")
        return
    try:
        data = await logic_client.post_recording_wav(provider, headers, wav)
        log.info(
            f"RECORD: upload done callId={headers.get('x-call-id')!r} "
            f"http={data.get('_httpStatus')} object={data.get('object')!r} "
            f"accepted={data.get('accepted')} emailed={data.get('emailed')} "
            f"did={headers.get('x-did')!r} reason={data.get('reason')!r}"
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"RECORD: upload failed callId={headers.get('x-call-id')!r}: {exc}")


async def fail_notify_call(
    error: Any,
    *,
    session: Optional[dict[str, Any]] = None,
    session_id: str = "",
    ingress_id: str = "",
    cancel_sip: bool = True,
) -> None:
    """Single failure path: soft-end when DC is up; else hard SIP/PC teardown.

    Idempotent. Skip DC end only when the caller already hung up (clientEnded).
    Soft path keeps the session for DC RING reuse (Node parity). Hard path pops
    the session when no usable DC exists.
    """
    ingress = str(ingress_id or "").strip()
    sess, sid = _resolve_fail_session(session, session_id, ingress)
    if sess is None and not ingress:
        log.warn(f"NOTIFY: fail_notify_call no session/ingress error={error}")
        return

    if sess is not None and (
        sess.get("failureCleanupDone") or sess.get("softEndInProgress")
    ):
        log.info(
            f"NOTIFY: fail_notify_call skip session={sid or '?'} "
            f"cleanup={bool(sess.get('failureCleanupDone'))} "
            f"softEnd={bool(sess.get('softEndInProgress'))} error={error}"
        )
        return
    if sess is not None:
        sess["failureNotified"] = True
        sess["dcRingStarted"] = False
        if sess.get("voicemailActive"):
            # The recorder runs on the session loop. Awaiting it from the SIP
            # loop raises "attached to a different loop" and then the upload
            # below sees no wav. The recorder uploads once the pcap is closed.
            sess["clientEnded"] = True
        if not ingress:
            ingress = str(sess.get("sbcHairpinId") or "").strip()

    reason = _map_ring_fail_reason(error)
    log.error(
        f"NOTIFY: fail_notify_call session={sid or '?'} ingress={ingress or '-'} "
        f"reason={reason} error={error}"
    )

    if sess is not None and reason in ("cancelled", "remote-bye", "hangup", "end"):
        try:
            await _forward_cancel_to_ringing(sess, reason=reason)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: fail_notify forward-cancel failed session={sid}: {exc}")
        # Bridged media is the two live legs (caller↔phone, or caller↔voicemail).
        # An unanswered ring seat is not one of them. Waiting on its DC holds
        # the other leg's BYE and keeps the wav running after the call is over.
        live = bool(sess.get("mediaBridged") or sess.get("voicemailActive"))
        if live:
            log.info(
                f"NOTIFY: skip callee DC wait session={sid} "
                f"bridged={bool(sess.get('mediaBridged'))} "
                f"voicemail={bool(sess.get('voicemailActive'))}"
            )
        else:
            try:
                await _wait_cancelled_callee_dc_end(sess)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY: fail_notify wait callee DC end failed session={sid}: {exc}")

    if sess is not None and _is_product_leg(sess):
        log.info(
            f"NOTIFY: product-leg hangup skip webrtc teardown session={sid} "
            f"routeKind={sess.get('routeKind')}"
        )
        if sid:
            _pop_session(sid)
        if sess is not None:
            _schedule_grok_call(sess, reason, ended_leg="pc1", client_ended=bool(sess.get("clientEnded")))
        return

    if ingress:
        fail_sbc_hairpin(ingress, str(error))
        _pop_hairpin_ng_keys(ingress)

    if sess is None:
        return

    has_dc = bool(
        (sess.get("dcOpen") and sess.get("dataChannel") is not None)
        or (sess.get("calleeDcOpen") and sess.get("calleeDataChannel") is not None)
    )

    unanswered = reason in ("ring-timeout", "callee-declined", "ring-failed")
    # Soft keep: open DC → inactive reneg + SIP hard end, session stays registered.
    # Unanswered hunt: pc1 only — do not end-call / FCM-cancel the callee we missed.
    if has_dc and not sess.get("clientEnded"):
        try:
            if unanswered:
                await _soft_end_call(
                    sess,
                    reason,
                    client_ended=False,
                    ended_leg="pc1",
                    send_ui_end=False,
                    offer_legs=("pc1",),
                    inbound_reject_code=480,
                )
            else:
                await _soft_end_call(
                    sess,
                    reason,
                    client_ended=False,
                    ended_leg="pc1",
                    send_ui_end=True,
                )
            _mark_never_connected_fail(sess)
            return
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"NOTIFY: fail_notify_call soft-end failed → hard close "
                f"session={sid}: {exc}"
            )

    if not sess.get("clientEnded"):
        try:
            if unanswered:
                webrtc_pc.send_leg_ui_hangup(sess, leg="pc1", reason=reason)
            elif _signal_dc_end(sess, reason):
                log.info(
                    f"NOTIFY: end-call signaled session={sid or '?'} reason={reason} "
                    f"pc1_dc={bool(sess.get('dcOpen'))} "
                    f"callee_dc={bool(sess.get('calleeDcOpen'))}"
                )
                await asyncio.sleep(0.08)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: fail_notify_call DC end failed session={sid}: {exc}")

    if cancel_sip and (sess.get("routeKind") == "sbc" or sess.get("voicemailMediaCallId")):
        try:
            await _cancel_pending_sbc(sess)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: fail_notify_call cancel SIP failed session={sid}: {exc}")
    if cancel_sip and sess.get("routeKind") == "inbound":
        try:
            reject_code = 486 if reason == "callee-declined" else 480
            _reject_inbound_sip(sess, reject_code, str(error)[:80] or "Unavailable")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: fail_notify_call inbound reject failed session={sid}: {exc}")

    if _caller_stopped(sess, reason) and _live_callee_legs(sess):
        _hunt_end_session(sess)
        await _keep_callee_pcs(sess, sid)
        return

    _mark_never_connected_fail(sess)

    _hunt_end_session(sess)

    popped = _pop_session(sid) if sid else None
    target = popped or sess
    try:
        if target.get("mediaBridged"):
            await webrtc_pc.unbridge_media(target)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: fail_notify_call unbridge failed session={sid}: {exc}")
    _schedule_recording_upload(target)
    try:
        await webrtc_pc.close(target)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: fail_notify_call PC1 close failed session={sid}: {exc}")
    try:
        _delete_session_rtpengine(target, sid or "unknown")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: fail_notify_call rtpengine delete failed session={sid}: {exc}")
    sess["failureCleanupDone"] = True
    posted = float(target.get("_grokPosted") or 0)
    if time.time() - posted > 1:
        _schedule_grok_call(
            target,
            reason,
            ended_leg="pc1",
            client_ended=bool(target.get("clientEnded")),
        )


def fail_notify_call_sync(
    error: Any,
    *,
    session: Optional[dict[str, Any]] = None,
    session_id: str = "",
    ingress_id: str = "",
    cancel_sip: bool = True,
) -> None:
    """Sync entry (on_failure / Dummy-N). Do not touch DC here — schedule only."""
    ingress = str(ingress_id or "").strip()
    sess, sid = _resolve_fail_session(session, session_id, ingress)
    if sess is not None and (
        sess.get("failureNotified") or sess.get("failureCleanupDone")
    ):
        return
    if sess is not None:
        sess["failureNotified"] = True
        sess["dcRingStarted"] = False
    cleanup = fail_notify_call(
        error,
        session=sess,
        session_id=sid,
        ingress_id=ingress,
        cancel_sip=cancel_sip,
    )
    # Prefer the hairpin waiter's loop (same one _on_dc_ring is awaiting on).
    fut = None
    if ingress:
        with _hairpin_lock:
            fut = _hairpin_waiters.get(ingress)
        fail_sbc_hairpin(ingress, str(error))
    if fut is not None:
        try:
            asyncio.run_coroutine_threadsafe(cleanup, fut.get_loop())
            return
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: fail_notify_call_sync schedule on waiter loop: {exc}")
    _schedule_coro(cleanup)


def _header_from_obj(obj: Any, name: str) -> str:
    try:
        if hasattr(obj, "get_header"):
            return str(obj.get_header(name) or "")
        if hasattr(obj, "header"):
            return str(obj.header(name) or "")
    except Exception:  # noqa: BLE001
        return ""
    return ""


async def ack_sbc_hairpin(call: Any, reply: Any) -> None:
    """ACK the hairpin A-leg 200 — UAC may have already dropped pending on 100.

    Wait briefly so @b2bua.on_answer returns and siphon registers + sends the
    A-leg 200 OK before our ACK lands. Sending the ACK inside on_answer races
    ahead of register_unacked_answer, so the A-leg 200 keeps retransmitting and
    loops back into handle_b2bua_response as a bogus B-leg 200.
    """
    call_id = str(getattr(call, "call_id", None) or getattr(call, "id", "") or "")
    from_hdr = _header_from_obj(call, "From") or _header_from_obj(call, "from")
    to_hdr = _header_from_obj(reply, "To") or _header_from_obj(reply, "to")
    if not from_hdr:
        from_uri = getattr(call, "from_uri", None)
        if from_uri is not None:
            from_hdr = f"<{from_uri}>"
    if not to_hdr:
        to_uri = getattr(call, "to_uri", None)
        if to_uri is not None:
            to_hdr = f"<{to_uri}>"
    if not call_id or not from_hdr or not to_hdr:
        raise RuntimeError("hairpin ACK missing Call-ID/From/To")

    a_local_tag = _uas_local_tag(call)
    if a_local_tag:
        if ";tag=" in to_hdr:
            to_hdr = re.sub(r";tag=[^;\s>]+", f";tag={a_local_tag}", to_hdr)
        else:
            to_hdr = f"{to_hdr};tag={a_local_tag}"

    domain = policy.local_domain()
    bind_ip = policy.local_bind_ip()
    ruri = f"sip:{SBC_HAIRPIN_USER}@{domain}"
    headers = {
        "From": from_hdr,
        "To": to_hdr,
        "Call-ID": call_id,
        "CSeq": "1 ACK",
        "Max-Forwards": "70",
        "Contact": f"<sip:{SBC_HAIRPIN_USER}@{domain}>",
    }
    next_hop = f"sip:{bind_ip}:5060;transport=tcp"
    _remember_hairpin_ack(call, from_hdr, to_hdr, call_id)

    async def _send_ack_after_200() -> None:
        await asyncio.sleep(0.05)
        log.info(f"SBC_HAIRPIN: ACK {ruri} call_id={call_id}")
        await proxy.send_request(
            "ACK",
            ruri,
            headers=headers,
            next_hop=next_hop,
            wait_for_response=False,
        )

    asyncio.create_task(_send_ack_after_200())


def _remember_hairpin_ack(call: Any, from_hdr: str, to_hdr: str, call_id: str) -> None:
    """Keep the A-leg dialog the ACK used, so hangup can BYE it."""
    ingress = _header_from_obj(call, SBC_HAIRPIN_HEADER).strip()
    keys = _peek_hairpin_ng_keys(ingress) if ingress else {}
    session = _get_session(str(keys.get("session_id") or ""))
    if session is None:
        return
    session["hairpinAckFrom"] = from_hdr
    session["hairpinAckTo"] = to_hdr
    session["hairpinAckCallId"] = call_id


def _sdp_has_audio(sdp: str) -> bool:
    """True if SDP has an active audio m-line (port != 0)."""
    for line in str(sdp or "").replace("\r\n", "\n").split("\n"):
        if not line.startswith("m=audio "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            port = int(parts[1])
        except ValueError:
            continue
        if port > 0:
            return True
    return False


def _sdp_is_datachannel_only(sdp: str) -> bool:
    text = str(sdp or "")
    has_dc = "webrtc-datachannel" in text or "UDP/DTLS/SCTP" in text
    return has_dc and not _sdp_has_audio(text)


def _offer_audio_mid(sdp: str) -> str:
    """Audio a=mid from client RING offer (default 0)."""
    text = str(sdp or "").replace("\r\n", "\n")
    m = re.search(r"^m=audio .*\n(?:.*\n)*?^a=mid:([^\n]+)", text, re.M)
    if not m:
        m = re.search(r"^a=mid:([^\n]+)", text, re.M)
    mid = (m.group(1).strip() if m else "0") or "0"
    return mid


def _audio_only_webrtc_sdp(sdp: str, *, force_mid: str = "0") -> str:
    """Strip non-audio m-lines for SBC (Node PC2 is audio-only; no datachannel).

    Client RING offers are BUNDLE(application+audio). PSTN SBCs 603 on
    ``m=application … webrtc-datachannel``. Keep session + audio only, fix BUNDLE.

    force_mid defaults to 0 so rtpengine answers with mid:0 (client PC2 expects that).
    """
    text = str(sdp or "").replace("\r\n", "\n")
    if not text.strip():
        return sdp
    parts = re.split(r"(?=^m=)", text, flags=re.M)
    if not parts:
        return sdp
    session = parts[0]
    audio_sections = [p for p in parts[1:] if p.startswith("m=audio ")]
    if not audio_sections:
        return sdp

    audio = audio_sections[0]
    cand_lines: list[str] = []
    for p in parts[1:]:
        for ln in p.split("\n"):
            if ln.startswith("a=candidate:") and ln not in cand_lines:
                cand_lines.append(ln)
    if cand_lines and not re.search(r"^a=candidate:", audio, re.M):
        audio = audio.rstrip("\n") + "\n" + "\n".join(cand_lines) + "\n"
    mid = str(force_mid or "0").strip() or "0"
    if re.search(r"^a=mid:", audio, re.M):
        audio = re.sub(r"^a=mid:[^\n]*", f"a=mid:{mid}", audio, count=1, flags=re.M)
    else:
        audio = audio.replace("\n", f"\na=mid:{mid}\n", 1) if "\n" in audio else audio

    # Rewrite / insert BUNDLE for the audio mid only.
    if re.search(r"^a=group:BUNDLE\s+", session, re.M):
        session = re.sub(
            r"^a=group:BUNDLE\s+[^\n]+",
            f"a=group:BUNDLE {mid}",
            session,
            count=1,
            flags=re.M,
        )
    else:
        session = session.rstrip("\n") + f"\na=group:BUNDLE {mid}\n"

    out = (session.rstrip("\n") + "\n" + audio.lstrip("\n")).replace("\n", "\r\n")
    if not out.endswith("\r\n"):
        out += "\r\n"
    return out


_TE_RTPMAP_RE = re.compile(
    r"^a=rtpmap:(\d+)\s+telephone-event(?:/\d+)?", re.I | re.M
)


def drop_wideband_telephone_event(sdp: str) -> str:
    """Carrier leg is G.711. Keep telephone-event/8000 only.

    110 telephone-event/48000 on that offer is what Cellact ignores.
    """
    text = str(sdp or "")
    if "telephone-event/" not in text.lower():
        return text
    wide: set[str] = set()
    for match in re.finditer(
        r"^a=rtpmap:(\d+)\s+telephone-event/(\d+)",
        text,
        re.I | re.M,
    ):
        if match.group(2) != "8000":
            wide.add(match.group(1))
    if not wide:
        return text
    ending = "\r\n" if "\r\n" in text else "\n"
    out: list[str] = []
    for line in text.split(ending):
        if line.startswith("m=audio "):
            parts = line.split()
            parts = parts[:3] + [pt for pt in parts[3:] if pt not in wide]
            line = " ".join(parts)
        elif line.startswith(("a=rtpmap:", "a=fmtp:", "a=rtcp-fb:")):
            pt = line.split(":", 1)[1].split()[0].split("/")[0]
            if pt in wide:
                continue
        out.append(line)
    joined = ending.join(out)
    if text.endswith("\r\n") and not joined.endswith("\r\n"):
        joined += "\r\n"
    elif text.endswith("\n") and not joined.endswith("\n"):
        joined += "\n"
    return joined


def telephone_event_pt(sdp: str) -> Optional[str]:
    """Prefer telephone-event/8000 (iOS 126). Do not pick 48000 (110)."""
    found_8k: Optional[str] = None
    found_any: Optional[str] = None
    for m in re.finditer(
        r"^a=rtpmap:(\d+)\s+telephone-event(?:/(\d+))?",
        str(sdp or ""),
        re.I | re.M,
    ):
        pt, rate = m.group(1), m.group(2)
        if found_any is None:
            found_any = pt
        if rate is None or rate == "8000":
            found_8k = pt
            break
    return found_8k or found_any


def ensure_telephone_event_sdp(
    sdp: str, offer: str = "", *, force_offer_pt: bool = False
) -> str:
    """Make sure m=audio advertises RFC 4733 so the client can insertDTMF.

    Insert next to existing rtpmap lines. A blank line after a=ptime is treated
    as end-of-SDP by some UAs (TBSIP), so never append TE after whitespace.
    """
    text = str(sdp or "")
    if "m=audio" not in text.lower():
        return text
    offer_pt = telephone_event_pt(offer) if offer else None
    existing_pt = telephone_event_pt(text)
    if existing_pt and (not force_offer_pt or not offer_pt or existing_pt == offer_pt):
        return text
    pt = offer_pt or existing_pt or "126"
    fmtp = "0-16"
    om = re.search(
        rf"^a=fmtp:{re.escape(pt)}\s+(\S+)", str(offer or ""), re.I | re.M
    )
    if om:
        fmtp = om.group(1).strip()
    ending = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(ending)
    out: list[str] = []
    in_audio = False
    maps_added = False
    te_rtpmap = f"a=rtpmap:{pt} telephone-event/8000"
    te_fmtp = f"a=fmtp:{pt} {fmtp}"
    stale_te = (
        {
            m.group(1)
            for m in re.finditer(
                r"^a=rtpmap:(\d+)\s+telephone-event(?:/\d+)?",
                text,
                re.I | re.M,
            )
            if m.group(1) != pt
        }
        if force_offer_pt and offer_pt and existing_pt and existing_pt != offer_pt
        else set()
    )

    for line in lines:
        if line.startswith("m="):
            if in_audio and not maps_added:
                out.append(te_rtpmap)
                out.append(te_fmtp)
                maps_added = True
            in_audio = line.lower().startswith("m=audio ")
            maps_added = False
            if in_audio:
                parts = line.split()
                payloads = [p for p in parts[3:] if p not in stale_te]
                if pt not in payloads:
                    payloads.append(pt)
                line = " ".join([*parts[:3], *payloads])
            out.append(line)
            continue
        if in_audio and stale_te:
            pm = re.match(r"^a=(?:rtpmap|fmtp|rtcp-fb):(\d+)(?:\s|$)", line, re.I)
            if pm and pm.group(1) in stale_te:
                continue
        if in_audio and not line.strip():
            if not maps_added:
                out.append(te_rtpmap)
                out.append(te_fmtp)
                maps_added = True
            out.append(line)
            continue
        out.append(line)
        if (
            in_audio
            and not maps_added
            and line.lower().startswith("a=rtpmap:")
            and "telephone-event" not in line.lower()
        ):
            out.append(te_rtpmap)
            out.append(te_fmtp)
            maps_added = True
    if in_audio and not maps_added:
        out.append(te_rtpmap)
        out.append(te_fmtp)
    joined = ending.join(out)
    if text.endswith("\r\n") and not joined.endswith("\r\n"):
        return joined + "\r\n"
    if text.endswith("\n") and not joined.endswith("\n"):
        return joined + "\n"
    return joined


def _narrow_telephony_audio_sdp(sdp: str) -> str:
    """Keep PCMU/PCMA/telephone-event like Node sipAudioCodecNormalizer (0/8/101)."""
    te_pts = set(_TE_RTPMAP_RE.findall(str(sdp or "")))
    allowed = {"0", "8", "101", "126", "96", *te_pts}
    line_ending = "\r\n" if "\r\n" in sdp else "\n"
    out: list[str] = []
    in_audio = False
    for line in sdp.split(line_ending):
        if line.startswith("m="):
            in_audio = line.startswith("m=audio ")
            if in_audio:
                parts = line.split()
                header = parts[:3]
                payloads = [p for p in parts[3:] if p in allowed]
                # Keep the client's telephone-event PT (iOS uses 126, not 101).
                remapped = list(payloads)
                seen: set[str] = set()
                payloads = []
                for p in remapped:
                    if p in seen:
                        continue
                    seen.add(p)
                    payloads.append(p)
                if not payloads:
                    payloads = ["0", "8"]
                out.append(" ".join([*header, *payloads]))
            else:
                out.append(line)
            continue
        if in_audio and (
            line.startswith("a=rtpmap:")
            or line.startswith("a=fmtp:")
            or line.startswith("a=rtcp-fb:")
        ):
            prefix = (
                "a=rtpmap:"
                if line.startswith("a=rtpmap:")
                else "a=fmtp:"
                if line.startswith("a=fmtp:")
                else "a=rtcp-fb:"
            )
            rest = line[len(prefix) :]
            pt = rest.split()[0].split("/")[0]
            if pt not in allowed:
                continue
            if pt not in {"0", "8", "101", "96"} and pt not in te_pts:
                continue
        out.append(line)
    joined = line_ending.join(out)
    if sdp.endswith("\r\n"):
        joined = joined + "\r\n"
    elif sdp.endswith("\n"):
        joined = joined + "\n"
    return drop_wideband_telephone_event(ensure_telephone_event_sdp(joined, sdp))


# Prod Kamailio→SBC keeps mid/msid/ssrc/extmap-allow-mixed/end-of-candidates.
# It does NOT keep per-line a=extmap:N … (those are WebRTC leftovers).
_PSTN_STRIP_PREFIXES = (
    "a=fingerprint",
    "a=setup",
    "a=ice-",
    "a=candidate",
    "a=sctp-port",
    "a=max-message-size",
    "a=rtcp-rsize",
    "a=rtcp-fb",
    "a=group:BUNDLE",
    "a=extmap:",  # keep a=extmap-allow-mixed (different prefix)
)


def sanitize_pstn_sdp(sdp: str) -> str:
    """PSTN offer: PCMA/PCMU + NG telephone-event PT (do not remap 126→101).

    Rewriting TE after rtpengine.offer makes SBC answer 101 while NG still
    has 126 → WebRTC answer loses TE (`m=audio … 8`).
    """
    text = str(sdp or "")
    line_ending = "\r\n" if "\r\n" in text else "\n"
    text = drop_wideband_telephone_event(text)
    te_pts = [p for p in _TE_RTPMAP_RE.findall(text) if p]
    te_order: list[str] = []
    for pt in te_pts:
        if pt not in te_order:
            te_order.append(pt)
    if not te_order:
        te_order = ["101"]
    keep_pt = {"8", "0", *te_order}
    out: list[str] = []
    in_audio = False
    c_line = ""
    pending_m_head: list[str] = []
    rtpmap_by_pt: dict[str, str] = {}
    rest_audio: list[str] = []
    saw_end_cand = False
    saw_msid_semantic = False

    def _flush_audio_tail() -> None:
        nonlocal c_line, saw_end_cand, pending_m_head
        # Only advertise the audio PTs the engine actually offered. A
        # codec-mask that dropped PCMU must not be put back on the m-line,
        # or the carrier can answer it and the call stays relay-only.
        audio_pts = [pt for pt in ("8", "0") if pt in rtpmap_by_pt]
        if not audio_pts:
            audio_pts = ["8", "0"]
        if pending_m_head:
            out.append(" ".join([*pending_m_head, *audio_pts, *te_order]))
            pending_m_head = []
        if c_line:
            out.append(c_line)
            c_line = ""
        out.append("a=mid:0")
        for pt in ("8", "0"):
            if pt in rtpmap_by_pt:
                out.append(rtpmap_by_pt[pt])
        for pt in te_order:
            if pt in rtpmap_by_pt:
                out.append(rtpmap_by_pt[pt])
            else:
                out.append(f"a=rtpmap:{pt} telephone-event/8000")
                out.append(f"a=fmtp:{pt} 0-16")
        for line in rest_audio:
            if line.strip():
                out.append(line)
        if not saw_end_cand:
            out.append("a=end-of-candidates")
        rtpmap_by_pt.clear()
        rest_audio.clear()
        saw_end_cand = False

    for line in text.split(line_ending):
        if line.startswith("m="):
            if not in_audio and not saw_msid_semantic:
                out.append("a=msid-semantic:WMS *")
                saw_msid_semantic = True
            if in_audio:
                _flush_audio_tail()
            in_audio = line.startswith("m=audio ")
            if not in_audio:
                continue
            parts = line.split()
            if len(parts) >= 3:
                parts[2] = "RTP/AVP"
            pending_m_head = parts[:3]
            continue
        if any(line.startswith(p) for p in _PSTN_STRIP_PREFIXES):
            continue
        # Prod Kamailio→SBC: a=msid-semantic:WMS * (no space, wildcard stream)
        if line.startswith("a=msid-semantic"):
            if not in_audio and not saw_msid_semantic:
                out.append("a=msid-semantic:WMS *")
                saw_msid_semantic = True
            continue
        if in_audio and line.startswith("c="):
            c_line = line
            continue
        if in_audio and line.startswith("a=rtpmap:"):
            pt = line[len("a=rtpmap:") :].split()[0].split("/")[0]
            if pt in keep_pt:
                rtpmap_by_pt[pt] = line
            continue
        if in_audio and (line.startswith("a=fmtp:") or line.startswith("a=rtcp-fb:")):
            prefix = "a=fmtp:" if line.startswith("a=fmtp:") else "a=rtcp-fb:"
            pt = line[len(prefix) :].split()[0].split("/")[0]
            if pt in keep_pt:
                rest_audio.append(line)
            continue
        if in_audio and line.startswith("a=mid:"):
            continue  # forced to mid:0 on flush
        if in_audio and line.startswith("a=end-of-candidates"):
            saw_end_cand = True
            continue  # appended on flush
        if in_audio:
            rest_audio.append(line)
            continue
        out.append(line)
    if in_audio:
        _flush_audio_tail()
    joined = line_ending.join(out)
    if text.endswith("\r\n"):
        return joined if joined.endswith("\r\n") else joined + "\r\n"
    if text.endswith("\n"):
        return joined if joined.endswith("\n") else joined + "\n"
    return joined


def _sip_header_tag(raw: str) -> str:
    m = re.search(r"[;?]tag=([^;>\s]+)", str(raw or ""), flags=re.I)
    return m.group(1).strip() if m else ""


def _angle_uri(header: str) -> str:
    text = str(header or "").strip()
    m = re.search(r"<([^>]+)>", text)
    if m:
        return m.group(1).strip()
    return text.split()[-1].strip() if text else ""


def _header_with_tag(header: str, tag: str) -> str:
    uri = _angle_uri(header)
    if not uri:
        return ""
    text = str(header or "").strip()
    display = text.split("<", 1)[0].strip() if "<" in text else ""
    body = f"{display} <{uri}>".strip() if display else f"<{uri}>"
    tag = str(tag or "").strip()
    if tag:
        body += f";tag={tag}"
    return body


def _remember_inbound_peer(session: dict[str, Any], call: Any) -> None:
    """INVITE Contact is where a later BYE has to go.

    b2bua.terminate sends the BYE back down the accepted connection. The pool
    drops that TLS socket after 30s idle, then the reconnect uses the peer's
    old source port and Cellact never sees the BYE.
    """
    contact = _header_from_obj(call, "Contact") or _header_from_obj(call, "m")
    from_h = _header_from_obj(call, "From") or _header_from_obj(call, "f")
    to_h = _header_from_obj(call, "To") or _header_from_obj(call, "t")
    via = _header_from_obj(call, "Via") or _header_from_obj(call, "v")
    if contact:
        session["inboundPeerContact"] = contact
    if from_h:
        session["inboundFromHdr"] = from_h
    if to_h:
        session["inboundToHdr"] = to_h
    via_u = via.upper()
    if "SIP/2.0/TLS" in via_u:
        session["inboundPeerTransport"] = "tls"
    elif "SIP/2.0/TCP" in via_u:
        session["inboundPeerTransport"] = "tcp"
    elif via:
        session["inboundPeerTransport"] = "udp"


def _inbound_peer_next_hop(session: dict[str, Any]) -> str:
    uri = _angle_uri(str(session.get("inboundPeerContact") or ""))
    m = re.search(r"@([^;>]+)", uri)
    if not m:
        return ""
    hostport = m.group(1).strip()
    transport = str(session.get("inboundPeerTransport") or "").strip().lower()
    if not transport:
        transport = "tls" if hostport.endswith(":5061") else "udp"
    return f"sip:{hostport};transport={transport}"


def _pstn_dialog_session(session: dict[str, Any]) -> dict[str, Any]:
    """IVR transfer hangs up the seat session. Cellact's Contact is on the A-leg."""
    aleg = str(session.get("b2buaCallId") or "").strip()
    if aleg and aleg != str(session.get("sessionId") or ""):
        prod = _get_session(aleg)
        if (
            prod is not None
            and prod is not session
            and prod.get("inboundPeerContact")
            and prod.get("inviteSdp")
        ):
            return prod
    return session


async def _bye_inbound_peer(session: dict[str, Any]) -> None:
    """In-dialog BYE to the INVITE Contact. We are the UAS, so From/To swap."""
    if session.get("inboundByeSent"):
        return
    session = _pstn_dialog_session(session)
    if session.get("inboundByeSent"):
        return
    contact = _angle_uri(str(session.get("inboundPeerContact") or ""))
    from_hdr = str(session.get("inboundFromHdr") or "")
    to_hdr = str(session.get("inboundToHdr") or "")
    their = _header_with_tag(
        from_hdr,
        _sip_header_tag(from_hdr) or str(session.get("fromTag") or ""),
    )
    ours = _header_with_tag(
        to_hdr,
        str(session.get("toTag") or "") or _sip_header_tag(to_hdr),
    )
    call_id = str(session.get("b2buaCallId") or session.get("mediaCallId") or "").strip()
    next_hop = _inbound_peer_next_hop(session)
    if not contact or not their or not ours or not call_id or not next_hop:
        log.warn(
            f"NOTIFY/INBOUND: no Contact BYE session={session.get('sessionId')} "
            f"contact={bool(contact)} call_id={call_id or '-'}"
        )
        return
    session["inboundByeSent"] = True
    cseq = int(session.get("inboundLocalCSeq") or 0) + 1
    session["inboundLocalCSeq"] = cseq
    log.info(
        f"NOTIFY/INBOUND: BYE Contact {contact} via {next_hop} "
        f"call_id={call_id} session={session.get('sessionId')}"
    )
    try:
        await proxy.send_request(
            "BYE",
            contact,
            headers={
                "From": ours,
                "To": their,
                "Call-ID": call_id,
                "CSeq": f"{cseq} BYE",
                "Max-Forwards": "70",
            },
            next_hop=next_hop,
            wait_for_response=False,
        )
    except Exception as exc:  # noqa: BLE001
        session["inboundByeSent"] = False
        log.warn(
            f"NOTIFY/INBOUND: Contact BYE failed session={session.get('sessionId')}: {exc}"
        )


def hairpin_media_answer(call: Any, reply: Any, ingress_id: str = "") -> str:
    """NG answer for hairpin path — must reuse offer-time call-id/from-tag."""
    ingress = str(ingress_id or "").strip()
    keys = _peek_hairpin_ng_keys(ingress) if ingress else {}
    call_id = str(keys.get("call_id") or "").strip()
    from_tag = str(keys.get("from_tag") or "").strip()
    # Fallbacks only if map missing (should not happen on happy path).
    if not call_id:
        call_id = str(
            getattr(call, "call_id", None)
            or _header_from_obj(call, "Call-ID")
            or _header_from_obj(call, "i")
            or ""
        ).strip()
    if not from_tag:
        from_hdr = _header_from_obj(call, "From") or _header_from_obj(call, "f")
        from_tag = _sip_header_tag(from_hdr)
    to_hdr = _header_from_obj(reply, "To") or _header_from_obj(reply, "t")
    to_tag = _sip_header_tag(to_hdr)
    sbc_sdp = normalize_sbc_answer_sdp(
        _body_text(getattr(reply, "body", None) or b"")
    )
    log.info(
        f"SBC_HAIRPIN: NG answer in ingress={ingress or '-'} "
        f"call_id={call_id!r} from_tag={from_tag!r} to_tag={to_tag!r} "
        f"sdp_bytes={len(sbc_sdp)} keys_pinned={bool(keys)} "
        f"media_addr={_rtpengine_media_address()!r}"
    )
    _log_sdp("SBC_HAIRPIN: SBC 200 SDP (normalized → NG answer)", sbc_sdp)
    if not call_id or not from_tag or not to_tag or not sbc_sdp:
        raise RuntimeError(
            f"hairpin NG answer missing fields call_id={call_id!r} "
            f"from_tag={from_tag!r} to_tag={to_tag!r} sdp_len={len(sbc_sdp)}"
        )
    session_id = str(keys.get("session_id") or "").strip()
    session = _get_session(session_id) if session_id else None
    if session is not None:
        session["sbcNgToTag"] = to_tag
    webrtc_sdp = rtpengine_answer(call_id, from_tag, to_tag, sbc_sdp, "pc2_to_sbc")
    webrtc_sdp = ensure_telephone_event_sdp(localize_pc2_answer_sdp(webrtc_sdp))
    log.info(
        f"SBC_HAIRPIN: NG answer ok call_id={call_id} webrtc_bytes={len(webrtc_sdp)}"
    )
    return webrtc_sdp


def hairpin_media_delete(call: Any, ingress_id: str = "") -> None:
    ingress = str(ingress_id or "").strip()
    keys = _pop_hairpin_ng_keys(ingress) if ingress else None
    if keys and keys.get("call_id") and keys.get("from_tag"):
        rtpengine_delete(keys["call_id"], keys["from_tag"])
        return
    call_id = str(
        getattr(call, "call_id", None)
        or _header_from_obj(call, "Call-ID")
        or ""
    ).strip()
    from_hdr = _header_from_obj(call, "From") or _header_from_obj(call, "f")
    from_tag = _sip_header_tag(from_hdr)
    if call_id and from_tag:
        rtpengine_delete(call_id, from_tag)


_HOST_CANDIDATE_RE = re.compile(
    r"a=candidate:\S+ \d+ \S+ \d+ (\d+\.\d+\.\d+\.\d+) (\d+) typ host"
)


def _pin_connection_from_host_candidate(sdp: str) -> str:
    """rtpengine 12.5 + ICE=remove drops candidates and rejects c=0.0.0.0 port 9."""
    text = _body_text(sdp)
    match = _HOST_CANDIDATE_RE.search(text)
    if not match:
        return sdp
    ip, port = match.group(1), match.group(2)
    ending = "\r\n" if "\r\n" in text else "\n"
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    pinned_m = False
    out: list[str] = []
    for line in lines:
        if line == "c=IN IP4 0.0.0.0":
            line = f"c=IN IP4 {ip}"
        elif not pinned_m and line.startswith("m=audio 9 "):
            line = f"m=audio {port} " + line[len("m=audio 9 "):]
            pinned_m = True
        out.append(line)
    pinned = ending.join(out)
    if pinned == text:
        return sdp
    log.info(f"NOTIFY/SBC: pinned connection {ip}:{port} for rtpengine")
    return pinned


def _outgoing_minutes_applies(session: dict[str, Any]) -> bool:
    """Outbound PSTN only. Inbound, internal WebRTC, and OpenAI/IVR do not count."""
    if str(session.get("routeKind") or "") == "inbound":
        return False
    route = session.get("route") if isinstance(session.get("route"), dict) else {}
    product = str(
        session.get("productKind") or route.get("productKind") or ""
    ).strip().lower()
    if product in ("external-sip", "openai", "ivr", "openai-sip"):
        return False
    sip_uri = str(route.get("sipUri") or route.get("uri") or "").lower()
    if "sip.api.openai.com" in sip_uri:
        return False
    kind = str(route.get("route") or session.get("routeKind") or "").strip().lower()
    return kind == "sbc"


def _minutes_body(session: dict[str, Any], event: str, duration_ms: Optional[int] = None) -> dict[str, Any]:
    route = session.get("route") if isinstance(session.get("route"), dict) else {}
    body: dict[str, Any] = {
        "event": event,
        "from": session.get("from"),
        "to": route.get("number") or session.get("to"),
        "sessionId": session.get("sessionId"),
    }
    if duration_ms is not None:
        body["durationMs"] = int(duration_ms)
    return body


def _grok_secret_paths() -> list[str]:
    named = str(os.environ.get("LIGHTPBX_GROK_JSON") or "").strip()
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets", "lightpbx-grok.json")
    return [
        named,
        "/etc/kamailio/sip_code/secrets/lightpbx-grok.json",
        here,
    ]


def _grok_cfg() -> Optional[dict[str, Any]]:
    """Server secret. Missing file or enabled=false means do not post."""
    for path in _grok_secret_paths():
        if not path or not os.path.isfile(path):
            continue
        try:
            raw = json.loads(open(path, encoding="utf-8").read())
        except Exception as exc:  # noqa: BLE001
            log.info(f"GROK: secret unreadable path={path}: {exc}")
            return None
        if not isinstance(raw, dict) or raw.get("enabled") is not True:
            return None
        webhook = str(raw.get("webhook") or "").strip()
        if not webhook.startswith("https://"):
            log.info("GROK: secret has no https webhook")
            return None
        return raw
    return None


def _grok_hash(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return hashlib.sha256(text.encode()).hexdigest()


def _grok_reason(reason: Any) -> str:
    text = str(reason or "unknown").strip().lower()[:64]
    if re.search(r"\d{5,}|@", text):
        return "unspecified"
    cleaned = re.sub(r"[^a-z0-9_.: -]", "", text).strip()
    return cleaned or "unspecified"


def _grok_outcome(session: dict[str, Any], reason: str, reject_code: int) -> str:
    if reason in ("callee-declined", "reject", "rejected") or reject_code in (403, 486, 603):
        return "reject"
    if reason in ("cancelled", "cancel"):
        return "cancel"
    answered = bool(
        session.get("sbcAnswered")
        or session.get("inboundSipAnswered")
        or session.get("minutesAnsweredAt")
        or str(session.get("state") or "") in ("answered", "sbc-answered")
    )
    if reason in ("hangup", "end", "remote-bye") or answered:
        if reason in ("ring-failed", "ring-timeout"):
            return "fail"
        return "hangup"
    return "fail"


def _grok_event(
    session: dict[str, Any],
    reason: Any,
    *,
    ended_leg: str = "",
    client_ended: bool = False,
    reject_code: int = 0,
) -> dict[str, Any]:
    why = _grok_reason(reason)
    answered_at = session.get("minutesAnsweredAt")
    duration_ms = None
    if answered_at:
        duration_ms = max(0, int((time.time() - float(answered_at)) * 1000))
    route = session.get("route") if isinstance(session.get("route"), dict) else {}
    route_kind = str(session.get("routeKind") or route.get("route") or route.get("kind") or "")
    direction = "inbound" if route_kind == "inbound" else "outbound" if route_kind == "sbc" else route_kind or "unknown"
    event: dict[str, Any] = {
        "type": "lightpbx-admin-call",
        "product": "lightpbx",
        "outcome": _grok_outcome(session, why, int(reject_code or 0)),
        "reason": why,
        "direction": direction,
        "routeKind": route_kind or "unknown",
        "answered": bool(answered_at or session.get("sbcAnswered") or session.get("inboundSipAnswered")),
        "durationMs": duration_ms,
        "endedLeg": str(ended_leg or "") or "unknown",
        "clientEnded": bool(client_ended or session.get("clientEnded")),
        "voicemail": bool(session.get("voicemailActive")),
        "isExtension": bool(route.get("isExtension")),
        "from": _grok_hash(session.get("from")),
        "to": _grok_hash(session.get("to")),
        "callerId": _grok_hash(session.get("callerId")),
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if route_kind == "inbound" and reject_code:
        event["rejectCode"] = int(reject_code)
    return event


def _grok_headers(cfg: dict[str, Any]) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "User-Agent": "lightpbx-admin"}
    key = str(cfg.get("key") or "").strip()
    header = str(cfg.get("header") or "").strip()
    if ":" in header:
        name, value = header.split(":", 1)
        name, value = name.strip(), value.strip()
        if name:
            headers[name] = value
    elif header and key:
        headers[header] = key
    if key and "authorization" not in {name.lower() for name in headers}:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _grok_post(cfg: dict[str, Any], event: dict[str, Any]) -> None:
    import urllib.request

    body = json.dumps(event).encode()
    req = urllib.request.Request(
        str(cfg["webhook"]),
        data=body,
        headers=_grok_headers(cfg),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        resp.read(256)


def _schedule_grok_call(
    session: dict[str, Any],
    reason: Any,
    *,
    ended_leg: str = "",
    client_ended: bool = False,
    reject_code: int = 0,
) -> None:
    if _minutes_sp(session) != "lightpbx":
        return
    cfg = _grok_cfg()
    if cfg is None:
        return
    event = _grok_event(
        session,
        reason,
        ended_leg=ended_leg,
        client_ended=client_ended,
        reject_code=reject_code,
    )
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    async def _send() -> None:
        try:
            await asyncio.to_thread(_grok_post, cfg, event)
            log.info(
                f"GROK: posted outcome={event.get('outcome')} "
                f"reason={event.get('reason')} direction={event.get('direction')}"
            )
        except Exception as exc:  # noqa: BLE001
            log.info(f"GROK: post failed outcome={event.get('outcome')}: {exc}")

    loop.create_task(_send())


def _minutes_sp(session: dict[str, Any]) -> str:
    return str(session.get("callerLogicSp") or session.get("logicSp") or "").strip().lower()


async def _gate_outgoing_minutes(session: dict[str, Any]) -> bool:
    """True when the wrapper explicitly says not to send the SBC INVITE."""
    if not _outgoing_minutes_applies(session):
        return False
    sp = _minutes_sp(session)
    data = await logic_client.check_outgoing_minutes(sp, _minutes_body(session, "start"))
    if logic_client.minutes_denied(data):
        log.info(f"MINUTES: deny session={session.get('sessionId')} sp={sp or '-'}")
        return True
    ceiling = logic_client.minutes_remaining_ms(data)
    if ceiling is None:
        log.info(f"MINUTES: no ceiling session={session.get('sessionId')} sp={sp or '-'}")
        return False
    session["minutesStop"] = False
    session.pop("minutesEndSent", None)
    session.pop("minutesTask", None)
    session.pop("minutesAnsweredAt", None)
    session["minutesArmed"] = True
    session["minutesRemainingMs"] = ceiling
    session["minutesWake"] = asyncio.Event()
    log.info(
        f"MINUTES: ceiling {int(ceiling)}ms session={session.get('sessionId')} sp={sp or '-'}"
    )
    return False


def _take_minutes_end(session: dict[str, Any]) -> Optional[int]:
    """Stop the watch. Return talk ms when this call still owes an `end`."""
    session["minutesStop"] = True
    wake = session.get("minutesWake")
    if wake is not None:
        try:
            wake.set()
        except Exception:  # noqa: BLE001
            pass
    task = session.get("minutesTask")
    current = asyncio.current_task()
    if task is not None and task is not current and not task.done():
        try:
            task.cancel()
        except Exception:  # noqa: BLE001
            pass
    if session.get("minutesEndSent") or not session.get("minutesArmed"):
        return None
    session["minutesEndSent"] = True
    answered = session.get("minutesAnsweredAt")
    if not answered:
        return 0
    return max(0, int((time.time() - float(answered)) * 1000))


def _finish_outgoing_minutes(session: dict[str, Any]) -> None:
    duration = _take_minutes_end(session)
    if duration is None:
        return
    asyncio.create_task(_post_minutes_end(session, duration))


async def _close_outgoing_minutes(session: dict[str, Any]) -> None:
    duration = _take_minutes_end(session)
    if duration is None:
        return
    await _post_minutes_end(session, duration)


async def _post_minutes_end(session: dict[str, Any], duration_ms: int) -> None:
    try:
        await logic_client.check_outgoing_minutes(
            _minutes_sp(session),
            _minutes_body(session, "end", duration_ms),
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"MINUTES: end failed session={session.get('sessionId')}: {exc}")


async def _outgoing_minutes_watch(session: dict[str, Any]) -> None:
    sp = _minutes_sp(session)
    try:
        while not session.get("minutesStop"):
            data = await logic_client.check_outgoing_minutes(
                sp, _minutes_body(session, "sync")
            )
            if session.get("minutesStop"):
                return
            if logic_client.minutes_denied(data):
                session["minutesStop"] = True
                log.info(f"MINUTES: exhausted session={session.get('sessionId')} sp={sp or '-'}")
                await fail_notify_call("outgoing minutes exhausted", session=session)
                return
            ceiling = logic_client.minutes_remaining_ms(data)
            if ceiling is None:
                if data.get("event"):
                    return
                ceiling = session.get("minutesRemainingMs")
                if ceiling is None:
                    return
            else:
                session["minutesRemainingMs"] = ceiling
            wait = min(30.0, max(float(ceiling), 0.0) / 1000.0)
            if wait <= 0:
                session["minutesStop"] = True
                await fail_notify_call("outgoing minutes exhausted", session=session)
                return
            wake = session.get("minutesWake")
            if wake is None:
                return
            wake.clear()
            try:
                await asyncio.wait_for(wake.wait(), timeout=wait)
            except asyncio.TimeoutError:
                pass
    except asyncio.CancelledError:
        return
    except Exception as exc:  # noqa: BLE001
        log.warn(f"MINUTES: watch failed session={session.get('sessionId')}: {exc}")


async def _dial_sbc(
    session: dict[str, Any], offer_sdp: str, *, timeout_s: Optional[float] = None
) -> str:
    """Node SipLeg path: PC2 WebRTC SDP → hairpin → SIPhon rtpengine.offer/answer → PC2.

    Matches arnacon-webrtc-service: sip.js puts WebRTC in SIP INVITE; Kamailio/
    rtpengine rewrites in-dialog. We do NOT pre-rewrite via raw NG (that left
    PC2 ICE=completed + connectionState=failed / DTLS dead).

    Client answer is NOT returned here — PC1 held answer is flushed after SBC 200.
    """
    ring_text = _body_text(offer_sdp)
    if _sdp_is_datachannel_only(ring_text) or not _sdp_has_audio(ring_text):
        log.error(
            "NOTIFY/SBC refused: offer is DC-only / no active m=audio "
            "(phase-1 handshake SDP). Wait for DC RING with audio."
        )
        _log_sdp("NOTIFY/SBC rejected client offer SDP", ring_text)
        raise RuntimeError(
            "SBC dial requires audio SDP; got datachannel-only offer"
        )

    session["clientAudioMid"] = _offer_audio_mid(ring_text)
    session["ringOfferSdp"] = ring_text

    # PC2 local offer (codec-narrowed + audio-only). rtpengine must only see
    # 1 m-line (m=audio) so its media[0] matches the SBC's 1-m-line 200 OK.
    pc2_offer = await webrtc_pc.create_pc2_offer(session)
    pc2_audio_mid = _offer_audio_mid(pc2_offer)
    offer_text = _pin_connection_from_host_candidate(
        _audio_only_webrtc_sdp(
            _narrow_telephony_audio_sdp(pc2_offer),
            force_mid=pc2_audio_mid,
        )
    )
    log.info(
        f"NOTIFY/SBC: PC2→SIP (no raw NG) "
        f"pc2_offer_bytes={len(pc2_offer)} hairpin_body_bytes={len(offer_text)} "
        f"client_audio_mid={session.get('clientAudioMid')!r}"
    )
    _log_sdp("NOTIFY/SBC PC2 WebRTC offer SDP (→ hairpin / siphon rtpengine)", offer_text)

    number = session["route"]["number"]
    caller_id = str((session.get("route") or {}).get("callerId") or "").strip()
    from_user = policy.clean_from_user_for_sbc(
        caller_id
        or identity.identity_label(session["from"])
        or logic_client.normalize_phone(session["from"])
    )
    from_host = policy.local_domain()
    sip_uri = str((session.get("route") or {}).get("sipUri") or (session.get("route") or {}).get("uri") or "")
    sbc_host = str(
        session["route"].get("host") or session["route"].get("sbcAddress") or ""
    ).strip()
    if "sip.api.openai.com" in sip_uri.lower():
        parsed = policy.parse_sip_uri(sip_uri)
        proj = str((parsed[0] if parsed else "") or "")
        oai_host = str((parsed[1] if parsed else "") or "sip.api.openai.com").split(";")[0]
        dial = policy.SbcDialPlan(
            number=proj,
            sbc_address=oai_host,
            target_uri=sip_uri,
            next_hop_uri=f"sip:{oai_host}:5061;transport=tls",
            signaling_transport="tls",
            wire_transport="tls",
            via_shim=False,
            provider="openai",
        )
    else:
        try:
            dial = policy.build_sbc_dial_plan(
                number,
                from_user=from_user,
                from_domain=from_host,
                sbc_address=sbc_host or None,
            )
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

    call_id = str(session.get("voicemailMediaCallId") or session["mediaCallId"])
    from_tag = str(session.get("voicemailFromTag") or session["fromTag"])
    session["sbcDial"] = dial.as_dict()
    session["sbc"] = dial.sbc_address
    if session.get("routeKind") != "inbound":
        session["routeKind"] = "sbc"
    session["state"] = "dialing"
    # Critical: leave NG-owned false so SBC_TO runs siphon rtpengine.offer
    # and on_answer runs siphon rtpengine.answer (Kamailio-equivalent).
    if session.get("routeKind") != "inbound":
        session["sbcNgOwned"] = False

    ingress_id = uuid.uuid4().hex
    session["sbcHairpinId"] = ingress_id
    session["sbcFromUser"] = from_user
    session["sbcFromHost"] = from_host
    _bind_session_aliases(session)
    _store_hairpin_ng_keys(
        ingress_id,
        call_id=call_id,
        from_tag=from_tag,
        session_id=_storage_key(session),
    )
    waiter = _register_hairpin_waiter(ingress_id)

    bind_ip = policy.local_bind_ip()
    hairpin_ruri = f"sip:{SBC_HAIRPIN_USER}@{from_host}"
    hairpin_next_hop = f"sip:{bind_ip}:5060;transport=tcp"
    hairpin_to = dial.to_header_uri()
    session["hairpinRuri"] = hairpin_ruri
    session["hairpinNextHop"] = hairpin_next_hop
    session["hairpinToUri"] = hairpin_to
    headers = {
        "From": f"<sip:{from_user}@{from_host}>;tag={from_tag}",
        "To": f"<{hairpin_to}>",
        "Call-ID": call_id,
        "CSeq": "1 INVITE",
        "Contact": f"<sip:{from_user}@{from_host}>",
        "Content-Type": "application/sdp",
        "Max-Forwards": "70",
        "Allow": "INVITE, ACK, CANCEL, BYE, OPTIONS",
        SBC_HAIRPIN_HEADER: ingress_id,
        SBC_HAIRPIN_NUMBER_HEADER: dial.number,
        SBC_HAIRPIN_ADDRESS_HEADER: dial.sbc_address,
        # No SBC_HAIRPIN_NG_HEADER — force siphon in-dialog rtpengine.
    }
    log.info(
        f"NOTIFY/SBC: hairpin {hairpin_ruri} via {hairpin_next_hop} → "
        f"{dial.target_uri} next_hop={dial.next_hop_uri} shim={dial.via_shim} "
        f"ingress={ingress_id} call_id={call_id} media=siphon-rtpengine"
    )
    if await _gate_outgoing_minutes(session):
        await fail_notify_call("outgoing minutes exhausted", session=session)
        raise RuntimeError("outgoing minutes exhausted")
    await proxy.send_request(
        "INVITE",
        hairpin_ruri,
        headers=headers,
        body=offer_text,
        next_hop=hairpin_next_hop,
        wait_for_response=False,
    )

    if timeout_s is None:
        timeout_s = SBC_INVITE_TIMEOUT_MS / 1000.0
    timeout_s = max(float(timeout_s), 1.0)
    try:
        answer_sdp = await asyncio.wait_for(waiter, timeout=timeout_s)
    except asyncio.TimeoutError as exc:
        _pop_hairpin_waiter(ingress_id)
        raise RuntimeError("SBC INVITE timed out waiting for B2BUA answer") from exc
    except Exception:
        if not waiter.done():
            _pop_hairpin_waiter(ingress_id)
        raise

    # Siphon rtpengine.answer WebRTC SDP → PC2 (Node: SDH remote description).
    _log_sdp("NOTIFY/SBC PC2 answer SDP (siphon rtpengine ← hairpin)", answer_sdp)
    await webrtc_pc.apply_pc2_remote_answer(session, answer_sdp)
    session["state"] = "sbc-answered"
    session["sbcAnswered"] = True  # hangup → BYE, not CANCEL
    session["sbcHairpinAnswered"] = True
    if session.get("minutesArmed") and not session.get("minutesTask"):
        session["minutesAnsweredAt"] = time.time()
        session["minutesTask"] = asyncio.create_task(_outgoing_minutes_watch(session))
    return answer_sdp


async def dial_sbc_for_callee_callback(
    session: dict[str, Any], offer_sdp: str, *, timeout_s: Optional[float] = None
) -> str:
    """Callee RING after inbound BYE: INVITE the original PSTN caller via SBC.

    Phone DC is still up. rtpengine/pc1 is gone — SIP has no muted DC to unmute.
    """
    inbound = session.get("inboundCall") if isinstance(session.get("inboundCall"), dict) else {}
    pstn = str(inbound.get("fromNumber") or session.get("from") or "").strip()
    did = str(inbound.get("toNumber") or "").strip()
    from_id = did or str(session.get("to") or "")
    if not pstn:
        raise RuntimeError("callee SIP callback missing PSTN dest")
    parsed_to = logic_client.parse_address(pstn)
    parsed_from = logic_client.parse_address(from_id)
    decision = await logic_client.resolve_destination(
        parsed_to,
        parsed_from,
        origin="client",
        to=pstn,
        from_id=from_id,
        session_id=str(session.get("sessionId") or ""),
        kind="outbound",
        logic_sp=str(session.get("logicSp") or ""),
    )
    number = logic_client.normalize_phone(pstn)
    caller_id = "".join(ch for ch in did if ch.isdigit())
    host = str(decision.get("host") or decision.get("sbcAddress") or "").strip()
    if str(decision.get("route") or "").strip().lower() != "sbc" or not host:
        host = str(
            policy.determine_sbc_for_number(number, from_id, policy.local_domain()) or ""
        ).strip()
        if not host:
            raise RuntimeError(f"callee SIP callback: no SBC for {number}")
        decision = {
            "route": "sbc",
            "number": number,
            "host": host,
            "sbcAddress": host,
            "callerId": caller_id or decision.get("callerId"),
            "logicSp": session.get("logicSp") or decision.get("logicSp"),
        }
    else:
        decision = dict(decision)
        decision["number"] = str(decision.get("number") or number)
        if caller_id and not decision.get("callerId"):
            decision["callerId"] = caller_id
    session["route"] = decision
    session["sipCall"] = None
    session["inboundSipAnswered"] = False
    session["mediaCallId"] = f"{uuid.uuid4().hex}@{policy.local_domain()}"
    session["fromTag"] = uuid.uuid4().hex[:8]
    session["toTag"] = uuid.uuid4().hex[:8]
    session["sbcNgOwned"] = False
    session["sbcAnswered"] = False
    session["sbcHairpinId"] = None
    log.info(
        f"NOTIFY/SBC: callee callback INVITE pstn={decision.get('number')!r} "
        f"cli={decision.get('callerId') or from_id!r} host={decision.get('host')!r} "
        f"session={session.get('sessionId')}"
    )
    return await _dial_sbc(session, offer_sdp, timeout_s=timeout_s)


def _webrtc_ring_targets(route: dict[str, Any], fallback_to: str) -> list[dict[str, Any]]:
    raw = route.get("targets") if str(route.get("route") or "") == "webrtc-multiring" else None
    targets: list[dict[str, Any]] = []
    for item in raw or []:
        if isinstance(item, dict):
            ident = str(item.get("notifyIdentity") or item.get("ensName") or item.get("number") or "")
            if ident:
                row = {
                    "notifyIdentity": ident,
                    "ensName": str(item.get("ensName") or ident),
                    "wallet": item.get("wallet"),
                }
                row.update(logic_client._extension_fields(item))
                targets.append(row)
        elif item:
            ident = str(item)
            targets.append({"notifyIdentity": ident, "ensName": ident, "wallet": None})
    if not targets:
        ident = str(route.get("notifyIdentity") or route.get("ensName") or fallback_to)
        row = {
            "notifyIdentity": ident,
            "ensName": str(route.get("ensName") or ident),
            "wallet": route.get("wallet"),
        }
        row.update(logic_client._extension_fields(route))
        targets.append(row)
    return targets


def _wake_hunt_waiters(session_ids: list[str]) -> None:
    for sid in session_ids:
        sess = _get_session(sid)
        if not sess:
            continue
        ev = sess.get("huntResumeEvent")
        if ev is None:
            continue
        loop = sess.get("eventLoop")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if (
            isinstance(loop, asyncio.AbstractEventLoop)
            and running is not None
            and loop is not running
        ):
            loop.call_soon_threadsafe(ev.set)
        else:
            try:
                ev.set()
            except Exception:  # noqa: BLE001
                pass


def _hunt_end_session(session: dict[str, Any]) -> None:
    wake = extension_hunt.policy.end_session(session, _sessions)
    if wake:
        _wake_hunt_waiters(wake)


def _pair_session_id(*parts: Any, fallback: str = "") -> str:
    labels = [str(x) for x in parts if x]
    return "|".join(sorted(labels)) if labels else fallback


def _ring_leg_for(
    session: dict[str, Any], from_id: str = "", session_id: str = "", to_id: str = ""
) -> Any:
    legs = session.get("ringLegs") or {}
    by_sid = session.get("ringLegsBySid") or {}
    sid = str(session_id or "")
    if sid and sid in by_sid:
        return by_sid[sid]
    for raw in (from_id, to_id):
        if raw and raw in legs:
            return legs[raw]
        label = identity.identity_label(raw)
        if not label:
            continue
        for ident, leg in legs.items():
            if ident == raw or identity.identity_label(ident) == label:
                return leg
    return None


async def _push_dc_invite(
    session: dict[str, Any],
    invite: dict[str, Any],
    target: dict[str, Any],
    *,
    caller_id: str = "",
) -> None:
    notify_identity = target.get("notifyIdentity") or target.get("ensName") or session["to"]
    cli_raw = (session.get("route") or {}).get("callerId") or session.get("callerId") or ""
    cli = identity.callkit_handle(cli_raw)
    cli_label = identity.identity_label(cli_raw)
    caller_label = identity.identity_label(
        caller_id or cli_label or session.get("from") or ""
    )
    callee_label = identity.identity_label(notify_identity)
    signaling_session_id = _pair_session_id(
        callee_label, caller_label, fallback=str(session["sessionId"])
    )
    caller_handle = cli or identity.callkit_handle(caller_label)
    push_body: dict[str, Any] = {
        "type": "offer",
        "from": caller_handle,
        "to": notify_identity,
        "sessionId": signaling_session_id,
        "sdp": invite["sdp"],
        "candidates": invite.get("candidates") or [],
        "isCall": True,
        "callNonce": session.get("callNonce"),
        "label": caller_handle or None,
        "callerName": caller_handle or None,
        "multiring": bool(len(session.get("ringTargets") or []) > 1),
    }
    if session.get("xdata"):
        push_body["xdata"] = session["xdata"]
    if session.get("xsign"):
        push_body["xsign"] = session["xsign"]
    payload = json.dumps({k: v for k, v in push_body.items() if v is not None})
    log.info(
        f"NOTIFY/WEBRTC: DC-only push caller={caller_handle} callee={notify_identity} "
        f"session={signaling_session_id} sdp_bytes={len(invite['sdp'])} "
        f"candidates={len(invite.get('candidates') or [])}"
    )
    result = await notify_push.send_notification(
        caller_label or session.get("from") or "",
        notify_identity,
        payload,
        notify_push.NOTI_TYPE_CALL,
        {
            "targetWallet": target.get("wallet"),
            "web2identity": identity.derive_web2_identity(notify_identity),
            "sessionId": signaling_session_id,
            "logicSp": str((session.get("route") or {}).get("logicSp") or ""),
        },
    )


def _dc_ring_watch_key(ident: str) -> str:
    return identity.identity_label(ident) or str(ident or "")


def note_dc_peer_alive(session: dict[str, Any], ident: str) -> None:
    """Any message from this peer is a reply. Do not HTTP-invite them."""
    key = _dc_ring_watch_key(ident)
    if not key or not isinstance(session, dict):
        return
    watch = (session.get("dcRingWatch") or {}).get(key)
    if isinstance(watch, dict):
        watch["replied"] = True
    for leg in (session.get("ringLegs") or {}).values():
        if _dc_ring_watch_key(getattr(leg, "ident", "") or "") == key:
            leg.dc_seen = True


def note_dc_ring_sent(
    session: dict[str, Any],
    ident: str,
    invite: dict[str, Any],
    *,
    wallet: Any = None,
    invert_caller: bool = False,
) -> None:
    """Arm 8s silence → HTTP invite. Any reply from this peer cancels it."""
    key = _dc_ring_watch_key(ident)
    if not key or not isinstance(session, dict):
        return
    sdp = str((invite or {}).get("sdp") or "")
    if not sdp.strip():
        return
    watches = session.setdefault("dcRingWatch", {})
    watches[key] = {
        "ident": ident,
        "sent_at": time.monotonic(),
        "invite": {
            "sdp": sdp,
            "candidates": list((invite or {}).get("candidates") or []),
        },
        "wallet": wallet,
        "replied": False,
        "http_pushed": False,
        "invert_caller": bool(invert_caller),
    }
    task = session.get("dcRingWatchTask")
    if task is not None and not getattr(task, "done", lambda: True)():
        return
    try:
        session["dcRingWatchTask"] = _start_task_on_session_loop(
            session, _watch_dc_ring_silence(session)
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/WEBRTC: DC RING silence watch start failed "
            f"session={session.get('sessionId')}: {exc}"
        )


async def _watch_dc_ring_silence(session: dict[str, Any]) -> None:
    wait = float(DC_RING_SILENCE_HTTP_SECS)
    try:
        while True:
            if session.get("clientEnded") or session.get("callerCancelForwarded") or session.get("multiringWinner"):
                return
            watches = session.get("dcRingWatch") or {}
            if not watches:
                return
            pending = False
            due: list[str] = []
            now = time.monotonic()
            for key, watch in list(watches.items()):
                if not isinstance(watch, dict):
                    continue
                if watch.get("replied") or watch.get("http_pushed"):
                    continue
                t0 = watch.get("sent_at")
                if t0 is None:
                    pending = True
                    continue
                if now - float(t0) < wait:
                    pending = True
                    continue
                due.append(key)
            for key in due:
                await _http_invite_silent_ring(session, key)
            if not due and not pending:
                return
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        return


async def _http_invite_silent_ring(session: dict[str, Any], key: str) -> None:
    watch = (session.get("dcRingWatch") or {}).get(key)
    if not isinstance(watch, dict) or watch.get("http_pushed") or watch.get("replied"):
        return
    if session.get("clientEnded") or session.get("callerCancelForwarded") or session.get("multiringWinner"):
        return
    watch["http_pushed"] = True
    ident = str(watch.get("ident") or key)
    legs = session.get("ringLegs") or {}
    leg = legs.get(ident) or next(
        (
            item
            for item_ident, item in legs.items()
            if _dc_ring_watch_key(item_ident) == key
        ),
        None,
    )
    if leg is not None and not getattr(leg, "promoted", False):
        await _swap_silent_leg_to_http_invite(session, leg)
        return
    _set_call_nonce(session)
    invite = watch.get("invite") or {}
    caller_id = str(session.get("to") or "") if watch.get("invert_caller") else ""
    target = next(
        (
            t
            for t in (session.get("ringTargets") or [])
            if _dc_ring_watch_key(t.get("notifyIdentity") or "") == key
        ),
        {"notifyIdentity": ident, "wallet": watch.get("wallet")},
    )
    try:
        await _push_dc_invite(session, invite, target, caller_id=caller_id)
        if leg is not None:
            leg.invite_pushed = True
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/WEBRTC: DC RING silence HTTP push failed ident={ident!r}: {exc}"
        )
        return
    log.info(
        f"NOTIFY/WEBRTC: DC RING silent {DC_RING_SILENCE_HTTP_SECS:.0f}s "
        f"→ HTTP invite ident={ident!r} session={session.get('sessionId')}"
    )


async def _swap_silent_leg_to_http_invite(session: dict[str, Any], old: Any) -> None:
    ident = str(getattr(old, "ident", "") or "")
    if not ident or old.promoted or getattr(old, "_http_fallback_done", False):
        return
    if session.get("clientEnded") or session.get("callerCancelForwarded"):
        return
    old._http_fallback_done = True
    _set_call_nonce(session)
    caller_label = identity.identity_label(session.get("from") or "")
    legs = session.setdefault("ringLegs", {})
    by_sid = session.setdefault("ringLegsBySid", {})
    sid = _pair_session_id(
        caller_label,
        identity.identity_label(ident),
        fallback=str(session.get("sessionId") or ""),
    )
    push_sid = _pair_session_id(
        identity.identity_label(ident),
        caller_label,
        fallback=sid,
    )
    leg = webrtc_pc.RingLeg(
        session,
        ident=ident,
        wallet=old.wallet,
        signaling_session_id=push_sid,
    )
    legs[ident] = leg
    by_sid[sid] = leg
    by_sid[push_sid] = leg
    _bind_session_aliases(session)
    old.cancelled = True
    task = getattr(old, "drive_task", None)
    if task is not None and not task.done():
        task.cancel()
    try:
        await old.close(force=True)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/WEBRTC: silent-DC close before HTTP invite {ident!r}: {exc}")
    try:
        await leg.create_offer()
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/WEBRTC: silent-DC HTTP offer failed callee={ident!r}: {exc}"
        )
        return
    target = next(
        (
            t
            for t in (session.get("ringTargets") or [])
            if t.get("notifyIdentity") == ident
        ),
        {"notifyIdentity": ident, "wallet": old.wallet},
    )
    _log_sdp(
        f"NOTIFY/WEBRTC invite SDP out ({ident})",
        (leg.invite or {}).get("sdp", ""),
    )
    try:
        await _push_dc_invite(session, leg.invite or {}, target)
        leg.invite_pushed = True
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/WEBRTC: silent-DC HTTP push failed callee={ident!r}: {exc}"
        )
        return
    log.info(
        f"NOTIFY/WEBRTC: DC RING silent {DC_RING_SILENCE_HTTP_SECS:.0f}s "
        f"→ HTTP invite ident={ident!r} session={session.get('sessionId')}"
    )


async def _cancel_multiring_losers(
    session: dict[str, Any], winner: str, *, reason: str = "answered-elsewhere"
) -> None:
    winner = str(winner or "")
    reason = str(reason or "answered-elsewhere")
    if not winner or reason != "answered-elsewhere":
        log.info(
            f"NOTIFY/WEBRTC: skip cancel losers winner={winner!r} reason={reason} "
            f"session={session.get('sessionId')} (unreachable ≠ loser)"
        )
        return
    if session.get("ringCancelSent"):
        return
    session["ringCancelSent"] = True
    caller_label = identity.identity_label(session.get("from") or "")
    nonce = session.get("callNonce")
    legs = session.get("ringLegs") or {}
    reason = str(reason or "answered-elsewhere")
    # Timeout/decline is not "someone else picked up". Don't stamp isCall+answered-elsewhere
    # — that re-wakes Android through the CALL FCM path after the only seat already missed.
    answered_elsewhere = reason == "answered-elsewhere" and bool(winner)

    async def _push_and_close(
        ident: str,
        sid: str,
        target: Optional[dict[str, Any]],
        leg: Any,
        sent: bool,
    ) -> None:
        payload = json.dumps(
            {
                "type": "cancel",
                "from": caller_label,
                "to": ident,
                "sessionId": sid,
                "callNonce": nonce,
                "isCall": False,
                "reason": reason,
            }
        )
        try:
            wallet = (target or {}).get("wallet") if target else None
            if wallet is None and leg is not None:
                wallet = leg.wallet
            await notify_push.send_notification(
                caller_label or session.get("from") or "",
                ident,
                payload,
                notify_push.NOTI_TYPE_REALTIME,
                {
                    "targetWallet": wallet,
                    "web2identity": identity.derive_web2_identity(ident),
                    "sessionId": sid,
                    "logicSp": str((session.get("route") or {}).get("logicSp") or ""),
                },
            )
            log.info(
                f"NOTIFY/WEBRTC: cancel {ident!r} via push session={sid} "
                f"reason={reason} nonce={nonce!r} dcHangup={sent}"
            )
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/WEBRTC: cancel {ident!r} failed: {exc}")
        # Push is the backup for a phone that never connects. A leg that
        # already has an invite must stay up: the late HTTP answer finishes
        # the DC and drive dumps call/end there. Closing here is what left
        # CallKit ringing until this slow plan returned.
        if leg is None:
            return
        if not getattr(leg, "callerEndDumped", False):
            log.info(
                f"NOTIFY/WEBRTC: cancel {ident!r} keep PC for DC end "
                f"session={sid} reason={reason}"
            )
            return
        try:
            await asyncio.sleep(0.4)
        except Exception:  # noqa: BLE001
            pass
        await leg.close()

    async def _cancel_one(ident: str, target: Optional[dict[str, Any]] = None) -> None:
        if not ident:
            return
        if answered_elsewhere and ident == winner:
            return
        sid = _pair_session_id(
            caller_label,
            identity.identity_label(ident),
            fallback=str(session.get("sessionId") or ""),
        )
        leg = legs.get(ident)
        sent = False
        if leg is not None:
            sent = await leg.send_cancel(reason)
            if sent:
                log.info(
                    f"NOTIFY/WEBRTC: hangup {ident!r} via DC session={sid} "
                    f"reason={reason}"
                )
        _schedule_coro(_push_and_close(ident, sid, target, leg, sent))

    tasks = []
    seen: set[str] = set()
    for ident in list(legs.keys()):
        seen.add(ident)
        tasks.append(_cancel_one(ident))
    for target in session.get("ringTargets") or []:
        ident = str(target.get("notifyIdentity") or "")
        if ident and ident not in seen:
            tasks.append(_cancel_one(ident, target))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    winner = str(winner or "")
    wake: list[str] = []
    for ident in list(legs.keys()):
        if winner and ident == winner:
            continue
        wake.extend(
            extension_hunt.policy.release_seat(session, ident, _sessions)
        )
    for target in session.get("ringTargets") or []:
        ident = str(target.get("notifyIdentity") or "")
        if ident and ident != winner:
            wake.extend(
                extension_hunt.policy.release_seat(session, ident, _sessions)
            )
    if wake:
        _wake_hunt_waiters(list(dict.fromkeys(wake)))


async def _forward_cancel_to_ringing(
    session: dict[str, Any], *, reason: str = "cancelled"
) -> None:
    """Caller hung up while seats were still ringing.

    DC open → ``call/end`` + ``signaling/end-call`` on that channel.
    Invite already out but DC not up yet → keep the PC. The HTTP answer
    still completes the handshake and ``RingLeg.drive`` dumps the end there.
    Never a second CALL notify-plan: that APNS is a new CallKit call.
    """
    if session.get("callerCancelForwarded"):
        return
    session["callerCancelForwarded"] = True
    session["cancelledPc1RingId"] = session.get("activePc1RingId")
    session["ringGeneration"] = int(session.get("ringGeneration") or 0) + 1
    pickup = session.get("pickupEvent")
    if pickup is not None:
        try:
            pickup.set()
        except Exception:  # noqa: BLE001
            pass
    reason = str(reason or "cancelled")
    legs = session.get("ringLegs") or {}

    async def _cancel_one(ident: str, target: Optional[dict[str, Any]] = None) -> None:
        if not ident:
            return
        leg = legs.get(ident)
        if leg is None:
            label = identity.identity_label(ident)
            for key, candidate in legs.items():
                if key == ident or identity.identity_label(key) == label:
                    leg = candidate
                    break
        if ident and ident == str(session.get("multiringWinner") or ""):
            return
        if leg is not None and getattr(leg, "promoted", False):
            return
        if leg is not None and getattr(leg, "cancelled", False):
            return
        sent_dc = False
        if leg is not None:
            try:
                sent_dc = bool(await leg.send_cancel(reason))
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY/WEBRTC: caller-cancel DC {ident!r} failed: {exc}"
                )
        if sent_dc:
            log.info(
                f"NOTIFY/WEBRTC: caller-cancel {ident!r} via DC "
                f"session={session.get('sessionId')} reason={reason}"
            )
            return
        if leg is not None:
            log.info(
                f"NOTIFY/WEBRTC: caller-cancel {ident!r} deferred to DC "
                f"session={session.get('sessionId')} reason={reason}"
            )
            return
        log.info(
            f"NOTIFY/WEBRTC: caller-cancel {ident!r} no PC, skip push "
            f"session={session.get('sessionId')} reason={reason}"
        )

    tasks = []
    seen: set[str] = set()
    for ident in list(legs.keys()):
        seen.add(ident)
        tasks.append(_cancel_one(ident))
    for target in session.get("ringTargets") or []:
        ident = str(target.get("notifyIdentity") or "")
        if ident and ident not in seen:
            tasks.append(_cancel_one(ident, target))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    log.info(
        f"NOTIFY/WEBRTC: caller-cancel done session={session.get('sessionId')} "
        f"seats={len(seen)} gen={session.get('ringGeneration')}"
    )


async def _wait_cancelled_callee_dc_end(
    session: dict[str, Any], *, timeout_s: float = 25.0
) -> None:
    """Invite already left: keep PCs until DC opens, then dump end-call."""
    if session.get("cancelDcWaitDone"):
        return
    if not session.get("clientEnded") and not session.get("callerCancelForwarded"):
        return
    legs = [
        leg
        for leg in (session.get("ringLegs") or {}).values()
        if leg is not None and not getattr(leg, "promoted", False)
    ]
    if not legs:
        session["cancelDcWaitDone"] = True
        return
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.5, float(timeout_s))
    while loop.time() < deadline:
        pending = []
        for leg in legs:
            ident = str(getattr(leg, "ident", "") or "")
            by_id = session.get("dcByIdentity") or {}
            dc = by_id.get(ident) if ident else None
            if dc is None:
                dc = getattr(leg, "dc", None)
            open_dc = str(getattr(dc, "readyState", "") or "").lower() == "open"
            if open_dc and not getattr(leg, "callerEndDumped", False):
                try:
                    dumped = bool(await leg.send_cancel("cancelled"))
                except Exception as exc:  # noqa: BLE001
                    log.warn(
                        f"NOTIFY/WEBRTC: late DC end {ident!r} failed: {exc}"
                    )
                    dumped = False
                if dumped:
                    leg.callerEndDumped = True
                    log.info(
                        f"NOTIFY/WEBRTC: caller-cancel {ident!r} via DC (late open) "
                        f"session={session.get('sessionId')}"
                    )
            task = getattr(leg, "drive_task", None)
            still = bool(
                not getattr(leg, "declined", False)
                and not getattr(leg, "callerEndDumped", False)
                and (
                    getattr(leg, "invite_pushed", False)
                    or getattr(leg, "invite", None)
                    or (task is not None and not task.done())
                    or getattr(leg, "dc_reusable", lambda: False)()
                )
            )
            if still:
                pending.append(leg)
        if not pending:
            session["cancelDcWaitDone"] = True
            return
        await asyncio.sleep(0.12)
    session["cancelDcWaitDone"] = True


def _release_declined_ring_seat(session: dict[str, Any], ident: str) -> None:
    wake = extension_hunt.policy.release_seat(session, ident, _sessions)
    if wake:
        _wake_hunt_waiters(wake)


def _on_ring_winner(session: dict[str, Any], ident: str) -> None:
    extension_hunt.policy.mark_in_call(session, ident)


async def _prepare_inbound_sbc_leg(
    session: dict[str, Any],
    *,
    webrtc_offer: str,
    call_id: str,
    from_tag: str,
    to_tag: str,
    ng_profile: str,
    sbc_sdp: str = "",
) -> str:
    """Siphon offers WebRTC; rtpengine DTLS-active answers. Same polarity as hairpin pc2.

    sbc_to_webrtc (rtpengine offers, siphon answers as DTLS client) ICE-completes
    and leaves DTLS connecting forever — see pc2_to_sbc profile comment.
    """
    del webrtc_offer  # leftover from siphon-as-answerer path
    sbc = str(sbc_sdp or session.get("inboundSbcInviteSdp") or "")
    if not sbc.strip():
        raise RuntimeError("inbound SBC INVITE SDP missing for pc1 offer")
    if not to_tag:
        to_tag = _uas_local_tag(session.get("sipCall")) or str(session.get("toTag") or "")
        session["toTag"] = to_tag
    pc1_offer = await webrtc_pc.create_pc1_offer(session)
    pc1_audio_mid = _offer_audio_mid(pc1_offer)
    pc1_offer = _pin_connection_from_host_candidate(
        _audio_only_webrtc_sdp(
            _narrow_telephony_audio_sdp(pc1_offer),
            force_mid=pc1_audio_mid,
        )
    )
    if telephone_event_pt(sbc):
        pc1_offer = ensure_telephone_event_sdp(pc1_offer, sbc, force_offer_pt=True)
    # siphon is NG offerer → from-tag = UAS to-tag. SBC INVITE SDP is the NG answer.
    aleg = str(session.get("b2buaCallId") or "").strip()
    is_xfer_chain = bool(session.get("xferPark") and aleg and aleg != call_id)
    offer_profile = "pc2_to_sbc_local" if is_xfer_chain else "pc2_to_sbc"
    plain = rtpengine_offer(call_id, to_tag, pc1_offer, offer_profile)
    plain_raw = _body_text(plain)
    plain = strip_webrtc_attrs_for_sbc_uas(plain_raw) or plain_raw
    plain = fit_plain_sdp_to_sbc_offer(plain, sbc) or plain
    if telephone_event_pt(sbc):
        plain = ensure_telephone_event_sdp(plain, sbc, force_offer_pt=True)
    sbc_for_xfer = sbc
    if is_xfer_chain:
        # The Call-ID index now points at this park session, whose fromTag
        # is the park INVITE (sb-…). rtpengine.offer on the PSTN call used
        # the original A-leg From tag, saved before that steal.
        fallback_tag = str(session.get("alegFromTag") or "").strip()
        fallback_to_tag = str(session.get("alegToTag") or "").strip()
        if not fallback_tag or not fallback_to_tag:
            prod_sess = get_session_by_sip_call_id(aleg)
            if prod_sess is not session:
                if not fallback_tag:
                    fallback_tag = str((prod_sess or {}).get("fromTag") or "").strip()
                if not fallback_to_tag:
                    fallback_to_tag = str(
                        (prod_sess or {}).get("blegRemoteTag")
                        or (prod_sess or {}).get("bLegRemoteTag")
                        or ""
                    ).strip()
        if not fallback_tag:
            log.warn(
                f"NOTIFY/INBOUND: xfer_park a_leg={aleg} has no rtpengine "
                f"from-tag (park tag {from_tag!r} is not that dialog)"
            )
        aleg_from_tag, aleg_to_tag = _rtpengine_aleg_tags(
            aleg, fallback_tag, fallback_to_tag
        )
        if aleg_from_tag:
            session["alegFromTag"] = aleg_from_tag
            if aleg_to_tag:
                session["alegToTag"] = aleg_to_tag
            try:
                if not aleg_to_tag:
                    raise RuntimeError(
                        f"xfer_park a_leg={aleg} from-tag={aleg_from_tag!r} "
                        f"has no B-leg to-tag (refusing park to-tag {to_tag!r})"
                    )
                # No offer. Offer deletes this call-id and Cellact is left
                # on a port nothing listens on. Answer keeps the near port
                # and points the far side at the park call's plain socket.
                aleg_b_sdp = _aleg_far_loopback_sdp(aleg, aleg_from_tag, sbc)
                if telephone_event_pt(sbc):
                    aleg_b_sdp = ensure_telephone_event_sdp(
                        aleg_b_sdp, sbc, force_offer_pt=True
                    )
                _log_sdp(
                    "NOTIFY/INBOUND a_leg far socket (xfer, existing port)",
                    aleg_b_sdp,
                )
                sbc_for_xfer = aleg_b_sdp
                kept = rtpengine_answer(
                    aleg,
                    aleg_from_tag,
                    aleg_to_tag,
                    plain,
                    "sbc_to_sbc_xfer",
                )
                kept_port = ""
                kept_match = re.search(
                    r"^m=audio\s+(\d+)", _body_text(kept) or "", re.M
                )
                if kept_match:
                    kept_port = kept_match.group(1)
                log.info(
                    f"NOTIFY/INBOUND: xfer_park retarget a_leg={aleg} "
                    f"(from_tag={aleg_from_tag!r} to_tag={aleg_to_tag!r}) "
                    f"<-> xfer={call_id} far_bytes={len(aleg_b_sdp)} "
                    f"plain_bytes={len(plain)} near_port={kept_port or '-'} "
                    f"(not sent; Cellact already has it)"
                )
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY/INBOUND: xfer_park a_leg={aleg} chain failed: {exc}"
                )
        park_cid = str(session.get("parkCallId") or "").strip()
        if park_cid and park_cid not in (call_id, aleg):
            rtpengine_delete(park_cid, "")
    webrtc_answer = rtpengine_answer(
        call_id, to_tag, from_tag, sbc_for_xfer, offer_profile
    )
    webrtc_answer = ensure_telephone_event_sdp(webrtc_answer, pc1_offer)
    _log_sdp("NOTIFY/INBOUND rtpengine WebRTC answer (siphon-offerer)", webrtc_answer)
    await webrtc_pc.apply_pc1_remote_answer(session, webrtc_answer)
    session["inboundSbcInviteSdp"] = sbc
    session["inboundNgCallId"] = call_id
    session["inboundNgFromTag"] = to_tag
    session["inboundNgProfile"] = offer_profile
    session["inboundPlainSdp"] = plain
    session["pc1AnswerSdp"] = webrtc_answer
    session["sbcNgAnswered"] = True
    session["pc1Connected"] = False
    log.info(
        f"NOTIFY/INBOUND: SBC leg NG as siphon-offerer session={session.get('sessionId')} "
        f"pc1_offer_bytes={len(pc1_offer or '')} answer_bytes={len(webrtc_answer or '')} "
        f"plain_bytes={len(plain)} profile={offer_profile}"
    )
    _start_task_on_session_loop(session, _watch_inbound_sbc_leg(session))
    return plain


async def _watch_inbound_sbc_leg(session: dict[str, Any]) -> None:
    try:
        ok = await webrtc_pc.wait_pc1_connected(session, timeout_s=20.0)
        if ok:
            await webrtc_pc.rebridge_media(session)
        else:
            log.warn(
                f"NOTIFY/INBOUND: SBC leg DTLS not up yet session={session.get('sessionId')} "
                f"(join waits for pc1 connected event)"
            )
    except asyncio.TimeoutError:
        log.warn(
            f"NOTIFY/INBOUND: SBC leg wait RPC timeout session={session.get('sessionId')} "
            f"(join still waits for pc1 connected)"
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/INBOUND: SBC leg watch failed: {exc} "
            f"session={session.get('sessionId')} (join still waits for pc1 connected)"
        )


def _ring_timeout_secs(session: dict[str, Any]) -> float:
    route = session.get("route") or {}
    raw = route.get("ringTimeoutSeconds")
    if raw is not None:
        try:
            val = float(raw)
            if val > 0:
                return max(10.0, min(60.0, val))
        except (TypeError, ValueError):
            pass
    return float(WEBRTC_WAIT_SECS)


def _remaining_ring_timeout_secs(session: dict[str, Any]) -> float:
    total = _ring_timeout_secs(session)
    started = session.get("ringStartedAt")
    if isinstance(started, (int, float)) and started > 0:
        elapsed = max(0.0, time.monotonic() - float(started))
        return max(1.0, total - elapsed)
    return total


# Host engine (User=siphon-rtp, ProtectSystem=strict) can read this and can
# only create files under its StateDirectory. The container bind-mounts both.
VOICEMAIL_DIR = "/var/lib/siphon-voicemail"
VOICEMAIL_PCAP_DIR = "/var/lib/siphon-rtp"
VOICEMAIL_RECORD_SECS = 300.0


def _alaw_to_s16(byte: int) -> int:
    """ITU-T G.711 A-law. The carrier offers payload 8."""
    value = byte ^ 0x55
    sign = value & 0x80
    exponent = (value & 0x70) >> 4
    sample = ((value & 0x0F) << 4) + 8
    if exponent:
        sample += 0x100
        sample <<= exponent - 1
    if not sign:
        sample = -sample
    if sample > 32767:
        return 32767
    if sample < -32768:
        return -32768
    return sample


def _ulaw_to_s16(byte: int) -> int:
    value = (~byte) & 0xFF
    sign = value & 0x80
    exponent = (value >> 4) & 0x07
    mantissa = value & 0x0F
    sample = ((mantissa << 3) + 0x84) << exponent
    sample -= 0x84
    if sign:
        sample = -sample
    if sample > 32767:
        return 32767
    if sample < -32768:
        return -32768
    return sample


def _pcm16_wav(pcm: bytes, rate: int = 8000) -> bytes:
    if len(pcm) % 2:
        pcm = pcm[:-1]
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + len(pcm),
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        rate,
        rate * 2,
        2,
        16,
        b"data",
        len(pcm),
    )
    return header + pcm


def _pcap_caller_pcm(blob: bytes) -> bytes:
    """Ingress G.711 from the engine's synthetic ethernet pcap, one SSRC.

    Played audio is injected on egress, so it is not in this file when
    recording starts after the greeting.
    """
    if len(blob) < 24 or blob[:4] != b"\xd4\xc3\xb2\xa1":
        raise RuntimeError("voicemail pcap is not a little-endian ethernet capture")
    samples = array.array("h")
    offset = 24
    ssrc = None
    last_end = None
    while offset + 16 <= len(blob):
        incl = int.from_bytes(blob[offset + 8 : offset + 12], "little")
        start = offset + 16
        if incl < 0 or start + incl > len(blob):
            break
        offset = start + incl
        frame = blob[start : start + incl]
        if len(frame) < 42 or int.from_bytes(frame[12:14], "big") != 0x0800:
            continue
        ihl = (frame[14] & 0x0F) * 4
        if ihl < 20 or 14 + ihl + 8 >= len(frame):
            continue
        if frame[14 + 9] != 17:
            continue
        rtp = frame[14 + ihl + 8 :]
        if len(rtp) < 12 or (rtp[0] & 0xC0) != 0x80:
            continue
        pt = rtp[1] & 0x7F
        if pt not in (0, 8):
            continue
        packet_ssrc = rtp[8:12]
        if ssrc is None:
            ssrc = packet_ssrc
        elif packet_ssrc != ssrc:
            continue
        header = 12 + (rtp[0] & 0x0F) * 4
        if rtp[0] & 0x10:
            if len(rtp) < header + 4:
                continue
            header += 4 + int.from_bytes(rtp[header + 2 : header + 4], "big") * 4
        if header >= len(rtp):
            continue
        payload = rtp[header:]
        if rtp[0] & 0x20 and payload:
            pad = payload[-1]
            if 0 < pad <= len(payload):
                payload = payload[:-pad]
        if not payload:
            continue
        ts = int.from_bytes(rtp[4:8], "big")
        if last_end is not None:
            gap = (ts - last_end) & 0xFFFFFFFF
            if 0 < gap <= 8000:
                samples.extend([0] * gap)
        last_end = (ts + len(payload)) & 0xFFFFFFFF
        decode = _alaw_to_s16 if pt == 8 else _ulaw_to_s16
        samples.extend(decode(byte) for byte in payload)
    return samples.tobytes()


def _voicemail_plain_sdp(session: dict[str, Any], carrier_sdp: str) -> str:
    """Offer the carrier INVITE as plain RTP. No to-tag on the offer."""
    call_id = str(session.get("mediaCallId") or "").strip()
    from_tag = str(session.get("fromTag") or "").strip()
    if not call_id or not from_tag:
        raise RuntimeError("voicemail offer has no call-id or from-tag")
    if not str(carrier_sdp or "").strip():
        raise RuntimeError("voicemail offer has no carrier SDP")
    # trust-address uses the INVITE c= line. Do not send media address, and
    # do not send received-from: that would aim RTP at the SIP source, not c=.
    # The offer's own SDP faces the loopback leg. The carrier must get the
    # answer SDP, which is the public socket play sends from.
    rtpengine_offer(
        call_id,
        from_tag,
        carrier_sdp,
        "voicemail_plain",
    )
    return _voicemail_loopback_answer(session)


def _wav_pcm(wav: bytes) -> bytes:
    if len(wav) < 44 or wav[:4] != b"RIFF" or wav[8:12] != b"WAVE":
        raise RuntimeError("voicemail greeting is not a wav")
    offset = 12
    data = b""
    while offset + 8 <= len(wav):
        chunk = wav[offset : offset + 4]
        size = int.from_bytes(wav[offset + 4 : offset + 8], "little")
        start = offset + 8
        if start + size > len(wav):
            break
        if chunk == b"data":
            data = wav[start : start + size]
            break
        offset = start + size + (size & 1)
    if len(data) < 2:
        raise RuntimeError("voicemail greeting has no audio")
    if len(data) % 2:
        data = data[:-1]
    return data


def _recording_beep() -> bytes:
    """200 ms gap, 500 ms 800 Hz, 100 ms gap. The sentence says 'after the tone'."""
    rate = 8000
    samples = array.array("h")
    samples.extend([0] * 1600)
    amp = 9000
    for i in range(4000):
        samples.append(int(amp * math.sin(2 * math.pi * 800 * i / rate)))
    samples.extend([0] * 800)
    return samples.tobytes()


def _close_voicemail_loopback(session: dict[str, Any]) -> None:
    sock = session.pop("voicemailLoopback", None)
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _voicemail_loopback_answer(session: dict[str, Any]) -> str:
    """Answer a loopback leg. Returns the SDP the carrier has to be given.

    The offer return is the loopback socket. Putting that in the 200 makes
    the phone send and listen on a port the greeting never uses.
    """
    call_id = str(session.get("mediaCallId") or "").strip()
    from_tag = str(session.get("fromTag") or "").strip()
    to_tag = str(session.get("toTag") or "").strip()
    if not call_id or not from_tag or not to_tag:
        raise RuntimeError("voicemail answer has no tags")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
        sdp = (
            "v=0\r\n"
            "o=siphon 0 0 IN IP4 127.0.0.1\r\n"
            "s=voicemail\r\n"
            "c=IN IP4 127.0.0.1\r\n"
            "t=0 0\r\n"
            f"m=audio {port} RTP/AVP 8 101\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n"
            "a=fmtp:101 0-16\r\n"
            "a=ptime:20\r\n"
            "a=sendrecv\r\n"
        )
        carrier = rtpengine_answer(call_id, from_tag, to_tag, sdp, "voicemail_plain")
    except Exception:
        sock.close()
        raise
    session["voicemailLoopback"] = sock
    log.info(
        f"VOICEMAIL: loopback answer session={session.get('sessionId')} "
        f"port={port} to_tag={to_tag!r} carrier_bytes={len(carrier)}"
    )
    return carrier


def _write_voicemail_wav(wav: bytes) -> str:
    os.makedirs(VOICEMAIL_DIR, mode=0o755, exist_ok=True)
    try:
        os.chmod(VOICEMAIL_DIR, 0o755)
    except OSError:
        pass
    fd, path = tempfile.mkstemp(prefix="vm-", suffix=".wav", dir=VOICEMAIL_DIR)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(_pcm16_wav(_wav_pcm(wav) + _recording_beep()))
            fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    return path


def _voicemail_play_file(session: dict[str, Any], path: str) -> float:
    """Play toward the carrier. from-tag is the offerer; omit to-tag."""
    call_id = str(session.get("mediaCallId") or "").strip()
    from_tag = str(session.get("fromTag") or "").strip()
    if not call_id or not from_tag:
        raise RuntimeError("voicemail play has no NG call")
    decoded = _ng_command(
        {
            "command": "play media",
            "call-id": call_id,
            "from-tag": from_tag,
            "file": path,
        },
        timeout=5.0,
    )
    try:
        ms = int(decoded.get("duration") or 0)
    except (TypeError, ValueError):
        ms = 0
    log.info(
        f"VOICEMAIL: play media call_id={call_id} from_tag={from_tag!r} "
        f"duration_ms={ms}"
    )
    return max(0.0, ms / 1000.0)


def _voicemail_pcap_path(call_id: str) -> str:
    name = str(call_id or "").strip()
    if not name or "/" in name or name in (".", ".."):
        raise RuntimeError("voicemail recording call-id is not a filename")
    return os.path.join(VOICEMAIL_PCAP_DIR, name + ".pcap")


async def _voicemail_record_caller(session: dict[str, Any]) -> None:
    """Caller RTP after the greeting, from the engine pcap, into recordingWav.

    Do not set callRecorder. finalize_recording uploads recordingWav when
    there is no recorder, and a recorder with no frames would replace it.
    """
    session["voicemailRecordTask"] = asyncio.current_task()
    call_id = str(session.get("mediaCallId") or "").strip()
    from_tag = str(session.get("fromTag") or "").strip()
    if not call_id or not from_tag:
        log.warn(f"VOICEMAIL: record has no NG call session={session.get('sessionId')}")
        return
    try:
        path = _voicemail_pcap_path(call_id)
    except RuntimeError as exc:
        log.warn(f"VOICEMAIL: {exc}")
        return
    try:
        await asyncio.to_thread(
            _ng_command,
            {
                "command": "start recording",
                "call-id": call_id,
                "from-tag": from_tag,
                "recording-dir": VOICEMAIL_PCAP_DIR,
            },
            3.0,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"VOICEMAIL: start recording failed session={session.get('sessionId')}: {exc}"
        )
        return
    session["recordingStartedAt"] = time.time()
    log.info(
        f"VOICEMAIL: recording caller session={session.get('sessionId')} "
        f"call_id={call_id}"
    )
    deadline = time.monotonic() + VOICEMAIL_RECORD_SECS
    while not session.get("clientEnded") and not session.get("sipRejected"):
        if time.monotonic() >= deadline:
            break
        await asyncio.sleep(0.2)
    try:
        await asyncio.to_thread(
            _ng_command,
            {
                "command": "stop recording",
                "call-id": call_id,
                "from-tag": from_tag,
            },
            3.0,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"VOICEMAIL: stop recording failed session={session.get('sessionId')}: {exc}"
        )
    await asyncio.sleep(0.3)
    try:
        def _read(path: str = path) -> bytes:
            with open(path, "rb") as handle:
                return handle.read()

        raw = await asyncio.to_thread(_read)
    except OSError as exc:
        log.warn(
            f"VOICEMAIL: pcap unreadable session={session.get('sessionId')} "
            f"path={path}: {exc}"
        )
        return
    try:
        os.remove(path)
    except OSError:
        pass
    try:
        pcm = _pcap_caller_pcm(raw)
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"VOICEMAIL: pcap decode failed session={session.get('sessionId')}: {exc}"
        )
        return
    if len(pcm) < 2:
        log.info(f"VOICEMAIL: recording empty session={session.get('sessionId')}")
        return
    session["recordingWav"] = _pcm16_wav(pcm)
    session["recordingEndedAt"] = time.time()
    log.info(
        f"VOICEMAIL: recording wav session={session.get('sessionId')} "
        f"bytes={len(session['recordingWav'])}"
    )
    hung_up = bool(session.get("failureNotified") or session.get("clientEnded"))
    _schedule_recording_upload(session)
    if hung_up:
        return
    loop = asyncio.get_running_loop()
    loop.call_soon(_reject_inbound_sip, session, 200, "voicemail done")


async def _voicemail_after_prompt(session: dict[str, Any], duration_s: float) -> None:
    try:
        if duration_s > 0 and not session.get("clientEnded"):
            await asyncio.sleep(duration_s)
        path = str(session.pop("voicemailGreetingPath", "") or "")
        if path:
            try:
                os.remove(path)
            except OSError:
                pass
        if session.get("clientEnded") or session.get("sipRejected"):
            return
        await _voicemail_record_caller(session)
    finally:
        _close_voicemail_loopback(session)


async def _connect_no_answer_voicemail(
    session: dict[str, Any], offer_sdp: str
) -> bool:
    """When seats time out and route.noAnswer is set, play the greeting or dial the bot."""
    if session.get("clientEnded") or session.get("sipRejected"):
        return False
    route = session.get("route") or {}
    no_answer = route.get("noAnswer")
    if not isinstance(no_answer, dict):
        return False
    sip_uri = str(no_answer.get("sipUri") or no_answer.get("uri") or "").strip()
    greeting_sha = str(no_answer.get("greetingSha") or "").strip().lower()

    try:
        await _forward_cancel_to_ringing(session, reason="timeout")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"VOICEMAIL: forward cancel to ringing failed: {exc}")
    _hunt_end_session(session)
    # Only the callee hunt timed out — caller is still live.
    session["callerCancelForwarded"] = False
    session["pcCallee"] = None
    session["calleeDataChannel"] = None
    session["calleeDcOpen"] = False
    session["calleeRingAnswered"] = False

    mode = str(no_answer.get("mode") or "voicemail").strip() or "voicemail"
    sys_id = str(
        no_answer.get("systemId")
        or session.get("systemId")
        or route.get("systemId")
        or ""
    ).strip()
    did = "".join(
        ch
        for ch in str(
            no_answer.get("number")
            or _recording_did(session)
            or route.get("number")
            or ""
        )
        if ch.isdigit()
    )
    caller = str(
        (session.get("inboundCall") or {}).get("fromNumber")
        or session.get("from")
        or ""
    ).strip()
    lang = str(no_answer.get("language") or "").strip()
    biz = str(no_answer.get("businessName") or "").strip()

    vm_headers: dict[str, str] = {"X-Lpbx-Mode": mode}
    if sys_id:
        vm_headers["X-Lpbx-System-Id"] = sys_id
    if did:
        vm_headers["X-Lpbx-Number"] = did
    if caller:
        vm_headers["X-Lpbx-From"] = caller
    if lang:
        vm_headers["X-Lpbx-Language"] = lang
    if biz:
        vm_headers["X-Lpbx-Business"] = urllib.parse.quote(biz, safe="")

    _reset_recording_state(session)
    session["voicemailActive"] = True
    session["recordingKind"] = mode
    session["voicemailHeaders"] = vm_headers
    _apply_recording_policy(session, no_answer)
    if no_answer.get("callRecordingEnabled", True):
        session["callRecordingEnabled"] = True

    is_inbound = str(session.get("routeKind") or "") == "inbound"

    route_copy = dict(route)
    if sip_uri:
        route_copy["sipUri"] = sip_uri
        route_copy["uri"] = sip_uri
    if did:
        route_copy["number"] = did
    session["route"] = route_copy
    session["productKind"] = str(no_answer.get("route") or "external-sip").strip()

    dial_sdp = _body_text(
        offer_sdp
        or session.get("ringOfferSdp")
        or session.get("inboundSbcInviteSdp")
        or ""
    )
    log.info(
        f"VOICEMAIL: no-answer session={session.get('sessionId')} "
        f"did={did!r} sys={sys_id!r} greeting={greeting_sha[:12]!r} "
        f"uri={sip_uri!r} inbound={is_inbound}"
    )
    if (
        is_inbound
        and not session.get("referTransfer")
        and not session.get("sbcAnswered")
        and session.get("sipCall") is not None
    ):
        call = session.get("sipCall")
        to_tag = _uas_local_tag(call) or str(session.get("toTag") or "")
        session["toTag"] = to_tag
        plain = _voicemail_plain_sdp(session, dial_sdp)
        if session.get("clientEnded") or session.get("sipRejected"):
            return False
        log.info(
            f"VOICEMAIL/INBOUND: early 200 to SBC session={session.get('sessionId')} "
            f"to_tag={to_tag!r} plain_bytes={len(plain)}"
        )
        _log_sdp("NOTIFY/INBOUND SBC 200 SDP (voicemail early answer)", plain)
        _uas_answer(call, plain)
        session["sbcAnswered"] = True
        session["state"] = "answered"
        session["inboundSipAnswered"] = True
        session["hadConfirmedSip"] = True
        session["voicemailSbcPreAnswered"] = True
    if greeting_sha:
        try:
            sp = str(session.get("logicSp") or route.get("logicSp") or "").strip().lower()
            provider = policy.logic_provider(sp)
            if not provider:
                raise RuntimeError(f"no logic provider for sp={sp!r}")
            wav = await asyncio.to_thread(
                logic_client.fetch_voicemail_greeting, provider, greeting_sha
            )
            path = _write_voicemail_wav(wav)
            session["voicemailGreetingPath"] = path
            duration_s = _voicemail_play_file(session, path)
            session["voicemailPlayback"] = True
            _start_task_on_session_loop(
                session, _voicemail_after_prompt(session, duration_s)
            )
            return True
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"VOICEMAIL: greeting play failed session={session.get('sessionId')}: {exc}"
            )
            path = str(session.pop("voicemailGreetingPath", "") or "")
            if path:
                try:
                    os.remove(path)
                except OSError:
                    pass
            _close_voicemail_loopback(session)
            if not sip_uri:
                return False
            log.info(
                f"VOICEMAIL: falling back to bot session={session.get('sessionId')}"
            )
    if not sip_uri:
        return False
    if is_inbound:
        vm_call_id = f"vm-{uuid.uuid4().hex}@{policy.local_domain()}"
        vm_from_tag = uuid.uuid4().hex[:8]
        session["voicemailMediaCallId"] = vm_call_id
        session["voicemailFromTag"] = vm_from_tag
        _bind_session_aliases(session)
    log.info(
        f"VOICEMAIL: connecting no-answer session={session.get('sessionId')} "
        f"uri={sip_uri!r}"
    )
    await _dial_sbc(session, dial_sdp)
    return True


async def _execute_webrtc(session: dict[str, Any], _ring_offer_sdp: str) -> None:
    """Per-seat ring: notify + DC handshake + RING, first DC pickup wins."""
    route = session["route"]
    if session.get("routeKind") != "inbound":
        session["routeKind"] = "webrtc"
    my_gen = int(session.get("ringGeneration") or 0)
    dest = str(session.get("dialedTo") or route.get("number") or session.get("to") or "")
    all_targets = _webrtc_ring_targets(route, dest)
    session["huntAllTargets"] = all_targets
    hunt_on = extension_hunt.has_extension(all_targets)
    log.info(
        f"HUNT: RING to={dest!r} session={session.get('sessionId')} "
        f"hunt_on={hunt_on} {extension_hunt.describe_targets(all_targets)}"
    )

    session["answerEvent"] = threading.Event()
    session["pickupEvent"] = asyncio.Event()
    session["ringLock"] = asyncio.Lock()
    session["calleeAnswerSdp"] = None
    session["calleeAnswerCandidates"] = None
    session["calleeAnsweredOnce"] = False
    session["multiringWinner"] = None
    session["declinedBeforePickup"] = False
    session["ringCancelSent"] = False
    if not session.get("clientEnded"):
        session["callerCancelForwarded"] = False
    session.pop("cancelDcWaitDone", None)
    session.pop("activeCallId", None)
    session["on_ring_leg_dropped"] = _release_declined_ring_seat
    session["on_ring_winner"] = _on_ring_winner
    session["huntResumeEvent"] = asyncio.Event() if hunt_on else None

    if hunt_on:
        while True:
            if session.get("clientEnded") or session.get("failureNotified") or session.get("callerCancelForwarded"):
                await _wait_cancelled_callee_dc_end(session)
                _hunt_end_session(session)
                raise RuntimeError("Caller abandoned")
            if int(session.get("ringGeneration") or 0) != my_gen:
                if session.get("clientEnded") or session.get("callerCancelForwarded"):
                    await _wait_cancelled_callee_dc_end(session)
                    _hunt_end_session(session)
                    raise RuntimeError("Caller abandoned")
                log.info(
                    f"HUNT: RING superseded session={session.get('sessionId')} gen={my_gen}"
                )
                raise RuntimeError("RING superseded")
            filtered = extension_hunt.policy.filter_and_maybe_enqueue(
                all_targets, session, _sessions
            )
            if filtered:
                session["ringTargets"] = filtered
                break
            session["state"] = "extension-queued"
            session["ringTargets"] = []
            log.info(
                f"HUNT: wait occupancy session={session.get('sessionId')} "
                f"to={session.get('to')!r} state=extension-queued"
            )
            ev = session["huntResumeEvent"]
            if ev.is_set():
                ev.clear()
                continue
            await ev.wait()
    else:
        session["ringTargets"] = all_targets

    session["state"] = "ringing"
    session["ringStartedAt"] = time.monotonic()
    _bind_session_aliases(session)
    if hunt_on:
        extension_hunt.policy.mark_ringing(session, session["ringTargets"])

    caller_label = identity.identity_label(session.get("from") or "")
    cli_label = identity.identity_label(
        (session.get("route") or {}).get("callerId") or session.get("callerId") or ""
    )
    effective_caller_label = cli_label or caller_label
    existing_legs = dict(session.get("ringLegs") or {})
    legs: dict[str, Any] = {}
    by_sid: dict[str, Any] = {}
    reuse_legs: list[Any] = []
    cold_legs: list[Any] = []

    def _bind_leg_sids(leg: Any, ident: str) -> None:
        callee_lbl = identity.identity_label(ident)
        sid = _pair_session_id(
            caller_label,
            callee_lbl,
            fallback=str(session["sessionId"]),
        )
        push_sid = _pair_session_id(
            callee_lbl,
            caller_label,
            fallback=sid,
        )
        by_sid[sid] = leg
        by_sid[push_sid] = leg
        if cli_label and cli_label != caller_label:
            cli_sid = _pair_session_id(
                cli_label,
                callee_lbl,
                fallback=sid,
            )
            by_sid[cli_sid] = leg
        legs[ident] = leg

    for target in session["ringTargets"]:
        ident = str(target.get("notifyIdentity") or "")
        if not ident or ident in legs:
            continue
        old = existing_legs.pop(ident, None)
        if (
            old is not None
            and             old.dc_reusable()
            and not session.get("skipCalleeDcReuse")
        ):
            old.prepare_for_reuse_ring()
            old.signaling_session_id = _pair_session_id(
                identity.identity_label(ident),
                effective_caller_label,
                fallback=str(session["sessionId"]),
            )
            _bind_leg_sids(old, ident)
            reuse_legs.append(old)
            log.info(
                f"NOTIFY/WEBRTC: reuse callee DC ident={ident!r} "
                f"session={session.get('sessionId')}"
            )
            continue
        if old is not None:
            try:
                await old.close(force=True)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY/WEBRTC: close stale leg {ident!r}: {exc}")
        sid = _pair_session_id(
            effective_caller_label,
            identity.identity_label(ident),
            fallback=str(session["sessionId"]),
        )
        push_sid = _pair_session_id(
            identity.identity_label(ident),
            effective_caller_label,
            fallback=sid,
        )
        leg = webrtc_pc.RingLeg(
            session,
            ident=ident,
            wallet=target.get("wallet"),
            signaling_session_id=push_sid,
        )
        _bind_leg_sids(leg, ident)
        cold_legs.append(leg)
    for stale in existing_legs.values():
        if getattr(stale, "promoted", False) and stale.dc_reusable():
            log.info(
                f"NOTIFY/WEBRTC: keep leftover in-call ident="
                f"{getattr(stale, 'ident', '')!r} session={session.get('sessionId')}"
            )
            continue
        try:
            await stale.close(force=True)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/WEBRTC: close leftover leg: {exc}")
    session["ringLegs"] = legs
    session["ringLegsBySid"] = by_sid
    _bind_session_aliases(session)
    with _sessions_lock:
        siphon_sid = session["sessionId"]
        aliases = list(session.get("_aliasKeys") or [])
        for pair_sid in by_sid:
            aliases.append(pair_sid)
            _pair_append_locked(pair_sid, _storage_key(session))
        session["_aliasKeys"] = [k for k in dict.fromkeys(aliases) if k]
    if not legs:
        raise RuntimeError("Multi-ring: no targets")

    ring_timeout = _remaining_ring_timeout_secs(session)
    for leg in reuse_legs:
        leg._drive_started = True
        leg.drive_task = _start_task_on_session_loop(
            session, leg.drive_reused_ring(ring_timeout)
        )

    errors: list[str] = []
    pushed = 0
    if cold_legs:
        offers = await asyncio.gather(
            *[leg.create_offer() for leg in cold_legs],
            return_exceptions=True,
        )
        push_coros = []
        for leg, offer in zip(cold_legs, offers):
            ident = leg.ident
            if isinstance(offer, Exception):
                errors.append(f"{ident}: {offer}")
                log.warn(f"NOTIFY/WEBRTC: offer failed callee={ident!r}: {offer}")
                continue
            target = next(
                (t for t in session["ringTargets"] if t.get("notifyIdentity") == ident),
                {"notifyIdentity": ident, "wallet": leg.wallet},
            )
            _log_sdp(
                f"NOTIFY/WEBRTC invite SDP out ({ident})",
                (leg.invite or {}).get("sdp", ""),
            )
            async def _push_marked(_leg=leg, _target=target):
                await _push_dc_invite(session, _leg.invite or {}, _target)
                _leg.invite_pushed = True

            push_coros.append(_push_marked())
        results = await asyncio.gather(*push_coros, return_exceptions=True) if push_coros else []
        for result in results:
            if isinstance(result, Exception):
                errors.append(str(result))
                log.warn(f"NOTIFY/WEBRTC: push failed: {result}")
            else:
                pushed += 1
    if pushed < 1 and not reuse_legs:
        raise RuntimeError(f"Multi-ring push failed: {'; '.join(errors) or 'no targets'}")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + _remaining_ring_timeout_secs(session)
    winner = ""
    while True:
        if session.get("clientEnded") or session.get("callerCancelForwarded"):
            log.info(
                f"HUNT: caller abandoned session={session.get('sessionId')} gen={my_gen}"
            )
            await _wait_cancelled_callee_dc_end(session)
            raise RuntimeError("Caller abandoned")
        if int(session.get("ringGeneration") or 0) != my_gen:
            log.info(
                f"HUNT: RING superseded session={session.get('sessionId')} gen={my_gen}"
            )
            raise RuntimeError("RING superseded")
        winner = str(session.get("multiringWinner") or "")
        if winner:
            break
        still = [
            ident
            for ident, leg in (session.get("ringLegs") or {}).items()
            if getattr(leg, "still_ringing", lambda: False)()
        ]
        if session.get("declinedBeforePickup") and not still:
            raise RuntimeError("Callee declined")
        if session.get("declinedBeforePickup"):
            log.info(
                f"HUNT: decline ignored, seats still ringing {still} "
                f"session={session.get('sessionId')}"
            )
            session["declinedBeforePickup"] = False
        if not still:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise RuntimeError("Callee answer timeout")
            ev = session.get("pickupEvent")
            if ev is None or ev.is_set():
                session["pickupEvent"] = asyncio.Event()
                ev = session["pickupEvent"]
            try:
                await asyncio.wait_for(ev.wait(), timeout=min(remaining, 0.5))
            except asyncio.TimeoutError:
                pass
            continue
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise RuntimeError("Callee answer timeout")
        ev = session.get("pickupEvent")
        if ev is None or ev.is_set():
            session["pickupEvent"] = asyncio.Event()
            ev = session["pickupEvent"]
        try:
            await asyncio.wait_for(ev.wait(), timeout=remaining)
        except asyncio.TimeoutError as exc:
            if session.get("clientEnded") or session.get("callerCancelForwarded"):
                log.info(
                    f"HUNT: caller abandoned session={session.get('sessionId')} "
                    f"gen={my_gen}"
                )
                await _wait_cancelled_callee_dc_end(session)
                raise RuntimeError("Caller abandoned")
            if int(session.get("ringGeneration") or 0) != my_gen:
                log.info(
                    f"HUNT: RING superseded session={session.get('sessionId')} "
                    f"gen={my_gen}"
                )
                raise RuntimeError("RING superseded")
            raise RuntimeError("Callee answer timeout") from exc
    await _cancel_multiring_losers(session, winner, reason="answered-elsewhere")
    log.info(
        f"NOTIFY/WEBRTC: callee DC open session={session['sessionId']} "
        f"winner={winner} rung={len(session['ringTargets'])}"
    )
    session["state"] = "callee-audio-up"


async def _finish_inbound_uas(
    session: dict[str, Any],
    *,
    call: Any,
    call_id: str,
    from_tag: str,
    offer_sdp: str,
    ng_profile: str,
    webrtc_offer: str,
    to_tag: str,
    contact_host: str,
    session_id: str,
    refer_transfer: bool,
    sip_bye_id: str,
    old_openai_ng: str,
    product_xfer: Optional[dict[str, Any]],
) -> None:
    """180 already sent. Pickup + 200 must not occupy siphon's pyexec slot.

    handler_stall_abort_secs=30 kills the process if one in-flight handler
    sits in pickupEvent.wait() with zero completions (inbound ring, 9002 down).
    """
    try:
        try:
            await _execute_webrtc(session, "")
        except RuntimeError as ring_exc:
            if any(
                k in str(ring_exc)
                for k in ("Callee answer timeout", "Callee declined")
            ):
                if not await _connect_no_answer_voicemail(session, offer_sdp):
                    raise
            else:
                raise
        if session.get("voicemailSbcPreAnswered"):
            if session.get("pc") is not None or session.get("pc2") is not None:
                await webrtc_pc.rebridge_media(session)
            log.info(
                f"NOTIFY/INBOUND: voicemail up session={session_id} "
                f"pc1_connected={bool(session.get('pc1Connected'))} to_tag={session.get('toTag')!r} "
                f"pc2Connected={session.get('pc2Connected')} "
                f"mediaBridged={session.get('mediaBridged')} "
                f"c2s={session.get('bridgedClientToSbc')} "
                f"s2c={session.get('bridgedSbcToClient')}"
            )
            return
        if refer_transfer:
            if not to_tag:
                to_tag = uuid.uuid4().hex[:16]
            session["toTag"] = to_tag
            webrtc_offer = rtpengine_offer(
                call_id,
                from_tag,
                offer_sdp,
                ng_profile,
            )
            _log_sdp("NOTIFY/INBOUND rtpengine WebRTC offer (OpenAI already BYE)", webrtc_offer)
            log.info(
                f"NOTIFY/INBOUND: refer-transfer NG offer OpenAI already down "
                f"to_tag={to_tag!r} webrtc_offer_bytes={len(webrtc_offer)}"
            )
            pc1_answer = await webrtc_pc.accept_sbc_rtpengine_offer(session, webrtc_offer)
            ng_answer = localize_pc1_answer_for_ng(pc1_answer)
            plain = rtpengine_answer(
                call_id, from_tag, to_tag, ng_answer, ng_profile
            )
            plain_raw = _body_text(plain)
            plain = strip_webrtc_attrs_for_sbc_uas(plain_raw) or plain_raw
            plain = fit_plain_sdp_to_sbc_offer(plain, offer_sdp) or plain
        else:
            task = session.get("sbcLegTask")
            if task is not None:
                try:
                    await task
                except Exception as exc:  # noqa: BLE001
                    raise RuntimeError(f"SBC leg NG failed: {exc}") from exc
            plain = str(session.get("inboundPlainSdp") or "")
            pc1_answer = str(session.get("pc1AnswerSdp") or "")
            if not plain:
                if not to_tag:
                    to_tag = _uas_local_tag(call) or str(session.get("toTag") or "")
                    session["toTag"] = to_tag
                log.info(
                    f"NOTIFY/INBOUND: NG answer at pickup session={session_id} "
                    f"(pc1 DTLS starts with 200, not 180)"
                )
                plain = await _prepare_inbound_sbc_leg(
                    session,
                    webrtc_offer=webrtc_offer,
                    call_id=call_id,
                    from_tag=from_tag,
                    to_tag=to_tag,
                    ng_profile=ng_profile,
                    sbc_sdp=offer_sdp,
                )
                pc1_answer = str(session.get("pc1AnswerSdp") or "")
            to_tag = _uas_local_tag(call) or str(session.get("toTag") or to_tag)
            session["toTag"] = to_tag
        if session.get("clientEnded") or session.get("sipRejected"):
            log.info(
                f"NOTIFY/INBOUND: skip SBC 200 session={session_id} "
                f"ended client={session.get('clientEnded')} rejected={session.get('sipRejected')}"
            )
            return
        log.info(
            f"NOTIFY/INBOUND: answering SBC 200 session={session_id} "
            f"to_tag={to_tag!r} contact_host={contact_host or '-'} "
            f"pc1_answer_bytes={len(pc1_answer or '')} plain_bytes={len(plain)} "
            f"(dialog confirm; media join waits for both legs)"
        )
        _log_sdp("NOTIFY/INBOUND SBC 200 SDP", plain)
        if refer_transfer:
            log.info(
                "NOTIFY/INBOUND: refer-transfer skip second 200 "
                f"session={session_id} (dialog already confirmed)"
            )
            aleg = str(session.get("b2buaCallId") or sip_bye_id or "")
            if aleg and plain:
                try:
                    import siphon_app as _siphon_app

                    _siphon_app._reinvite_aleg_now(aleg, plain)
                except Exception as exc:  # noqa: BLE001
                    log.warn(f"NOTIFY/INBOUND: A-leg re-INVITE failed: {exc}")
                else:
                    if old_openai_ng and old_openai_ng != call_id:
                        try:
                            rtpengine_delete(
                                old_openai_ng,
                                from_tag or (product_xfer or {}).get("fromTag") or "a",
                            )
                            log.info(
                                f"NOTIFY/INBOUND: deleted OpenAI NG {old_openai_ng} "
                                f"after A-leg re-INVITE → {call_id}"
                            )
                        except Exception as exc:  # noqa: BLE001
                            log.warn(
                                f"NOTIFY/INBOUND: OpenAI NG delete failed "
                                f"{old_openai_ng}: {exc}"
                            )
        else:
            if session.get("xferPark"):
                # Empty body. A body on this dialog makes siphon delete the
                # A-leg anchor. The seat is already on that call's far port.
                _uas_answer(call, "")
            else:
                _uas_answer(call, plain)
        session["sbcAnswered"] = True
        session["state"] = "answered"
        session["inboundSipAnswered"] = True
        session["hadConfirmedSip"] = True
        await webrtc_pc.rebridge_media(session)
        log.info(
            f"NOTIFY/INBOUND: up session={session_id} "
            f"pc1_connected={bool(session.get('pc1Connected'))} to_tag={to_tag!r} "
            f"pc2Connected={session.get('pc2Connected')} "
            f"mediaBridged={session.get('mediaBridged')} "
            f"c2s={session.get('bridgedClientToSbc')} "
            f"s2c={session.get('bridgedSbcToClient')}"
        )
    except Exception as exc:  # noqa: BLE001
        log.error(f"NOTIFY/INBOUND: failed session={session_id}: {exc}")
        await fail_notify_call(
            exc,
            session=session,
            session_id=session_id,
            cancel_sip=not refer_transfer,
        )


async def _inbound_sip_alive(sip_call_id: str) -> bool:
    """True while siphon still has this SIP dialog (pre-200 CANCEL removes it).

    ``on_cancel`` does not run until on_invite returns, so we probe with
    ``b2bua.unbridge``: live unanswered UAS → invalid_state; gone → not_found.
    """
    cid = str(sip_call_id or "").strip()
    if not cid:
        return True
    try:
        from siphon import b2bua as _b2bua

        unbridge = getattr(_b2bua, "unbridge", None)
        if not callable(unbridge):
            return True
        await unbridge(cid)
        return True
    except Exception as exc:  # noqa: BLE001
        text = str(exc).lower()
        if text.startswith("not_found") or "unknown or already gone" in text:
            return False
        return True


def _inbound_sip_cancel_probe_id(session: dict[str, Any]) -> str:
    """SIP dialog id for CANCEL probe — never rtpengine ``xfer-`` NG ids.

    Park/IVR UAS is not a siphon B2BUA actor; ``unbridge(xfer-…)`` is always
    not_found and used to false-cancel the hunt.
    """
    if session.get("xferPark") or session.get("referTransfer"):
        return ""
    for key in ("b2buaCallId", "parkCallId", "siphonActorId", "mediaCallId"):
        cid = str(session.get(key) or "").strip()
        if not cid or cid.startswith("xfer-"):
            continue
        return cid
    return ""


async def _watch_inbound_sip_cancel(session: dict[str, Any]) -> None:
    sip_cid = _inbound_sip_cancel_probe_id(session)
    if not sip_cid:
        return
    try:
        while True:
            if session.get("inboundSipAnswered") or session.get("sbcAnswered"):
                return
            if session.get("clientEnded") or session.get("callerCancelForwarded"):
                return
            if session.get("closed"):
                return
            if not await _inbound_sip_alive(sip_cid):
                log.info(
                    f"NOTIFY/INBOUND: SIP CANCEL probed session={session.get('sessionId')} "
                    f"call_id={sip_cid}"
                )
                session["clientEnded"] = True
                try:
                    await _forward_cancel_to_ringing(session, reason="cancelled")
                except Exception as exc:  # noqa: BLE001
                    log.warn(f"NOTIFY/INBOUND: cancel-forward after SIP CANCEL failed: {exc}")
                pickup = session.get("pickupEvent")
                if pickup is not None:
                    try:
                        pickup.set()
                    except Exception:  # noqa: BLE001
                        pass
                return
            await asyncio.sleep(0.12)
    except asyncio.CancelledError:
        return


def _arm_inbound_sip_cancel_watch(session: dict[str, Any]) -> None:
    if session.get("xferPark") or session.get("referTransfer"):
        return
    if not _inbound_sip_cancel_probe_id(session):
        return
    task = session.get("inboundSipWatchTask")
    if task is not None and not getattr(task, "done", lambda: True)():
        return
    try:
        session["inboundSipWatchTask"] = _start_task_on_session_loop(
            session, _watch_inbound_sip_cancel(session)
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/INBOUND: SIP cancel watch failed to start "
            f"session={session.get('sessionId')}: {exc}"
        )


def _dialog_originator(session: dict[str, Any]) -> str:
    stamped = identity.identity_label(str(session.get("dialogOriginator") or ""))
    if stamped:
        return stamped
    if session.get("sbcHairpinId"):
        return identity.identity_label(
            str(session.get("sbcFromUser") or session.get("to") or "")
        )
    return identity.identity_label(str(session.get("from") or ""))


def _dialog_inflight(session: Optional[dict[str, Any]]) -> bool:
    """Unanswered call attempt. A soft-ended DC waiting for the next call is not one."""
    if not session:
        return False
    if session.get("mediaBridged") or session.get("sbcAnswered") or session.get("inboundSipAnswered"):
        return False
    if session.get("sbcHairpinId") and not session.get("softEnded"):
        return True
    state = str(session.get("state") or "")
    if state == "inbound-ringing" and session.get("sipCall") is not None:
        return True
    if state in ("dialing", "ringing", "dc-ring"):
        return True
    return bool(session.get("dcRingStarted") and not session.get("clientEnded"))


def _webrtc_pair_attempt(session: dict[str, Any]) -> bool:
    """Phone-to-phone WebRTC attempt (no SIP dialog to clear)."""
    if session.get("sbcHairpinId") or session.get("sipCall") is not None:
        return False
    if str(session.get("routeKind") or "") in ("sbc", "inbound"):
        return False
    route = session.get("route") or {}
    return str(route.get("route") or "") in ("webrtc", "webrtc-multiring")


def _glare_sibling_attempts(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Unanswered opposite-direction attempts between the same two identities."""
    a = identity.identity_label(str(session.get("from") or ""))
    b = identity.identity_label(str(session.get("to") or ""))
    if not a or not b or a == b or not _webrtc_pair_attempt(session):
        return []
    me = _dialog_originator(session)
    out: list[dict[str, Any]] = []
    for s in _attempts_for_keys(
        _stable_key(a, b), _directional_key(a, b), _directional_key(b, a)
    ):
        if s is session or s.get("glareRetired"):
            continue
        pair = {
            identity.identity_label(str(s.get("from") or "")),
            identity.identity_label(str(s.get("to") or "")),
        }
        if pair != {a, b} or _dialog_originator(s) == me:
            continue
        if not _webrtc_pair_attempt(s) or s.get("mediaBridged"):
            continue
        if _attempt_connected(s) or not _dialog_inflight(s):
            continue
        out.append(s)
    return out


def retire_glare_siblings(session: dict[str, Any]) -> None:
    """The pair connected on this attempt: stop the opposite one, quietly.

    Android (WebRtcSessionManager) and iOS (SessionCoordinator) keep one PC
    per local|remote, and the live call owns it. The sibling's PCs no longer
    reach either phone. A cancel push or call/end would land on the live
    call's session (Android cancel without callId disposes it), so send
    nothing: stop the ring loop and close the sibling's server PCs.
    """
    for s in _glare_sibling_attempts(session):
        s["glareRetired"] = True
        s["clientEnded"] = True
        s["failureNotified"] = True
        s["cancelDcWaitDone"] = True
        s["dcRingStarted"] = False
        _bump_dialog_epoch(s)
        log.info(
            f"DIALOG-GLARE: retire sibling {_storage_key(s)} "
            f"from={_dialog_originator(s)} (pair connected on {_storage_key(session)}; "
            f"no push/DC cancel)"
        )
        try:
            _start_task_on_session_loop(s, _close_retired_sibling(s))
        except Exception as exc:  # noqa: BLE001
            log.warn(f"DIALOG-GLARE: retire sibling {_storage_key(s)} failed: {exc}")


async def _close_retired_sibling(s: dict[str, Any]) -> None:
    for key in ("pickupEvent", "answerEvent", "huntResumeEvent"):
        ev = s.get(key)
        if ev is not None:
            try:
                ev.set()
            except Exception:  # noqa: BLE001
                pass
    # Let _execute_webrtc see clientEnded and unwind ("DC RING aborted").
    await asyncio.sleep(0.3)
    sid = _storage_key(s)
    _hunt_end_session(s)
    _pop_session(sid)
    try:
        await webrtc_pc.close(s)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"DIALOG-GLARE: close retired sibling {sid} failed: {exc}")
    try:
        rtpengine_delete(s.get("mediaCallId") or sid or "unknown", s.get("fromTag") or "a")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"DIALOG-GLARE: rtpengine delete retired sibling {sid} failed: {exc}")
    s["failureCleanupDone"] = True
    log.info(f"DIALOG-GLARE: retired sibling closed {sid}")


def _bump_dialog_epoch(session: dict[str, Any]) -> int:
    epoch = int(session.get("dialogEpoch") or 0) + 1
    session["dialogEpoch"] = epoch
    return epoch


async def _cancel_losing_outgoing(session: dict[str, Any]) -> None:
    """Drop the losing attempt's SIP dialog. Leave the phone DC up for the winner."""
    _bump_dialog_epoch(session)
    session["dialogGlareLost"] = True
    session["dcRingStarted"] = False
    session["pendingCalleeAnswerSdp"] = None
    session["pc2OfferReady"] = False
    if session.get("sbcHairpinId") or str(session.get("routeKind") or "") == "sbc":
        try:
            await _cancel_pending_sbc(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"DIALOG-GLARE: cancel outgoing failed session={session.get('sessionId')}: {exc}"
            )
    session["sbcHairpinId"] = None
    if str(session.get("routeKind") or "") == "inbound" and session.get("sipCall") is not None:
        _reject_inbound_sip(session, 486, "Busy Here")
        session["sipCall"] = None


async def _resolve_inbound_dialog_glare(existing: dict[str, Any], new_from: str, call: Any) -> bool:
    """False → this INVITE was the loser and has been rejected."""
    if not _dialog_inflight(existing):
        return True
    mine = identity.identity_label(str(new_from or ""))
    theirs = _dialog_originator(existing)
    if not mine or not theirs or mine == theirs:
        return True
    if max(mine, theirs) != mine:
        log.info(
            f"DIALOG-GLARE: decline inbound from={mine} keep={theirs} "
            f"session={existing.get('sessionId')}"
        )
        try:
            call.reject(486, "Busy Here")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"DIALOG-GLARE: inbound reject failed: {exc}")
        return False
    log.info(
        f"DIALOG-GLARE: inbound from={mine} wins, decline {theirs} "
        f"session={existing.get('sessionId')}"
    )
    await _cancel_losing_outgoing(existing)
    return True


async def prepare_callee_dialog(session: dict[str, Any]) -> bool:
    """Callee callback vs an inbound that is already ringing this pair.

    Returns False when this callback is the loser. The inbound INVITE is already
    the winner, so it is not sent again.
    """
    me = identity.identity_label(str(session.get("to") or ""))
    session["dialogOriginator"] = me
    if (
        str(session.get("routeKind") or "") == "inbound"
        and session.get("sipCall") is not None
        and str(session.get("state") or "") == "inbound-ringing"
        and not session.get("sbcAnswered")
        and not session.get("inboundSipAnswered")
        and not session.get("mediaBridged")
    ):
        them = identity.identity_label(str(session.get("from") or ""))
        if me and them and me != them:
            if max(me, them) != me:
                log.info(
                    f"DIALOG-GLARE: callee {me} loses to inbound {them} "
                    f"session={session.get('sessionId')}"
                )
                _bump_dialog_epoch(session)
                session["dcRingStarted"] = False
                return False
            log.info(
                f"DIALOG-GLARE: callee {me} wins, decline inbound {them} "
                f"session={session.get('sessionId')}"
            )
            _reject_inbound_sip(session, 486, "Busy Here")
            session["sipCall"] = None
    _bump_dialog_epoch(session)
    return True


def callee_dialog_still_ours(session: dict[str, Any], epoch: Any) -> bool:
    return int(session.get("dialogEpoch") or 0) == int(epoch or 0)


def _inbound_callee_dc_live(session: Optional[dict[str, Any]]) -> bool:
    """True if inbound soft-end left a usable phone DC (RING reuse, no new PC)."""
    if not session:
        return False
    if session.get("sbcAnswered") and not session.get("softEnded") and not session.get("clientEnded"):
        return False
    for leg in (session.get("ringLegs") or {}).values():
        try:
            if leg.dc_reusable():
                return True
        except Exception:  # noqa: BLE001
            continue
    dc = session.get("calleeDataChannel")
    return str(getattr(dc, "readyState", "") or "").lower() == "open"


def _rebind_inbound_sip_on_live_dc(
    session: dict[str, Any],
    *,
    call: Any,
    clean_from: str,
    clean_to: str,
    diversion: str,
    notify_identity: str,
    route: dict[str, Any],
    call_id: str,
    sip_bye_id: str,
    park_sip_id: str,
    from_tag: str,
    to_tag: str,
    src: str,
    session_loop: Any,
    refer_transfer: bool,
    xfer_park: bool,
    product_xfer: Optional[dict[str, Any]],
) -> None:
    """Keep worker callee PC/DC; attach the new SBC INVITE (fresh pc1/rtpengine)."""
    session["from"] = clean_from
    session["to"] = notify_identity
    session["route"] = route
    session["routeKind"] = "inbound"
    session["mediaCallId"] = call_id
    session["b2buaCallId"] = sip_bye_id
    session["parkCallId"] = park_sip_id
    if not str(session.get("alegFromTag") or "").strip():
        session["alegFromTag"] = str(
            session.get("fromTag") or (product_xfer or {}).get("fromTag") or ""
        ).strip()
    if not str(session.get("alegToTag") or "").strip():
        session["alegToTag"] = str(
            session.get("blegRemoteTag")
            or (product_xfer or {}).get("blegRemoteTag")
            or ""
        ).strip()
    session["fromTag"] = from_tag
    session["toTag"] = to_tag
    session["sipCall"] = call
    session["siphonActorId"] = str(getattr(call, "id", "") or "")
    session["inboundCall"] = {
        "fromNumber": clean_from,
        "toNumber": clean_to,
        "diversion": diversion,
        "callId": call_id,
    }
    session["sbcNgOwned"] = True
    session["sbcSourceIp"] = src
    session["sbcAnswered"] = False
    session["inboundSipAnswered"] = False
    session["hadConfirmedSip"] = False
    session["state"] = "inbound-ringing"
    session["logicSp"] = route.get("logicSp")
    session["serviceId"] = route.get("logicSp")
    _set_call_nonce(session, fresh=True)
    session["dialogOriginator"] = identity.identity_label(str(clean_from or ""))
    session["dialogGlareLost"] = False
    session["on_dc_end"] = _on_dc_end
    session["on_dc_action"] = _on_dc_action
    session["referCall"] = getattr(call, "_refer_call", None)
    session["referTransfer"] = bool(refer_transfer)
    session["xferPark"] = bool(xfer_park)
    session["mediaWorker"] = True
    session["dtmfCount"] = 0
    session["dtmfLog"] = []
    session["transferLog"] = []
    session["ivrTransferArmed"] = bool(
        refer_transfer or (product_xfer or {}).get("ivrTransferArmed")
    )
    session["blegRemoteTag"] = (product_xfer or {}).get("blegRemoteTag")
    # Same values start_inbound_from_sbc stores on a fresh session. They are
    # not in this function's scope; product_xfer is None on a plain inbound.
    session["alegFromTag"] = str((product_xfer or {}).get("fromTag") or "").strip()
    session["alegToTag"] = str((product_xfer or {}).get("blegRemoteTag") or "").strip()
    session["eventLoop"] = session_loop
    session["softEnded"] = False
    session["clientEnded"] = False
    session["sipRejected"] = False
    session["callerCancelForwarded"] = False
    session.pop("cancelDcWaitDone", None)
    session["softEndInProgress"] = False
    session["failureNotified"] = False
    session["failureCleanupDone"] = False
    session["endCallSent"] = False
    session["endCallRenegotiating"] = False
    session["endingAwaitAnswerPc1"] = False
    session["endingAwaitAnswerCallee"] = False
    session["mediaBridged"] = False
    session["pc"] = None
    session["pc1Connected"] = False
    session["httpReused"] = True
    session["ringGeneration"] = int(session.get("ringGeneration") or 0) + 1
    session["ringCancelSent"] = False
    session["multiringWinner"] = None
    session["calleeAnsweredOnce"] = False
    session["pc2OfferReady"] = False
    session["pc2Connected"] = False
    session["pc1Connected"] = False
    session["sbcNgAnswered"] = False
    session.pop("inboundPlainSdp", None)
    session.pop("activeCallId", None)
    session.pop("sbcLegTask", None)
    session.pop("voicemailActive", None)
    session.pop("declinedBeforePickup", None)
    session.pop("voicemailSbcPreAnswered", None)
    session.pop("sbcHairpinAnswered", None)
    session.pop("ringStartedAt", None)
    session.pop("recordingKind", None)
    session.pop("voicemailHeaders", None)
    session.pop("voicemailMediaCallId", None)
    session.pop("voicemailFromTag", None)
    _reset_recording_state(session)


def _is_outbound_hairpin(session: Optional[dict[str, Any]]) -> bool:
    """Caller leg already dialing the SBC. Not an inbound dialog to glare against."""
    if not session:
        return False
    if str(session.get("routeKind") or "") == "inbound":
        return False
    if session.get("sipCall") is not None and str(session.get("state") or "") == "inbound-ringing":
        return False
    if session.get("sbcHairpinId"):
        return True
    rk = str(
        session.get("routeKind") or (session.get("route") or {}).get("route") or ""
    ).strip().lower()
    return rk == "sbc"


async def start_inbound_from_sbc(
    call: Any,
    *,
    clean_from: str,
    clean_to: str,
    diversion: str,
    call_id: str,
    from_tag: str,
    sbc_sdp: str,
    to_domain: str = "",
    provider: str = "",
    source_ip: str = "",
    origin: str = "sbc",
    kind: str = "inbound",
    route: Optional[dict[str, Any]] = None,
    refer_transfer: bool = False,
    b2bua_call_id: str = "",
    xfer_park: bool = False,
) -> None:
    """SBC→WebRTC inbound: Kamailio-parity UAS (180 → phone → 200).

    Order matches prod timing (suspend/180 while phone wakes, 200 after pickup):
    raw NG offer (Kamailio flags) → progress(180) → dialog to-tag → DC RING →
    PC1 answers rtpengine → NG answer → call.answer(200) with IP Contact.
    """
    # R-URI/To is the mapped identity (972…). Diversion is often the same DID
    # in national form (055…) which ANS does not have.
    lookup_ids: list[str] = []
    for item in (clean_to, diversion):
        v = str(item or "").strip()
        if v and v not in lookup_ids:
            lookup_ids.append(v)
    target = lookup_ids[0] if lookup_ids else str(clean_to or diversion or "")
    logic_sp = str(provider or "").strip().lower()
    from_key = identity.identity_label(clean_from) or str(clean_from or "")
    pinned = None
    if from_key:
        with _pending_ivr_lock:
            pinned = _pending_ivr_transfers.pop(from_key, None)
    if isinstance(pinned, dict) and pinned.get("route") in ("webrtc", "webrtc-multiring"):
        route = pinned
        log.info(
            f"NOTIFY/INBOUND: pinned ivr-action route={route.get('route')} "
            f"from={clean_from} digit={pinned.get('digit')!r} "
            f"targets={len(route.get('targets') or [])} "
            f"isExtension={bool(route.get('isExtension'))} "
            f"productItemId={route.get('productItemId') or '-'}"
        )
    elif not isinstance(route, dict) or not route.get("route"):
        route = {"route": "reject", "reason": "Missing destination", "statusCode": 400}
        for cand in lookup_ids:
            parsed_to = logic_client.parse_address(cand)
            parsed_from = logic_client.parse_address(clean_from)
            decision = await logic_client.resolve_destination(
                parsed_to,
                parsed_from,
                origin=origin,
                to=cand,
                from_id=clean_from,
                session_id=call_id,
                kind=kind,
                logic_sp=logic_sp,
                diversion=diversion,
                to_domain=to_domain,
            )
            target = cand
            route = decision
            if decision.get("route") in ("webrtc", "webrtc-multiring"):
                break
    ext_n = sum(1 for t in (route.get("targets") or []) if t.get("isExtension"))
    log.info(
        f"NOTIFY/INBOUND: resolve from={clean_from} to={target} "
        f"route={route.get('route')} wallet={route.get('wallet')} "
        f"sp={route.get('logicSp') or '-'} "
        f"source={route.get('walletSource')} domain={to_domain} provider={provider} "
        f"isExtension={bool(route.get('isExtension'))} extTargets={ext_n} "
        f"productItemId={route.get('productItemId') or '-'}"
    )
    try:
        session_loop = asyncio.get_running_loop()
    except RuntimeError:
        session_loop = None
    if route.get("route") not in ("webrtc", "webrtc-multiring"):
        reason = str(route.get("reason") or "No WebRTC user")
        code = int(route.get("statusCode") or 404)
        log.error(f"NOTIFY/INBOUND: reject {code} {reason}")
        try:
            call.reject(code, reason[:64] or "Not Found")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/INBOUND: call.reject failed: {exc}")
        return

    notify_identity = str(route.get("notifyIdentity") or route.get("ensName") or target)
    session_id = _stable_key(clean_from, notify_identity)
    existing = _get_session(session_id)
    hairpin_peer = None
    if _is_outbound_hairpin(existing):
        hairpin_peer = existing
        log.info(
            f"NOTIFY/INBOUND: outbound hairpin is not this dialog "
            f"session={existing.get('sessionId')} from={clean_from}"
        )
        existing = None
    if (
        existing is not None
        and not refer_transfer
        and not xfer_park
        and not await _resolve_inbound_dialog_glare(existing, clean_from, call)
    ):
        return
    reuse_dc = _inbound_callee_dc_live(existing)
    if existing and reuse_dc:
        # Soft-end kept the phone DC. A new HTTP DC-only PC reuses ICE 20028 +
        # the same DTLS cert and the client audio session stays inactive.
        log.info(
            f"NOTIFY/INBOUND: keep callee DC session={session_id} "
            f"worker={existing.get('workerSessionId')}"
        )
        try:
            await webrtc_pc.close_inbound_sip_pc(existing)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/INBOUND: close leftover pc1 failed session={session_id}: {exc}")
        rtpengine_delete(
            existing.get("mediaCallId") or session_id, existing.get("fromTag") or "a"
        )
    else:
        prior = None if _is_outbound_hairpin(_get_session(session_id)) else _pop_session(session_id)
        if _is_outbound_hairpin(prior):
            _put_session(prior)
            prior = None
        if prior:
            try:
                await webrtc_pc.close(prior)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY/INBOUND: close prior failed session={session_id}: {exc}")
            rtpengine_delete(
                prior.get("mediaCallId") or session_id, prior.get("fromTag") or "a"
            )

    if not call_id or not from_tag:
        log.error(
            f"NOTIFY/INBOUND: missing SIP keys call_id={call_id!r} from_tag={from_tag!r}"
        )
        try:
            call.reject(500, "Server Error")
        except Exception:  # noqa: BLE001
            pass
        return

    # Kamailio fed $rb to rtpengine_offer untouched. Do not sanitize/normalize.
    offer_sdp = _body_text(sbc_sdp)
    if not offer_sdp:
        log.error("NOTIFY/INBOUND: empty SBC INVITE SDP")
        if not refer_transfer:
            try:
                call.reject(488, "No SDP")
            except Exception:  # noqa: BLE001
                pass
        return
    src = str(source_ip or "").strip()
    contact_host = _rtpengine_media_address() or os.environ.get("SIPHON_BIND_IP", "")
    sip_bye_id = str(b2bua_call_id or call_id or "").strip()
    park_sip_id = ""
    ng_profile = "sbc_to_webrtc"
    if xfer_park:
        park_sip_id = str(call_id or "")
        call_id = f"xfer-{uuid.uuid4().hex}"
        ng_profile = "sbc_to_webrtc_xfer"
        log.info(
            f"NOTIFY/INBOUND: xfer_park NG call-id={call_id} park_sip={park_sip_id} "
            f"a_leg={sip_bye_id} profile={ng_profile} "
            "(unique NG id so siphon re-anchor cannot replace PC1 ports)"
        )
    product_xfer = None
    old_openai_ng = ""
    # Snapshot before the new session steals the A-leg Call-ID index.
    # After that, get_session_by_sip_call_id returns the park dialog and
    # its From tag is not the tag rtpengine.offer used.
    if refer_transfer or xfer_park:
        product_xfer = get_session_by_sip_call_id(sip_bye_id) if sip_bye_id else None
    aleg_from_saved = str((product_xfer or {}).get("fromTag") or "").strip()
    aleg_to_saved = str((product_xfer or {}).get("blegRemoteTag") or "").strip()
    if refer_transfer:
        old_openai_ng = str(
            (product_xfer or {}).get("mediaCallId") or sip_bye_id or ""
        ).strip()
        # Do NOT ICE-upgrade the PSTN↔OpenAI NG call. That session is
        # always-transcode RTP/AVP; a second offer with ICE/DTLS reuses
        # the OpenAI port (30762 here) and yields PC1.in≈0 + PSTN static.
        if not xfer_park:
            call_id = f"xfer-{uuid.uuid4().hex}"
            ng_profile = "sbc_to_webrtc_xfer"
        log.info(
            f"NOTIFY/INBOUND: refer-transfer NG call-id={call_id} "
            f"old_ng={old_openai_ng or '-'} profile={ng_profile} "
            "(fresh NG after OpenAI BYE, then A-leg re-INVITE)"
        )
        if product_xfer and product_xfer.get("referCall"):
            # Stash on the inbound call object so the webrtc session can BYE OpenAI.
            try:
                setattr(call, "_refer_call", product_xfer.get("referCall"))
            except Exception:  # noqa: BLE001
                pass
    _log_sdp(f"NOTIFY/INBOUND SBC INVITE SDP src={src or '-'}", offer_sdp)
    # Enrich static PT maps so rtpengine definitely sees PCMA (invite often
    # omits a=rtpmap:8).
    offer_sdp = normalize_sbc_answer_sdp(offer_sdp) or offer_sdp
    webrtc_offer = ""
    if refer_transfer:
        log.info(
            f"NOTIFY/INBOUND: refer-transfer defer rtpengine offer "
            f"until seat answers media={call_id}"
        )
    else:
        # Do NOT rtpengine_offer(SBC) here. That makes siphon the DTLS client
        # (sbc_to_webrtc DTLS=passive) which never completes with werift.
        # Pickup uses pc2_to_sbc: siphon offers, rtpengine DTLS-active answers.
        log.info(
            f"NOTIFY/INBOUND: defer NG until pickup (siphon-offerer) "
            f"src={src or '-'} contact_host={contact_host or '-'} "
            f"invite_bytes={len(offer_sdp)}"
        )

    # 180 stamps A-leg local_tag (sb-…) — NG answer must reuse that To-tag.
    # REFER lands on an already-200 dialog; do not send a second 180.
    if refer_transfer:
        to_tag = _uas_local_tag(call) or uuid.uuid4().hex[:16]
        log.info(
            f"NOTIFY/INBOUND: refer-transfer skip 180 to_tag={to_tag!r} "
            f"media={call_id} (new NG to-tag, not OpenAI B-leg)"
        )
    else:
        _uas_progress(call, 180, "Ringing")
        to_tag = _uas_local_tag(call)
    if not to_tag and not refer_transfer:
        log.info(
            "NOTIFY/INBOUND: no To-tag after 180 — SIP dialog already gone, drop"
        )
        return
    log.info(
        f"NOTIFY/INBOUND: dialog to_tag={to_tag!r} from_tag={from_tag!r} "
        f"contact_host={contact_host or '-'} (UAS Contact = BIND_IP:5061/tls)"
    )

    if reuse_dc and existing is not None:
        session = existing
        _rebind_inbound_sip_on_live_dc(
            session,
            call=call,
            clean_from=clean_from,
            clean_to=clean_to,
            diversion=diversion,
            notify_identity=notify_identity,
            route=route,
            call_id=call_id,
            sip_bye_id=sip_bye_id,
            park_sip_id=park_sip_id,
            from_tag=from_tag,
            to_tag=to_tag,
            src=src,
            session_loop=session_loop,
            refer_transfer=refer_transfer,
            xfer_park=xfer_park,
            product_xfer=product_xfer,
        )
        _put_session(session)
        _apply_recording_policy(session, route)
        log.info(
            f"NOTIFY/INBOUND: session={session_id} worker={session.get('workerSessionId')} "
            f"call_id={call_id} to_tag={to_tag} webrtc_offer_bytes={len(webrtc_offer)} "
            f"reuse_dc=True record={bool(session.get('callRecordingEnabled') or (session.get('route') or {}).get('callRecordingEnabled'))} "
            f"did={_recording_did(session) or '-'} → RING on live DC"
        )
    else:
        session = {
            "sessionId": session_id,
            "workerSessionId": f"{session_id}:{uuid.uuid4().hex[:10]}",
            "from": clean_from,
            "to": notify_identity,
            "route": route,
            "routeKind": "inbound",
            "mediaCallId": call_id,
            "b2buaCallId": sip_bye_id,
            "parkCallId": park_sip_id,
            "fromTag": from_tag,
            "toTag": to_tag,
            "sipCall": call,
            "siphonActorId": str(getattr(call, "id", "") or ""),
            "inboundCall": {
                "fromNumber": clean_from,
                "toNumber": clean_to,
                "diversion": diversion,
                "callId": call_id,
            },
            "sbcNgOwned": True,
            "sbcSourceIp": src,
            "peerHairpinId": str((hairpin_peer or {}).get("sbcHairpinId") or ""),
            "hairpinCallerKey": _storage_key(hairpin_peer) if hairpin_peer else "",
            "hairpinCallerWorker": str((hairpin_peer or {}).get("workerSessionId") or ""),
            "sbcAnswered": False,
            "state": "inbound-ringing",
            "createdAt": time.time(),
            "logicSp": route.get("logicSp"),
            "serviceId": route.get("logicSp"),
            "callNonce": str(uuid.uuid4()),
            "dialogOriginator": identity.identity_label(str(clean_from or "")),
            "dialogGlareLost": False,
            "on_dc_end": _on_dc_end,
            "on_dc_action": _on_dc_action,
            "referCall": getattr(call, "_refer_call", None),
            "referTransfer": bool(refer_transfer),
            "xferPark": bool(xfer_park),
            "mediaWorker": True,
            "dtmfCount": 0,
            "dtmfLog": [],
            "transferLog": [],
            "ivrTransferArmed": bool(
                refer_transfer or (product_xfer or {}).get("ivrTransferArmed")
            ),
            "blegRemoteTag": (product_xfer or {}).get("blegRemoteTag"),
            "alegFromTag": aleg_from_saved,
            "alegToTag": aleg_to_saved,
            "eventLoop": session_loop,
        }
        if hairpin_peer is not None and session.get("peerHairpinId"):
            hairpin_peer["hairpinReturnKey"] = _storage_key(session)
            hairpin_peer["hairpinReturnWorker"] = session.get("workerSessionId")
        _put_session(session)
        _apply_recording_policy(session, route)
        log.info(
            f"NOTIFY/INBOUND: session={session_id} worker={session.get('workerSessionId')} "
            f"call_id={call_id} to_tag={to_tag} webrtc_offer_bytes={len(webrtc_offer)} "
            f"record={bool(session.get('callRecordingEnabled') or (session.get('route') or {}).get('callRecordingEnabled'))} "
            f"did={_recording_did(session) or '-'} → push wake"
        )

    session["inboundSbcInviteSdp"] = offer_sdp
    _remember_inbound_peer(session, call)
    _arm_inbound_sip_cancel_watch(session)
    # Must stay inside on_invite until 200. Returning after 180 drops siphon's
    # live B2BUA Call; later call.answer() hits "no live B2BUA call" (internal
    # UUID) and Cellact never gets 200. stall watchdog is off (0).
    # Do NOT NG-answer pc1 during 180 — ICE-up / DTLS-dead, then remint kills it.
    await _finish_inbound_uas(
        session,
        call=call,
        call_id=call_id,
        from_tag=from_tag,
        offer_sdp=offer_sdp,
        ng_profile=ng_profile,
        webrtc_offer=webrtc_offer,
        to_tag=to_tag,
        contact_host=contact_host,
        session_id=session_id,
        refer_transfer=refer_transfer,
        sip_bye_id=sip_bye_id,
        old_openai_ng=old_openai_ng,
        product_xfer=product_xfer,
    )


async def _handle_callee_answer(
    session: dict[str, Any],
    sdp: str,
    candidates: Optional[list] = None,
    *,
    from_id: str = "",
    to_id: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """DC-only HTTP answer for a ring seat — does not pick the winner."""
    caller = identity.identity_label(session.get("from") or "")
    from_label = identity.identity_label(from_id)
    fut = session.get("pc1RingAnswerFut")
    if (
        fut is not None
        and not fut.done()
        and from_label
        and caller
        and from_label == caller
        and sdp.strip()
    ):
        note_dc_peer_alive(session, from_id)
        webrtc_pc._resolve_future(fut, sdp)
        log.info(
            f"NOTIFY/WEBRTC: HTTP answer completes PC1 RING "
            f"from={from_id!r} session={session.get('sessionId')}"
        )
        return {
            "ok": True,
            "sessionId": session["sessionId"],
            "type": "answer",
            "handled": True,
            "leg": "pc1",
        }
    leg = _ring_leg_for(
        session, from_id=from_id, to_id=to_id, session_id=str(session_id or "")
    )
    if leg is None and session.get("ringLegs"):
        log.info(
            f"NOTIFY/WEBRTC: HTTP answer no ring leg from={from_id!r} "
            f"to={to_id!r} sessionId={session_id!r}"
        )
        return {
            "ok": True,
            "ignored": True,
            "reason": "unknown-leg",
            "sessionId": session["sessionId"],
            "type": "answer",
        }
    if leg is not None:
        if getattr(leg, "cancelled", False) and getattr(leg, "callerEndDumped", False):
            log.info(
                f"NOTIFY/WEBRTC: ignore HTTP answer on cancelled leg "
                f"from={from_id!r} session={session.get('sessionId')}"
            )
            return {
                "ok": True,
                "ignored": True,
                "reason": "leg-cancelled",
                "sessionId": session["sessionId"],
                "type": "answer",
                "leg": leg.ident,
            }
        if getattr(leg, "_drive_started", False):
            return {
                "ok": True,
                "ignored": True,
                "reason": "leg-already-driving",
                "sessionId": session["sessionId"],
                "type": "answer",
                "leg": leg.ident,
            }
        leg._drive_started = True
        sess_loop = session.get("eventLoop")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if sess_loop is not None and running is not sess_loop:
            log.info(
                f"NOTIFY/WEBRTC: hop ring drive onto session loop "
                f"leg={leg.ident} session={session.get('sessionId')}"
            )
        leg.drive_task = _start_task_on_session_loop(
            session, leg.drive(sdp, candidates or [], _remaining_ring_timeout_secs(session))
        )
        return {
            "ok": True,
            "sessionId": session["sessionId"],
            "type": "answer",
            "handled": True,
            "leg": leg.ident,
        }
    if session.get("calleeAnsweredOnce"):
        log.info(
            f"NOTIFY/WEBRTC: ignore late answer session={session.get('sessionId')} "
            f"from={from_id!r} winner={session.get('multiringWinner')!r}"
        )
        return {
            "ok": True,
            "ignored": True,
            "reason": "answered-elsewhere",
            "sessionId": session["sessionId"],
            "type": "answer",
        }
    session["calleeAnsweredOnce"] = True
    session["calleeAnswerSdp"] = sdp
    session["calleeAnswerCandidates"] = candidates or []
    if from_id:
        session["multiringWinner"] = from_id
    event = session.get("answerEvent")
    if event is not None:
        event.set()
    return {
        "ok": True,
        "sessionId": session["sessionId"],
        "type": "answer",
        "handled": True,
        "winner": session.get("multiringWinner"),
    }


def _same_outbound_party(session: dict[str, Any], from_id: str, to_id: str) -> bool:
    caller = identity.identity_label(session.get("from") or "")
    if caller != identity.identity_label(from_id):
        return False
    dest = identity.identity_label(to_id)
    dialed = identity.identity_label(session.get("dialedTo") or "")
    if dialed and dest and dialed == dest:
        return True
    return str(session.get("sessionId") or "") == _stable_key(from_id, to_id)


def _http_offer_can_reuse(
    prior: dict[str, Any], from_id: str, to_id: str, route: dict[str, Any], offer_sdp: str = ""
) -> bool:
    """Reuse the live PC only if this HTTP is the same ICE identity + DC still open.

    New client PC (new ufrag) after hangup → close + handshake. Same ufrag on
    open pc1 DC → apply SDP on that PC (Node onExistingPairOffer).
    """
    if not prior or not prior.get("mediaWorker"):
        return False
    if str(route.get("route") or "") not in ("webrtc", "webrtc-multiring", "sbc"):
        return False
    from_label = identity.identity_label(from_id)
    caller = identity.identity_label(prior.get("from") or "")
    if not from_label or from_label != caller:
        return False
    if not prior.get("dcOpen"):
        return False
    new_u, _pwd = webrtc_pc._sdp_ice_ufrag_pwd(offer_sdp)
    old_u = str(prior.get("pc1RemoteUfrag") or "")
    if not new_u or not old_u:
        return False
    return new_u == old_u


async def _reset_webrtc_session_for_redial(
    session: dict[str, Any],
    *,
    route: dict[str, Any],
    to_id: str,
    payload: dict[str, Any],
    logic_sp: str,
) -> None:
    """Keep callee DCs; bump ring gen so the previous hunt doesn't cancel them."""
    session["ringGeneration"] = int(session.get("ringGeneration") or 0) + 1
    ev = session.get("pickupEvent")
    if ev is not None:
        try:
            ev.set()
        except Exception:  # noqa: BLE001
            pass
    for leg in list((session.get("ringLegs") or {}).values()):
        task = getattr(leg, "drive_task", None)
        if task is not None and not task.done():
            try:
                task.cancel()
            except Exception:  # noqa: BLE001
                pass
    if session.get("mediaBridged") or session.get("mediaWorker"):
        try:
            import webrtc_pc_worker as wkr

            await wkr.unbridge_media(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: redial unbridge failed: {exc}")
        _schedule_recording_upload(session)
    _reset_recording_state(session)
    await _close_outgoing_minutes(session)
    session["route"] = route
    session["productKind"] = route.get("productKind")
    session["to"] = to_id
    session["dialedTo"] = to_id
    _apply_recording_policy(session, route)
    session["logicSp"] = route.get("logicSp") or logic_sp
    if logic_sp:
        session["callerLogicSp"] = str(logic_sp)
    session["serviceId"] = route.get("logicSp") or logic_sp or session.get("serviceId")
    session["callNonce"] = payload.get("callNonce")
    session["xdata"] = payload.get("xdata") or payload.get("x-data")
    session["xsign"] = payload.get("xsign") or payload.get("x-sign")
    session["clientEnded"] = False
    session["failureNotified"] = False
    session["dtmfCount"] = 0
    session["dtmfLog"] = []
    session["transferLog"] = []
    session["ivrTransferArmed"] = False
    session.pop("voicemailActive", None)
    session.pop("declinedBeforePickup", None)
    session.pop("voicemailSbcPreAnswered", None)
    session.pop("sbcHairpinAnswered", None)
    session.pop("ringStartedAt", None)
    session.pop("recordingKind", None)
    session.pop("voicemailHeaders", None)
    session.pop("voicemailMediaCallId", None)
    session.pop("voicemailFromTag", None)
    session["ringCancelSent"] = False
    session["declinedBeforePickup"] = False
    session["calleeAnsweredOnce"] = False
    session["multiringWinner"] = None
    session["pcCallee"] = None
    session["pc2"] = None
    session["httpReused"] = True
    session["blockRingReuse"] = False
    session["softEnded"] = False
    _bind_session_aliases(session)
    log.info(
        f"NOTIFY: redial reuse session={session.get('sessionId')} "
        f"worker={session.get('workerSessionId')} dest={to_id!r} "
        f"legs={list((session.get('ringLegs') or {}).keys())}"
    )


async def _try_inbound_callee_http_offer(
    payload: dict[str, Any],
    *,
    from_id: str,
    to_id: str,
    session_id: Any,
    signaling_sid: str,
    sdp: str,
) -> Optional[dict[str, Any]]:
    """Callee HTTP offer on an existing ring PC — only if the client marked ICE restart.

    iOS sendCall / Android sendCallNotification never set iceRestart (new invite).
    Android ICE restart sets iceRestart=true and must not /auth.
    """
    raw = payload.get("iceRestart")
    if raw is True:
        pass
    elif isinstance(raw, str) and raw.strip().lower() in ("true", "1", "yes"):
        pass
    else:
        return None
    session, _why = _select_attempt(
        from_id, to_id, str(session_id or ""), payload, role="answer"
    )
    if session is None:
        session, _why = _select_attempt(
            to_id, from_id, str(session_id or ""), payload, role="answer"
        )
    if not session or not session.get("ringLegs"):
        return None
    if session.get("routeKind") not in ("inbound", "webrtc"):
        return None
    caller = identity.identity_label(session.get("from") or "")
    from_label = identity.identity_label(from_id)
    if caller and from_label and caller == from_label:
        return None
    leg = _ring_leg_for(
        session,
        from_id=from_id,
        to_id=to_id,
        session_id=str(signaling_sid or ""),
    )
    if leg is None:
        log.info(
            f"NOTIFY: inbound HTTP offer no ring leg from={from_id!r} "
            f"to={to_id!r} sessionId={signaling_sid!r} "
            f"legs={list((session.get('ringLegs') or {}).keys())}"
        )
        return None
    if not sdp:
        return {"error": "Missing sdp on inbound offer", "ok": False}
    log.info(
        f"NOTIFY: inbound HTTP offer (ICE restart/glare) from={from_id!r} "
        f"to={to_id!r} leg={leg.ident} session={session.get('sessionId')} "
        f"sdp_len={len(sdp)}"
    )
    result = await _await_on_session_loop(
        session,
        leg.apply_http_offer(sdp, payload.get("candidates") or []),
    )
    return {
        "type": "answer",
        "from": to_id,
        "to": from_id,
        "sessionId": signaling_sid or session["sessionId"],
        "sdp": result.get("sdp") or "",
        "candidates": result.get("candidates") or [],
        "ok": True,
        "handled": "inbound-http-offer",
        "leg": leg.ident,
    }


def _sbc_call_established(session: dict[str, Any]) -> bool:
    """True once B-leg 200 was processed — hangup must be BYE, not CANCEL."""
    if session.get("voicemailActive") and str(session.get("routeKind") or "") == "inbound":
        return bool(
            session.get("sbcHairpinAnswered")
            or session.get("pc2Connected")
            or session.get("mediaBridged")
        )
    if session.get("sbcAnswered"):
        return True
    state = str(session.get("state") or "")
    if state in ("answered", "sbc-answered"):
        return True
    return bool(session.get("pc2Connected") or session.get("mediaBridged"))


async def _bye_sbc_hairpin(session: dict[str, Any]) -> bool:
    """BYE the hairpin A-leg. The B2BUA then BYEs the carrier.

    b2bua.terminate returns true when this Call-ID is not one of its dialogs,
    and the carrier stays up. The ACK already proved which From/To match.
    """
    from_hdr = str(session.get("hairpinAckFrom") or "").strip()
    to_hdr = str(session.get("hairpinAckTo") or "").strip()
    call_id = str(session.get("hairpinAckCallId") or "").strip()
    if not from_hdr or not to_hdr or not call_id:
        return False
    domain = policy.local_domain()
    bind_ip = policy.local_bind_ip()
    ruri = str(session.get("hairpinRuri") or f"sip:{SBC_HAIRPIN_USER}@{domain}")
    next_hop = str(session.get("hairpinNextHop") or f"sip:{bind_ip}:5060;transport=tcp")
    log.info(f"NOTIFY/SBC: BYE hairpin {ruri} call_id={call_id}")
    await proxy.send_request(
        "BYE",
        ruri,
        headers={
            "From": from_hdr,
            "To": to_hdr,
            "Call-ID": call_id,
            "CSeq": "2 BYE",
            "Max-Forwards": "70",
        },
        next_hop=next_hop,
        wait_for_response=False,
    )
    return True


async def _cancel_pending_sbc(session: dict[str, Any]) -> None:
    """End hairpin SBC leg: CANCEL if early, BYE (b2bua.terminate) if answered."""
    ingress_id = str(session.get("sbcHairpinId") or "")
    if ingress_id:
        fail_sbc_hairpin(ingress_id, "cancelled")

    call_id = str(
        session.get("voicemailMediaCallId") or session.get("mediaCallId") or ""
    ).strip()
    from_tag = str(
        session.get("voicemailFromTag") or session.get("fromTag") or ""
    ).strip()
    from_user = str(session.get("sbcFromUser") or "").strip()
    from_host = str(session.get("sbcFromHost") or policy.local_domain()).strip()
    to_uri = str(session.get("hairpinToUri") or "").strip()
    ruri = str(session.get("hairpinRuri") or "").strip()
    next_hop = str(session.get("hairpinNextHop") or "").strip()
    established = _sbc_call_established(session)

    if established:
        # Post-200: CANCEL is illegal / ignored by SBC — callee stays up.
        # b2bua.terminate sends BYE to A-leg + B-leg (callee).
        try:
            from siphon import b2bua as _b2bua

            terminate = getattr(_b2bua, "terminate", None)
            if callable(terminate) and call_id:
                ok = terminate(call_id, "Normal Clearing")
                log.info(
                    f"NOTIFY/SBC: BYE via b2bua.terminate call_id={call_id} ok={ok}"
                )
                if ok and not session.get("hairpinAckCallId"):
                    return
                if not ok:
                    log.warn(
                        f"NOTIFY/SBC: b2bua.terminate returned False call_id={call_id} "
                        "— callee may still be up"
                    )
            else:
                log.warn(
                    f"NOTIFY/SBC: cannot BYE — terminate="
                    f"{callable(terminate)} call_id={call_id!r}"
                )
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: B2BUA terminate (BYE) failed: {exc}")
        try:
            await _bye_sbc_hairpin(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/SBC: hairpin BYE failed call_id={call_id}: {exc}")
        return

    # Pre-answer: CANCEL A-leg so B2BUA drops the B-leg.
    if call_id and from_tag and from_user and ruri:
        try:
            log.info(
                f"NOTIFY/SBC: CANCEL hairpin call_id={call_id} ruri={ruri} "
                f"next_hop={next_hop or 'default'}"
            )
            headers = {
                "From": f"<sip:{from_user}@{from_host}>;tag={from_tag}",
                "To": f"<{to_uri}>" if to_uri else f"<{ruri}>",
                "Call-ID": call_id,
                "CSeq": "1 CANCEL",
                "Max-Forwards": "70",
            }
            kwargs: dict[str, Any] = {
                "headers": headers,
                "wait_for_response": False,
            }
            if next_hop:
                kwargs["next_hop"] = next_hop
            await proxy.send_request("CANCEL", ruri, **kwargs)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/SBC: CANCEL hairpin failed: {exc}")

    try:
        from siphon import b2bua as _b2bua

        terminate = getattr(_b2bua, "terminate", None)
        if callable(terminate) and call_id:
            ok = terminate(call_id, "cancelled")
            log.info(f"NOTIFY/SBC: b2bua.terminate call_id={call_id} ok={ok}")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: B2BUA terminate failed: {exc}")


async def _soft_end_call(
    session: dict[str, Any],
    reason: str = "hangup",
    *,
    client_ended: bool = False,
    ended_leg: str = "pc1",
    send_ui_end: bool = True,
    offer_legs: Optional[tuple[str, ...]] = None,
    inbound_reject_code: int = 487,
) -> dict[str, Any]:
    """Node soft end: hard SIP BYE/CANCEL, inactive WebRTC reneg, keep PC/DC.

    Session stays in `_sessions` for DC RING reuse on the same PC.
    A new HTTP `/notify` offer with a different ICE ufrag closes PCs and
    starts a new call; same ufrag + open DC applies on the live PC.
    """
    session_id = str(session.get("sessionId") or "")
    if session.get("softEndInProgress"):
        return {"ok": True, "ignored": True, "sessionId": session_id, "type": "soft-end"}
    session["softEndInProgress"] = True
    _finish_outgoing_minutes(session)
    session["dcRingStarted"] = False
    webrtc_pc.clear_glare_offers(session)
    offered = False
    legs_to_offer: list[str] = []
    try:
        if client_ended:
            session["clientEnded"] = True
        log.info(
            f"NOTIFY: soft-end begin session={session_id} reason={reason} "
            f"client_ended={client_ended} ended_leg={ended_leg} "
            f"routeKind={session.get('routeKind')}"
        )

        event = session.get("answerEvent")
        if event is not None:
            try:
                event.set()
            except Exception:  # noqa: BLE001
                pass
        pickup = session.get("pickupEvent")
        if pickup is not None:
            try:
                pickup.set()
            except Exception:  # noqa: BLE001
                pass
        resume = session.get("huntResumeEvent")
        if resume is not None:
            try:
                resume.set()
            except Exception:  # noqa: BLE001
                pass
        _hunt_end_session(session)
        ingress_id = str(session.get("sbcHairpinId") or "")
        if ingress_id:
            fail_sbc_hairpin(ingress_id, reason)
            _pop_hairpin_ng_keys(ingress_id)

        # Hard SIP first (dialog cannot soft-reuse).
        route_kind = str(session.get("routeKind") or "")
        if route_kind == "sbc" or session.get("voicemailMediaCallId"):
            try:
                await _cancel_pending_sbc(session)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY: soft-end cancel SBC failed session={session_id}: {exc}")
        if route_kind == "inbound":
            try:
                _reject_inbound_sip(
                    session,
                    int(inbound_reject_code),
                    "Temporarily Unavailable" if int(inbound_reject_code) == 480 else "Request Terminated",
                )
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY: soft-end inbound reject failed session={session_id}: {exc}")

        # unbridge pops activeCallId. CallKit only ends on that same id.
        saved_call_id = session.get("activeCallId")
        # Drop media bridge / rtpengine; keep WebRTC transports.
        try:
            await webrtc_pc.unbridge_media(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: soft-end unbridge failed session={session_id}: {exc}")
        _schedule_recording_upload(session)
        if session.get("sbcNgOwned") or route_kind in ("sbc", "webrtc", "inbound"):
            try:
                _delete_session_rtpengine(session, session_id)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY: soft-end rtpengine delete failed session={session_id}: {exc}")
        session["sbcNgOwned"] = False
        session["sbcAnswered"] = False
        session["inboundSipAnswered"] = False
        if route_kind == "inbound":
            try:
                await webrtc_pc.close_inbound_sip_pc(session)
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY: soft-end close inbound pc1 failed session={session_id}: {exc}"
                )

        if isinstance(saved_call_id, int) and saved_call_id > 0:
            session["activeCallId"] = saved_call_id

        def _dc_open(leg: str) -> bool:
            # readyState, not just dcOpen — inbound DC can already be open
            # so the 'open' event never fires and the flag stays False.
            return webrtc_pc._leg_dc_open(session, leg)

        # WebRTC soft-end: do not re-offer the leg that already drove the end;
        # initiate inactive reneg toward the other live WebRTC DC(s).
        if offer_legs is not None:
            for leg in offer_legs:
                if _dc_open(leg):
                    legs_to_offer.append(leg)
        elif client_ended:
            peer = "callee" if ended_leg == "pc1" else "pc1"
            if _dc_open(peer):
                legs_to_offer.append(peer)
        else:
            for leg in ("pc1", "callee"):
                if _dc_open(leg):
                    legs_to_offer.append(leg)

        for leg in legs_to_offer:
            # call/end first: iOS CallKit + Android legacy UI. Then inactive
            # signaling/end-call so Android matches callId and both tear media.
            try:
                webrtc_pc.send_leg_ui_hangup(session, leg=leg, reason=reason)
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY: soft-end UI hangup failed session={session_id} "
                    f"leg={leg}: {exc}"
                )
            try:
                ok = await webrtc_pc.initiate_end_call_offer(
                    session, leg=leg, reason=reason
                )
                offered = offered or ok
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY: soft-end initiate end-call failed session={session_id} "
                    f"leg={leg}: {exc}"
                )

        if ended_leg == "pc1":
            try:
                await _forward_cancel_to_ringing(session, reason=reason)
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY: forward cancel to ringing failed "
                    f"session={session_id}: {exc}"
                )
        elif ended_leg == "callee" and session.get("bLegCallerLeg"):
            b_caller_leg = str(session.get("bLegCallerLeg") or "")
            b_ident = str(session.get("bLegCallerIdent") or session.get("from") or "")
            try:
                import webrtc_pc_worker as wkr

                b_call_id = (
                    webrtc_pc._normalize_call_id(
                        session.get(f"ringCallId:{b_ident}")
                    )
                    or saved_call_id
                    or webrtc_pc._ensure_session_call_id(session)
                )
                await wkr.hangup_loser_leg(
                    session,
                    ident=b_ident,
                    worker_leg=b_caller_leg,
                    call_id=b_call_id,
                    reason=reason,
                )
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY: soft-end hangup bLegCallerLeg ({b_caller_leg}) "
                    f"failed session={session_id}: {exc}"
                )

        if (
            send_ui_end
            and not client_ended
            and not legs_to_offer
            and not session.get("endCallSent")
            and (_dc_open("pc1") or _dc_open("callee"))
        ):
            try:
                _signal_dc_end(session, reason)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY: soft-end UI end-call failed session={session_id}: {exc}")

        session.pop("bLegCallerLeg", None)
        session.pop("bLegCallerPc", None)
        session.pop("bLegCallerDc", None)
        session.pop("bLegCallerIdent", None)
        session.pop("bLegCallerConnected", None)
        session["pc1TransferredOut"] = False
        webrtc_pc.reset_soft_end_for_reuse(session)
        # Keep session registered — do not _pop_session / close PCs.
        log.info(
            f"NOTIFY: soft-end done session={session_id} offered={offered} "
            f"legs={legs_to_offer} dcOpen={bool(session.get('dcOpen'))} "
            f"calleeDcOpen={bool(session.get('calleeDcOpen'))}"
        )
        return {
            "ok": True,
            "type": "soft-end",
            "sessionId": session_id,
            "offered": offered,
            "legs": legs_to_offer,
        }
    finally:
        session["softEndInProgress"] = False
        session["_grokPosted"] = time.time()
        _schedule_grok_call(
            session,
            reason,
            ended_leg=ended_leg,
            client_ended=client_ended,
            reject_code=int(inbound_reject_code or 0),
        )


async def _on_dc_end(
    session: dict[str, Any],
    reason: Any = "hangup",
    *,
    ended_leg: str = "pc1",
) -> None:
    """Client ended over DC — soft end (Node end-call ingress), keep DC for reuse."""
    session_id = str(session.get("sessionId") or "")
    if isinstance(reason, dict):
        reason_s = str(reason.get("reason") or reason.get("action") or "hangup")
    else:
        reason_s = str(reason or "hangup")
    if ended_leg == "callee" and (
        session.get("voicemailActive")
        or (
            not session.get("calleeAnsweredOnce")
            and not session.get("multiringWinner")
        )
    ):
        log.info(
            f"NOTIFY: ignore callee DC end on unanswered/voicemail session={session_id} "
            f"reason={reason_s}"
        )
        return
    session["clientEnded"] = True
    log.info(
        f"NOTIFY: DC end session={session_id} reason={reason_s} ended_leg={ended_leg}"
    )
    # Prefer soft keep when a DC is still up; hard teardown if transport already gone.
    has_dc = bool(session.get("dcOpen") or session.get("calleeDcOpen"))
    if not has_dc and session.get("pc") is None and session.get("pcCallee") is None:
        await _teardown(_storage_key(session) or session_id, cancel_sip=True, client_ended=True)
        return
    try:
        await _soft_end_call(
            session,
            reason_s,
            client_ended=True,
            ended_leg=ended_leg,
            send_ui_end=False,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: soft-end failed → hard teardown session={session_id}: {exc}")
        await _teardown(_storage_key(session) or session_id, cancel_sip=True, client_ended=True)


async def _on_dc_ring(session: dict[str, Any], payload: dict[str, Any]) -> None:
    """DC RING — Node poly path: ackConnected → hold PC1 answer → dial → flush."""
    session_id = session.get("sessionId") or "?"
    offer_sdp = _body_text(payload.get("sdp"))
    route = session.get("route") or {}
    route_kind = str(route.get("route") or "")
    incoming_nonce = str(payload.get("callNonce") or "")
    # Soft-ended session: this RING is a new call; the old call's ids stop naming it.
    fresh_call = bool(session.get("softEnded"))
    if incoming_nonce or fresh_call:
        _set_call_nonce(session, incoming_nonce, fresh=fresh_call)
    ring_ids = _offer_ids(payload, offer_sdp)
    _remember_attempt_ids(session, call_id=ring_ids["call_id"], ufrag=ring_ids["ufrag"])
    reuse = bool(session.get("softEnded") or session.get("httpReused"))
    glare_sender = str(session.get("from") or "")
    webrtc_pc.note_glare_offer(
        session,
        glare_sender,
        offer_sdp,
        leg="pc1",
        call_id=webrtc_pc._normalize_call_id(payload.get("callId")),
    )
    log.info(
        f"NOTIFY: DC RING session={session_id} route={route_kind} "
        f"sdp_len={len(offer_sdp)} has_audio={_sdp_has_audio(offer_sdp)} "
        f"reuse={reuse}"
    )
    if not offer_sdp:
        raise RuntimeError("DC RING missing sdp")
    _log_sdp(f"NOTIFY: DC RING SDP in session={session_id}", offer_sdp)
    if route_kind == "sbc" and _sdp_ios_split_leftover_audio(offer_sdp):
        log.info(
            f"NOTIFY: DC RING skip iOS split leftover session={session_id} "
            f"(would re-INVITE PSTN)"
        )
        return

    # Node ackConnected: ACK immediately, wait ENDING, then dial. Never drop
    # a pc1 sendrecv RING on a leftover timer.
    try:
        n = webrtc_pc._normalize_call_id(payload.get("callId"))
        if n is not None and not webrtc_pc._other_seat_ring_id(session, "pc1", n):
            session["legCallId:pc1"] = n
            session["activeCallId"] = n
        webrtc_pc.send_dc_ack_ring(session)
        session["ringAckSent"] = True
        log.info(f"NOTIFY: DC RING ack sent session={session_id}")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: DC RING ack failed session={session_id}: {exc}")
    ring_id = uuid.uuid4().hex
    session["activePc1RingId"] = ring_id
    # This RING is the caller abandoning our unanswered end-call. iOS answers
    # the other leg's end-call in a few hundred ms; Android never does. Wait
    # the 1s cap so an iOS answer is not applied to this RING, then dial.
    # A missing answer does not cancel the redial.
    if session.get("endingAwaitAnswerPc1"):
        session["endingAwaitAnswerPc1"] = False
        log.info(
            f"PC1: new RING replaces unanswered end-call session={session_id}"
        )
    try:
        await webrtc_pc.wait_until_callee_rungable(session, 1.0)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: DC RING ENDING wait failed session={session_id}: {exc}")
    if session.get("activePc1RingId") != ring_id:
        log.info(f"NOTIFY: DC RING superseded session={session_id}")
        return
    if session.get("glareRetired"):
        log.info(f"NOTIFY: DC RING dropped (pair connected elsewhere) session={session_id}")
        return
    if session.get("cancelledPc1RingId") == ring_id:
        log.info(
            f"NOTIFY: DC RING aborted (caller cancelled) session={session_id}"
        )
        return
    if webrtc_pc._callee_ending(session):
        log.info(
            f"NOTIFY: DC RING dials, end-call unanswered session={session_id}"
        )

    # Fresh call presentation on reused DC (Node: new callId, new SIP dialog ids).
    session["softEnded"] = False
    session["clientEnded"] = False
    session["softEndInProgress"] = False
    session["failureNotified"] = False
    session["failureCleanupDone"] = False
    session["endCallSent"] = False
    session["httpReused"] = False
    session["ivrTransferArmed"] = False
    session["dtmfCount"] = 0
    session["dtmfLog"] = []
    session["endingAwaitAnswerPc1"] = False
    session["endingAwaitAnswerCallee"] = False
    session["endCallRenegotiating"] = False
    session.pop("voicemailActive", None)
    session.pop("declinedBeforePickup", None)
    session.pop("voicemailSbcPreAnswered", None)
    session.pop("sbcHairpinAnswered", None)
    session.pop("ringStartedAt", None)
    session.pop("recordingKind", None)
    session.pop("voicemailHeaders", None)
    session.pop("voicemailMediaCallId", None)
    session.pop("voicemailFromTag", None)
    _reset_recording_state(session)
    origin_route = session.get("originRoute")
    origin_to = str(session.get("originTo") or "")
    if reuse and isinstance(origin_route, dict) and origin_to:
        session["route"] = json.loads(json.dumps(origin_route))
        session["to"] = origin_to
        session["dialedTo"] = origin_to
        session["productKind"] = origin_route.get("productKind")
        route = session["route"] or {}
        route_kind = str(route.get("route") or "")
        log.info(
            f"NOTIFY: DC RING restore origin to={origin_to!r} "
            f"route={route_kind} session={session_id}"
        )
    if not await webrtc_pc.glare_keep(session, glare_sender):
        session["activePc1RingId"] = None
        return
    loser = webrtc_pc.glare_loser(session, glare_sender)
    if loser is not None and loser[0] == "callee":
        await webrtc_pc.hangup_glare_loser(session, loser[0], loser[1])
        session["skipCalleeDcReuse"] = True

    # Force remint of blank audio on existing mid (soft end nulled track keys).
    session["localAudioTrack"] = None
    session["pc2LocalTrack"] = None
    # New rtpengine / SIP Call-ID for redial after soft end deleted prior media.
    if route_kind in ("sbc", "webrtc", "webrtc-multiring") or session.get("routeKind") in (
        "sbc",
        "webrtc",
        "webrtc-multiring",
    ):
        session["mediaCallId"] = f"{uuid.uuid4().hex}@{policy.local_domain()}"
        session["fromTag"] = uuid.uuid4().hex[:8]
        session["toTag"] = uuid.uuid4().hex[:8]
        session["sbcNgOwned"] = False
        session["sbcAnswered"] = False
        session["sbcHairpinId"] = None

    session["state"] = "dc-ring"

    try:
        if route_kind == "sbc":
            await webrtc_pc.prepare_ring_answer(
                session,
                offer_sdp,
                payload.get("candidates") or [],
            )
            await _dial_sbc(session, offer_sdp)
            answer_sdp = webrtc_pc.flush_held_ring_answer(session)
            # Client applies answer then starts RTP — give it a beat, then bridge once.
            try:
                await asyncio.sleep(0.15)
                await webrtc_pc.rebridge_media(session)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY: post-flush rebridge failed: {exc}")
        elif route_kind in ("webrtc", "webrtc-multiring"):
            # Node WebRtcNegotiation.applyOffer: hold caller RING answer until
            # PolySession.answer() (peer picked up). iOS treats that SDP as
            # callAcceptedBy + audioCapability.enable — flushing early makes
            # the caller UI go in-call while 408 is still ringing.
            await webrtc_pc.prepare_ring_answer(
                session,
                offer_sdp,
                payload.get("candidates") or [],
            )
            try:
                await _execute_webrtc(session, offer_sdp)
            except RuntimeError as ring_exc:
                if any(
                    k in str(ring_exc)
                    for k in ("Callee answer timeout", "Callee declined")
                ):
                    if not await _connect_no_answer_voicemail(session, offer_sdp):
                        raise
                else:
                    raise
            answer_sdp = webrtc_pc.flush_held_ring_answer(session)
            try:
                await asyncio.sleep(0.15)
                await webrtc_pc.rebridge_media(session)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY: webrtc post-flush rebridge failed: {exc}")
        else:
            raise RuntimeError(f"DC RING unhandled route: {route_kind}")
    except Exception as exc:
        session["dcRingStarted"] = False
        # Single path: hang up caller unless they already ended.
        if session.get("clientEnded") or session.get("failureNotified"):
            log.info(f"NOTIFY: DC RING aborted session={session_id}: {exc}")
            return
        await fail_notify_call(
            exc,
            session=session,
            ingress_id=str(session.get("sbcHairpinId") or ""),
            cancel_sip=True,
        )
        return

    log.info(f"NOTIFY: DC RING complete session={session_id} answer_bytes={len(answer_sdp)}")


async def _teardown_body(
    session: dict[str, Any],
    *,
    cancel_sip: bool = False,
    client_ended: bool = False,
    close_webrtc: bool = True,
) -> None:
    session_id = str(session.get("sessionId") or "")
    if client_ended:
        session["clientEnded"] = True
    event = session.get("answerEvent")
    if event is not None:
        event.set()
    resume = session.get("huntResumeEvent")
    if resume is not None:
        try:
            resume.set()
        except Exception:  # noqa: BLE001
            pass
    _hunt_end_session(session)
    ingress_id = str(session.get("sbcHairpinId") or "")
    if ingress_id:
        _pop_hairpin_ng_keys(ingress_id)
    if cancel_sip and (session.get("routeKind") == "sbc" or session.get("voicemailMediaCallId")):
        try:
            await _cancel_pending_sbc(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: cancel pending SBC failed: {exc}")
    if cancel_sip and session.get("routeKind") == "inbound":
        try:
            _reject_inbound_sip(session, 487, "Request Terminated")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: cancel inbound SIP failed: {exc}")
    if session.get("mediaBridged"):
        try:
            await webrtc_pc.unbridge_media(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: teardown unbridge failed session={session_id}: {exc}")
    _schedule_recording_upload(session)
    if close_webrtc:
        try:
            await webrtc_pc.close(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: teardown close failed session={session_id}: {exc}")
    shared_a_leg = bool(session.get("referTransfer") or session.get("referCall"))
    if shared_a_leg:
        log.info(
            f"NOTIFY: teardown skip rtpengine delete session={session_id} "
            "(A-leg still on OpenAI)"
        )
    elif session.get("sbcNgOwned") or session.get("routeKind") in ("sbc", "webrtc", "inbound"):
        _delete_session_rtpengine(session, session_id)


async def _teardown(
    session_id: str,
    *,
    cancel_sip: bool = False,
    client_ended: bool = False,
) -> dict[str, Any]:
    session = _pop_session(session_id)
    if not session:
        return {"ok": True, "ignored": True, "sessionId": session_id}
    await _teardown_body(session, cancel_sip=cancel_sip, client_ended=client_ended)
    wire = str(session.get("sessionId") or session_id)
    return {"ok": True, "type": "teardown", "sessionId": wire}


def register_product_session(
    *,
    call_id: str,
    from_id: str,
    to_id: str,
    route: Optional[dict[str, Any]] = None,
    sip_call: Any = None,
    invite_sdp: str = "",
    from_tag: str = "",
) -> dict[str, Any]:
    """SIP product legs (OpenAI/IVR) so DTMF/DC can hit /action."""
    sid = str(call_id or "").strip() or _stable_key(from_id, to_id)
    route = dict(route or {})
    kind = str(route.get("productKind") or route.get("route") or "external-sip")
    session = {
        "sessionId": sid,
        "from": from_id,
        "to": to_id,
        "route": route,
        "routeKind": kind,
        "productKind": kind,
        "mediaCallId": sid,
        "sipCall": sip_call,
        "logicSp": str(route.get("logicSp") or "").strip().lower(),
        "inviteSdp": str(invite_sdp or ""),
        "fromTag": str(from_tag or ""),
        "state": "product",
        "createdAt": time.time(),
        "on_dc_action": _on_dc_action,
        "on_dc_end": _on_dc_end,
        "dtmfCount": 0,
        "dtmfLog": [],
        "transferLog": [],
    }
    if sip_call is not None:
        _remember_inbound_peer(session, sip_call)
    _apply_recording_policy(session, route)
    try:
        session["eventLoop"] = asyncio.get_running_loop()
        pin_event_loop(session["eventLoop"])
    except RuntimeError:
        pass
    _put_session(session)
    did = str(to_id or "").strip()
    if did and session["inviteSdp"]:
        with _sessions_lock:
            _xfer_did_index[did] = sid
        log.info(
            f"XFER: stored PSTN invite sdp_bytes={len(session['inviteSdp'])} "
            f"did={did} a_leg={sid} from={from_id}"
        )
    return session


def lookup_xfer_invite(call_id: str = "", *users: str) -> Optional[dict[str, Any]]:
    """Find the inbound IVR/OpenAI session that owns the original PSTN SDP.

    REFER arrives on the B-leg (b2b-… Call-ID, empty body). The A-leg offer
    was stored on the product session keyed by DID.
    """
    sess = get_session_by_sip_call_id(call_id)
    if sess and sess.get("inviteSdp"):
        return sess
    seen: list[str] = []
    for raw in users:
        user = policy.strip_plus_and_domain_suffix(str(raw or ""))
        if not user or user in seen:
            continue
        seen.append(user)
        with _sessions_lock:
            sid = _xfer_did_index.get(user)
            if sid:
                found = _sessions.get(sid)
                if found and found.get("inviteSdp"):
                    return found
            for found in _sessions.values():
                if found.get("inviteSdp") and found.get("from") == user:
                    return found
    return None


def put_pending_xfer(to_id: str, ctx: dict[str, Any]) -> None:
    did = policy.strip_plus_and_domain_suffix(str(to_id or ""))
    if not did:
        return
    with _sessions_lock:
        _pending_xfer[did] = dict(ctx)
        _pending_xfer[did]["to"] = did
    log.info(
        f"XFER: pending hairpin to={did} a_leg={ctx.get('a_leg') or '-'} "
        f"from={ctx.get('from') or '-'}"
    )


def take_pending_xfer(to_id: str) -> Optional[dict[str, Any]]:
    did = policy.strip_plus_and_domain_suffix(str(to_id or ""))
    if not did:
        return None
    with _sessions_lock:
        return _pending_xfer.pop(did, None)


def peek_pending_xfer(to_id: str) -> Optional[dict[str, Any]]:
    did = policy.strip_plus_and_domain_suffix(str(to_id or ""))
    if not did:
        return None
    with _sessions_lock:
        found = _pending_xfer.get(did)
        return dict(found) if found else None


def note_dtmf_digit(session: dict[str, Any], digit: str, *, window_s: float = 0.4) -> bool:
    """False if this is an RFC 4733 retransmit / rtpengine+worker double hit."""
    key = str(digit or "")
    if not key:
        return False
    now = time.monotonic()
    last = session.get("_dtmfLastPress")
    if isinstance(last, tuple) and last[0] == key and (now - float(last[1])) < window_s:
        return False
    session["_dtmfLastPress"] = (key, now)
    return True


def _dtmf_action_target(decision: dict[str, Any]) -> str:
    ident = str(
        decision.get("notifyIdentity") or decision.get("target") or ""
    ).strip()
    if ident:
        return ident
    targets = decision.get("targets") or []
    if targets and isinstance(targets[0], dict):
        return str(
            targets[0].get("notifyIdentity") or targets[0].get("ensName") or ""
        ).strip()
    return ""


def _note_dtmf_action(session: dict[str, Any], decision: dict[str, Any]) -> None:
    digit = str(decision.get("digit") or "").strip()
    action = str(decision.get("action") or "none").strip().lower() or "none"
    forward_dtmf = bool(decision.get("forwardDtmf")) or action == "forward"
    if not digit and action in ("", "none") and not forward_dtmf:
        return
    session.setdefault("dtmfLog", []).append(
        {
            "digit": digit,
            "dtmfIndex": decision.get("dtmfIndex"),
            "action": action,
            "forwardDtmf": forward_dtmf,
            "reason": str(decision.get("reason") or ""),
            "target": _dtmf_action_target(decision),
        }
    )


def _on_dc_action(session: dict[str, Any], msg: dict[str, Any]) -> None:
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    action_l = str(
        msg.get("action") or payload.get("action") or payload.get("type") or ""
    ).strip().lower()
    if action_l == "transfer" and ("targetId" in msg or "targetId" in payload):
        _schedule_coro(_handle_client_dc_transfer(session, msg))
        return
    if not session_handles_dtmf(session):
        return
    digit = msg.get("digit") or payload.get("digit")
    if digit is not None and not note_dtmf_digit(session, str(digit)):
        log.info(
            f"DTMF: dedupe digit={digit!r} source={msg.get('source') or 'dc'} "
            f"session={session.get('sessionId')}"
        )
        return
    _schedule_coro(_run_product_action(session, msg))


async def _handle_client_dc_transfer(
    session: dict[str, Any], msg: dict[str, Any]
) -> None:
    """Handle client DataChannel call transfer: {"msgType":"call","action":"transfer","targetId":"..."}.

    A (transferor) hangs up with matching callId + inactive SDP offer.
    B (surviving peer) stays connected and places a fresh outgoing call to C (targetId).
    """
    session_id = str(session.get("sessionId") or "")
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    target_id = str(msg.get("targetId") or payload.get("targetId") or "").strip()
    from_leg = "callee" if str(msg.get("_dcLeg") or "") == "callee" else "pc1"

    if from_leg == "callee":
        transferor_id = str(
            msg.get("_dcIdent")
            or session.get("multiringWinner")
            or session.get("to")
            or ""
        ).strip()
        survivor_id = str(session.get("from") or "").strip()
    else:
        transferor_id = str(session.get("from") or "").strip()
        survivor_id = str(
            session.get("multiringWinner") or session.get("to") or ""
        ).strip()

    target_labels = _party_labels(target_id)
    a_labels = _party_labels(transferor_id)
    b_labels = _party_labels(survivor_id)
    if (
        not target_id
        or not target_labels
        or not target_labels.isdisjoint(a_labels | b_labels)
    ):
        log.info(
            f"NOTIFY/TRANSFER: ignore invalid targetId={target_id!r} "
            f"transferor={transferor_id!r} survivor={survivor_id!r} "
            f"session={session_id}"
        )
        return
    if (
        session.get("clientEnded")
        or session.get("softEnded")
        or session.get("clientTransferInProgress")
    ):
        log.info(
            f"NOTIFY/TRANSFER: ignore on ended/transferring session={session_id} "
            f"ended={session.get('clientEnded')} soft={session.get('softEnded')} "
            f"inProgress={session.get('clientTransferInProgress')}"
        )
        return

    session["clientTransferInProgress"] = True
    try:
        if from_leg == "callee":
            call_id = (
                webrtc_pc._normalize_call_id(
                    session.get(f"ringCallId:{transferor_id}")
                )
                or webrtc_pc._ensure_session_call_id(session)
            )
        else:
            call_id = webrtc_pc._ensure_session_call_id(session)

        log.info(
            f"NOTIFY/TRANSFER: start session={session_id} from_leg={from_leg} "
            f"transferor={transferor_id!r} survivor={survivor_id!r} "
            f"target={target_id!r} callId={call_id}"
        )

        # 1. Stop media bridge with A and finalize A's recording segment.
        try:
            await webrtc_pc.unbridge_media(
                session, keep_pc1_audio=(from_leg == "callee")
            )
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"NOTIFY/TRANSFER: unbridge failed session={session_id}: {exc}"
            )
        _schedule_recording_upload(session)
        _reset_recording_state(session)

        # 2. Release A's extension seat occupancy.
        wake = extension_hunt.policy.release_seat(
            session, transferor_id, _sessions
        )
        if wake:
            _wake_hunt_waiters(wake)

        # 3. Hang up A on A's DataChannel with active callId, keeping B alive.
        import webrtc_pc_worker as wkr

        if from_leg == "callee":
            ring_legs = session.get("ringLegs") or {}
            a_leg = ring_legs.get(transferor_id)
            if a_leg is not None:
                a_leg.promoted = False
                a_leg.cancelled = True
                a_leg.callerEndDumped = True
                a_leg.transferredOut = True
                a_worker_leg = str(
                    getattr(a_leg.pc, "leg", "") or f"callee:{transferor_id}"
                )
            else:
                a_worker_leg = str(
                    getattr(session.get("pcCallee"), "leg", "")
                    or f"callee:{transferor_id}"
                )
            session["pcCallee"] = None
            session["pc2"] = None
            session["calleeDataChannel"] = None
            session["calleeDcOpen"] = False
            session["calleeRingAnswered"] = False
            session["pc2Connected"] = False
            session["pc2OfferReady"] = False
            session["multiringWinner"] = None
            await wkr.hangup_loser_leg(
                session,
                ident=transferor_id,
                worker_leg=a_worker_leg,
                call_id=call_id,
                reason="transfer",
            )
        else:
            session["pc1TransferredOut"] = True
            session["pc1Connected"] = False
            ring_legs = session.get("ringLegs") or {}
            b_leg = ring_legs.pop(survivor_id, None)
            if b_leg is not None:
                b_leg.promoted = False
                b_leg.isTransferSurvivor = True
            b_pc = session.get("pcCallee") or (
                getattr(b_leg, "pc", None) if b_leg is not None else None
            )
            b_dc = session.get("calleeDataChannel") or (
                getattr(b_leg, "dc", None) if b_leg is not None else None
            )
            b_worker_leg = str(
                getattr(b_pc, "leg", "") or f"callee:{survivor_id}"
            )
            session["bLegCallerLeg"] = b_worker_leg
            session["bLegCallerPc"] = b_pc
            session["bLegCallerDc"] = b_dc
            session["bLegCallerIdent"] = survivor_id
            session["bLegCallerConnected"] = True
            session["from"] = survivor_id

            session["pcCallee"] = None
            session["pc2"] = None
            session["calleeDataChannel"] = None
            session["calleeDcOpen"] = False
            session["calleeRingAnswered"] = False
            session["pc2Connected"] = False
            session["pc2OfferReady"] = False
            session["multiringWinner"] = None

            await wkr.hangup_loser_leg(
                session,
                ident=transferor_id,
                worker_leg="pc1",
                call_id=call_id,
                reason="transfer",
            )

        # 4. Resolve destination C (targetId) as an outgoing call from B (survivor_id).
        session.setdefault("transferLog", []).append(
            {
                "from": transferor_id,
                "survivor": survivor_id,
                "target": target_id,
                "action": "transfer",
                "reason": "client-dc-transfer",
            }
        )
        is_inbound = (
            str(session.get("routeKind") or "") == "inbound"
            and from_leg == "callee"
        )
        parsed_to = logic_client.parse_address(target_id)
        parsed_from = logic_client.parse_address(survivor_id)
        decision = await logic_client.resolve_destination(
            parsed_to,
            parsed_from,
            origin="sbc" if is_inbound else "client",
            to=target_id,
            from_id=survivor_id,
            session_id=session_id,
            kind="inbound" if is_inbound else "outbound",
            logic_sp=str(session.get("logicSp") or ""),
        )
        route_type = str(decision.get("route") or "").strip().lower()
        log.info(
            f"NOTIFY/TRANSFER: resolved B={survivor_id!r} -> C={target_id!r} "
            f"route={route_type!r} reason={decision.get('reason')!r} "
            f"session={session_id}"
        )

        session["to"] = target_id
        session["dialedTo"] = target_id
        session["route"] = decision
        _apply_recording_policy(session, decision)

        session["ringGeneration"] = int(session.get("ringGeneration") or 0) + 1
        _set_call_nonce(session, fresh=True)
        session["activeCallId"] = None
        session["voicemailActive"] = False
        session["ringStartedAt"] = time.monotonic()
        _bind_session_aliases(session)

        if route_type in ("webrtc", "webrtc-multiring"):
            try:
                await _execute_webrtc(session, "")
            except RuntimeError as ring_exc:
                if any(
                    k in str(ring_exc)
                    for k in ("Callee answer timeout", "Callee declined")
                ):
                    if not await _connect_no_answer_voicemail(session, ""):
                        raise
                else:
                    raise
            await webrtc_pc.rebridge_media(session, force=True)
        elif route_type == "sbc" or logic_client.is_product_route(decision):
            if logic_client.is_product_route(decision):
                target = str(
                    decision.get("target") or decision.get("uri") or ""
                ).strip()
                sip_uri = (
                    target
                    if target.lower().startswith("sip:")
                    else f"sip:{target}"
                )
                parsed = policy.parse_sip_uri(sip_uri)
                uri_user = str((parsed[0] if parsed else "") or "")
                uri_host = str((parsed[1] if parsed else "") or "").split(";")[0]
                is_oai = "sip.api.openai.com" in sip_uri.lower()
                sbc_host = (
                    "sip.api.openai.com"
                    if is_oai
                    else (
                        str(
                            decision.get("sbcAddress")
                            or decision.get("host")
                            or ""
                        ).strip()
                        or str(
                            policy.determine_sbc_for_number(
                                uri_user or target_id,
                                survivor_id,
                                policy.local_domain(),
                            )
                            or ""
                        ).strip()
                        or uri_host
                    )
                )
                decision = dict(decision)
                decision.update(
                    {
                        "route": "sbc",
                        "productKind": route_type,
                        "sipUri": sip_uri,
                        "uri": sip_uri,
                        "target": target,
                        "number": str(
                            decision.get("number") or uri_user or target_id
                        ),
                        "host": sbc_host,
                        "sbcAddress": sbc_host,
                    }
                )
                session["route"] = decision
                session["productKind"] = route_type
            offer_sdp = str(
                session.get("ringOfferSdp")
                or session.get("inboundSbcInviteSdp")
                or getattr(
                    getattr(session.get("bLegCallerPc"), "remoteDescription", None),
                    "sdp",
                    "",
                )
                or ""
            )
            await _dial_sbc(session, offer_sdp)
            await webrtc_pc.rebridge_media(session, force=True)
        else:
            raise RuntimeError(
                str(
                    decision.get("reason")
                    or f"Transfer route rejected: {route_type or 'unknown'}"
                )
            )
        log.info(
            f"NOTIFY/TRANSFER: connected B={survivor_id!r} <-> C={target_id!r} "
            f"session={session_id} mediaBridged={session.get('mediaBridged')}"
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/TRANSFER: failed B={survivor_id!r} -> C={target_id!r} "
            f"session={session_id}: {exc}"
        )
        b_caller_leg = str(session.get("bLegCallerLeg") or "")
        if b_caller_leg:
            try:
                import webrtc_pc_worker as wkr

                b_call_id = (
                    webrtc_pc._normalize_call_id(
                        session.get(f"ringCallId:{survivor_id}")
                    )
                    or webrtc_pc._ensure_session_call_id(session)
                )
                await wkr.hangup_loser_leg(
                    session,
                    ident=survivor_id,
                    worker_leg=b_caller_leg,
                    call_id=b_call_id,
                    reason="hangup",
                )
            except Exception as b_exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY/TRANSFER: hangup B ({b_caller_leg}) failed "
                    f"session={session_id}: {b_exc}"
                )
        await fail_notify_call(
            exc,
            session=session,
            session_id=session_id,
            cancel_sip=True,
        )
    finally:
        session["clientTransferInProgress"] = False


async def _run_product_action(
    session: dict[str, Any],
    msg: dict[str, Any],
    *,
    digit: Any = None,
    action: str = "",
) -> None:
    dc_leg = str(msg.get("_dcLeg") or "").strip()
    if dc_leg:
        session["lastDtmfDcLeg"] = dc_leg
    source = str(msg.get("source") or "").strip().lower()
    if source == "openai-dtmf":
        decision = await logic_client.decide_action(session, msg, digit=digit, action=action)
        if dc_leg and isinstance(decision, dict) and "_dcLeg" not in decision:
            decision = dict(decision)
            decision["_dcLeg"] = dc_leg
        await apply_action_decision(session, decision)
        return
    # Client and carrier digits are forwarded. The wrapper /action route is not consulted.
    decision = dict(msg)
    if digit is not None:
        decision["digit"] = digit
    decision["action"] = "forward"
    decision["forwardDtmf"] = True
    decision["reason"] = "dtmf-forward"
    if dc_leg:
        decision["_dcLeg"] = dc_leg
    log.info(
        f"DTMF: forward digit={decision.get('digit')!r} "
        f"source={decision.get('source') or 'dc'} "
        f"leg={dc_leg or '-'} session={session.get('sessionId')}"
    )
    await _forward_dtmf_decision(session, decision)


async def _apply_ivr_transfer(session: dict[str, Any], decision: dict[str, Any]) -> None:
    """Park PSTN + notify seats. Never REFER the Cellact A-leg."""
    if session.get("ivrTransferArmed"):
        log.info(
            f"NOTIFY/ACTION: transfer already armed session={session.get('sessionId')}"
        )
        return
    route_kind = str(decision.get("route") or "").strip().lower()
    ident = str(decision.get("notifyIdentity") or decision.get("target") or "").strip()
    if not ident and decision.get("targets"):
        first = decision["targets"][0] if isinstance(decision["targets"][0], dict) else {}
        ident = str((first or {}).get("notifyIdentity") or "")
    if ident and not decision.get("notifyIdentity"):
        decision["notifyIdentity"] = ident
    if ident and not decision.get("targets"):
        decision["targets"] = [{"notifyIdentity": ident}]
    if route_kind not in ("webrtc", "webrtc-multiring"):
        log.warn(
            f"NOTIFY/ACTION: transfer route={route_kind!r} not webrtc "
            f"session={session.get('sessionId')}"
        )
        return
    if not ident:
        log.warn(
            f"NOTIFY/ACTION: transfer missing target session={session.get('sessionId')}"
        )
        return
    session["ivrTransferArmed"] = True
    session["pendingActionRoute"] = decision
    _apply_recording_policy(session, decision)
    session.setdefault("transferLog", []).append(
        {
            "digit": str(decision.get("digit") or "").strip(),
            "dtmfIndex": decision.get("dtmfIndex"),
            "action": str(decision.get("action") or "transfer").strip().lower() or "transfer",
            "route": route_kind,
            "target": ident,
            "reason": str(decision.get("reason") or ""),
        }
    )
    from_key = identity.identity_label(session.get("from") or "") or str(session.get("from") or "")
    if from_key:
        with _pending_ivr_lock:
            _pending_ivr_transfers[from_key] = decision
    log.info(
        f"NOTIFY/ACTION: ivr transfer digit={decision.get('digit')!r} "
        f"route={route_kind} target={ident!r} "
        f"targets={len(decision.get('targets') or [])} "
        f"isExtension={bool(decision.get('isExtension'))} "
        f"productItemId={decision.get('productItemId') or '-'} "
        f"session={session.get('sessionId')}"
    )
    import siphon_app as _siphon_app

    await _siphon_app.wake_ivr_xfer(session, decision, ident)


def _far_is_openai(session: dict[str, Any]) -> bool:
    dial = session.get("sbcDial")
    if isinstance(dial, dict) and str(dial.get("provider") or "").lower() == "openai":
        return True
    route = session.get("route") if isinstance(session.get("route"), dict) else {}
    uri = str((route or {}).get("sipUri") or (route or {}).get("uri") or "")
    target = ""
    if isinstance(dial, dict):
        target = str(dial.get("target_uri") or dial.get("targetUri") or "")
    return "sip.api.openai.com" in f"{uri} {target}".lower()


def _carrier_wants_rfc4733(session: dict[str, Any], *, toward_phone: bool) -> bool:
    """OpenAI only hears telephone-event. Cellact does too when the pc2
    answer negotiated telephone-event/8000. A relay cannot play_dtmf, and
    an in-band tone on PT 8 is not a digit to that answer."""
    if toward_phone:
        return False
    if _far_is_openai(session):
        return True
    return bool(session.get("pc2AnswerHasTe")) and not session.get("voicemailActive")


async def _forward_dtmf_decision(session: dict[str, Any], decision: dict[str, Any]) -> None:
    action = str(decision.get("action") or "none").strip().lower()
    digit = decision.get("digit")
    source = str(decision.get("source") or "").strip().lower()
    if digit is None or not str(digit).strip():
        return
    source_leg = str(
        decision.get("_dcLeg")
        or ("pc2" if source == "openai-dtmf" else "")
        or session.get("lastDtmfDcLeg")
        or ""
    ).strip()
    try:
        has_worker = bool(
            session.get("mediaWorker")
            or session.get("pc")
            or session.get("pc2")
            or session.get("pcCallee")
            or session.get("bLegCallerLeg")
        )
        if has_worker:
            # rtpengine detect-dtmf already has the digit on the RTP stream.
            if source == "rtp" and not str(decision.get("_dcLeg") or "").strip():
                log.info(
                    f"NOTIFY/ACTION: RTP digit={digit!r} already in media "
                    f"session={session.get('sessionId')} "
                    f"dtmfIndex={decision.get('dtmfIndex')} "
                    f"reason={decision.get('reason')}"
                )
                return
            # Phone → carrier. siphon-rtp never sees the telephone-event
            # (str0m drops it). play DTMF synthesizes it. to-tag is the SBC
            # tag so the tone goes to the carrier, not back to the phone.
            ng_cid = str(session.get("sbcNgCallId") or "").strip()
            ng_tag = str(session.get("sbcNgFromTag") or "").strip()
            ng_to = str(session.get("sbcNgToTag") or "").strip()
            toward_phone = source_leg in ("pc2", "openai-dtmf") or source_leg.startswith("callee")
            use_rfc4733 = _carrier_wants_rfc4733(session, toward_phone=toward_phone)
            if ng_cid and ng_tag and not toward_phone and not session.get("voicemailActive"):
                # play DTMF only runs on a transcoding call. A PCMA↔PCMA relay
                # refuses it. The relay still forwards a telephone-event
                # packet written on pc2 when the answer negotiated one.
                try:
                    rtpengine_inject_dtmf(
                        ng_cid,
                        ng_tag,
                        digit,
                        session.get("lastDtmfDurationMs"),
                        session.get("lastDtmfVolume"),
                        ng_to,
                    )
                    log.info(
                        f"NOTIFY/ACTION: forwarded digit={digit!r} via siphon-rtp play DTMF "
                        f"session={session.get('sessionId')} call_id={ng_cid} "
                        f"from_tag={ng_tag} to_tag={ng_to or '-'} source_leg={source_leg or '-'} "
                        f"action={action} dtmfIndex={decision.get('dtmfIndex')} "
                        f"reason={decision.get('reason')}"
                    )
                    return
                except Exception as exc:  # noqa: BLE001
                    how_next = "telephone-event" if use_rfc4733 else "in-band"
                    log.info(
                        f"NOTIFY/ACTION: play DTMF refused ({exc}); "
                        f"{how_next} on pc2 session={session.get('sessionId')}"
                    )
            import webrtc_pc_worker as wkr

            await wkr.inject_dtmf(
                session,
                digit,
                session.get("lastDtmfDurationMs"),
                session.get("lastDtmfVolume"),
                source_leg=source_leg,
                rfc4733=use_rfc4733,
            )
            how = "RFC4733" if use_rfc4733 else "in-band"
            log.info(
                f"NOTIFY/ACTION: forwarded digit={digit!r} via worker {how} "
                f"session={session.get('sessionId')} source_leg={source_leg or '-'} "
                f"action={action} dtmfIndex={decision.get('dtmfIndex')} "
                f"reason={decision.get('reason')}"
            )
        else:
            ng_cid = str(
                session.get("voicemailMediaCallId")
                or session.get("mediaCallId")
                or session.get("b2buaCallId")
                or ""
            )
            if source_leg in ("pc2", "openai-dtmf") or source == "openai-dtmf":
                ng_tag = str(
                    session.get("bLegRemoteTag")
                    or session.get("toTag")
                    or session.get("alegToTag")
                    or ""
                )
            else:
                ng_tag = str(
                    decision.get("fromTag")
                    or session.get("lastDtmfFromTag")
                    or session.get("voicemailFromTag")
                    or session.get("fromTag")
                    or session.get("alegFromTag")
                    or ""
                )
            rtpengine_inject_dtmf(
                ng_cid,
                ng_tag,
                digit,
                session.get("lastDtmfDurationMs"),
                session.get("lastDtmfVolume"),
            )
            log.info(
                f"NOTIFY/ACTION: forwarded digit={digit!r} via rtpengine "
                f"session={session.get('sessionId')} call_id={ng_cid} "
                f"from_tag={ng_tag} action={action} "
                f"dtmfIndex={decision.get('dtmfIndex')} "
                f"reason={decision.get('reason')}"
            )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"NOTIFY/ACTION: inject DTMF failed digit={digit!r} "
            f"session={session.get('sessionId')}: {exc}"
        )


async def apply_action_decision(session: dict[str, Any], decision: dict[str, Any]) -> None:
    action = str(decision.get("action") or "none").strip().lower()
    should_forward = (
        bool(decision.get("forwardDtmf")) or action == "forward"
    ) and action != "reject"
    _note_dtmf_action(session, decision)
    if should_forward:
        if action in ("", "none", "forward"):
            await _forward_dtmf_decision(session, decision)
        else:
            _schedule_coro(_forward_dtmf_decision(session, decision))
    if action in ("", "none", "forward"):
        return
    if action == "reject":
        await fail_notify_call(
            decision.get("reason") or "action reject",
            session=session,
            cancel_sip=True,
        )
        return
    if action in ("transfer", "redirect"):
        await _apply_ivr_transfer(session, decision)
        return
    log.info(
        f"NOTIFY/ACTION: unhandled action={action!r} session={session.get('sessionId')}"
    )


def _party_labels(*raws: Any) -> set[str]:
    """identity_label plus digits-only, so +972 and 972 are the same party."""
    out: set[str] = set()
    for raw in raws:
        label = identity.identity_label(str(raw or ""))
        if label:
            out.add(label)
        phone = identity.normalize_phone_label(raw)
        if phone:
            out.add(phone)
    return out


def _openai_caller_labels(session: dict[str, Any]) -> set[str]:
    """Session from, plus the cover DID OpenAI actually saw on the INVITE."""
    route = session.get("route") if isinstance(session.get("route"), dict) else {}
    return _party_labels(
        session.get("from"),
        session.get("callerId"),
        session.get("sbcFromUser"),
        route.get("callerId"),
    )


def _openai_dtmf_session(from_id: str, to_id: str) -> Optional[dict[str, Any]]:
    """Live call for this from/to. A shared pair alias must not drop the digit.

    LightPBX stores the session as the sys id and presents a cover DID.
    OpenAI sends that cover as from, so the sys label alone is not a match.
    """
    from_labels = _party_labels(from_id)
    to_labels = _party_labels(to_id)
    hits = _attempts_for_keys(
        _stable_key(from_id, to_id),
        _directional_key(from_id, to_id),
    )

    def _take(pool: list[dict[str, Any]]) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for sess in pool:
            if from_labels.isdisjoint(_openai_caller_labels(sess)):
                continue
            if to_labels and to_labels.isdisjoint(_party_labels(sess.get("to"))):
                continue
            if not session_handles_dtmf(sess):
                continue
            found.append(sess)
        return found

    matched = _take(hits)
    if not matched:
        seen = {_storage_key(sess) for sess in hits}
        with _sessions_lock:
            rest = [
                sess
                for sess in _sessions.values()
                if _storage_key(sess) not in seen
            ]
        matched = _take(rest)
    live = [
        sess
        for sess in matched
        if not sess.get("clientEnded")
        and not sess.get("failureNotified")
        and not sess.get("failureCleanupDone")
    ]
    pool = live or matched
    if not pool:
        return None
    pool.sort(key=lambda sess: float(sess.get("createdAt") or 0))
    chosen = pool[-1]
    if len(pool) > 1:
        log.info(
            f"OPENAI-DTMF pair n={len(pool)} picked={chosen.get('sessionId')} "
            f"from={from_id!r} to={to_id!r} "
            f"others={[str(s.get('sessionId') or '') for s in pool[:-1]]}"
        )
    return chosen


def _openai_dtmf_client_ip(req) -> str:
    """siphon-http Request.client is remote ip:port. [::] listen reports v4 as ::ffff:."""
    raw = str(getattr(req, "client", "") or "").strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end > 1:
            raw = raw[1:end]
    elif raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    if raw.lower().startswith("::ffff:"):
        raw = raw[7:]
    if raw.count(":") == 1 and raw.rsplit(":", 1)[-1].isdigit():
        raw = raw.rsplit(":", 1)[0]
    return raw


@http.route("/open-ai-entrypoint", methods=["POST"])
async def on_openai_dtmf(req):
    pin_event_loop()
    client_ip = _openai_dtmf_client_ip(req)
    try:
        raw_bytes = req.body()
        raw_text = raw_bytes.decode() if isinstance(raw_bytes, (bytes, bytearray)) else str(raw_bytes)
        body = json.loads(raw_text) if raw_text else None
    except Exception:  # noqa: BLE001
        return _json_response(400, {"error": "JSON object required"})
    if not isinstance(body, dict):
        return _json_response(400, {"error": "JSON object required"})
    from_id = str(body.get("from") or "").strip()
    to_id = str(body.get("to") or "").strip()
    digit = str(body.get("digit") or "").strip()
    if not from_id or not to_id or not re.fullmatch(r"[0-9]", digit):
        return _json_response(400, {"error": "from, to, and digit 0-9 required"})
    session = _openai_dtmf_session(from_id, to_id)
    if not session:
        log.info(f"OPENAI-DTMF miss from={from_id!r} to={to_id!r} digit={digit}")
        return _json_response(404, {"error": "no live call"})
    log.info(
        f"OPENAI-DTMF ip={client_ip or '-'} from={from_id!r} to={to_id!r} digit={digit} "
        f"session={session.get('sessionId')}"
    )
    _on_dc_action(
        session,
        {"digit": digit, "source": "openai-dtmf", "_dcLeg": "pc2"},
    )
    return _json_response(200, {"ok": True})


@http.route("/notify", methods=["POST", "OPTIONS"])
async def on_notify(req):
    pin_event_loop()
    if req.method == "OPTIONS":
        return http.Response(status=204, headers=CORS_HEADERS)

    try:
        raw_bytes = req.body()
        raw_text = raw_bytes.decode() if isinstance(raw_bytes, (bytes, bytearray)) else str(raw_bytes)
        raw_len = len(raw_bytes) if isinstance(raw_bytes, (bytes, bytearray)) else len(raw_text)
        ctype = ""
        try:
            ctype = req.header("content-type") or req.header("Content-Type") or ""
        except Exception:  # noqa: BLE001
            ctype = ""
        hdr_keys = ""
        try:
            hdr_keys = str(sorted((req.headers or {}).keys()))
        except Exception:  # noqa: BLE001
            hdr_keys = "?"
        log.info(
            f"NOTIFY hit method={getattr(req, 'method', '?')} "
            f"content-type={ctype!r} raw_bytes={raw_len} "
            f"x-sign={bool(req.header('x-sign') or req.header('xsign'))} "
            f"x-data={bool(req.header('x-data') or req.header('xdata'))} "
            f"{logic_client.notify_req_probe(req)}"
        )
        raw_payload = _loads_notify_body(raw_text)
        if not isinstance(raw_payload, dict):
            return _json_response(400, {"error": "JSON object required"})
        proto = _notify_protocol(raw_payload, req)
        if proto and proto not in ("webrtc", "plaintext"):
            log.info(f"NOTIFY reject protocol={proto!r}")
            return _json_response(400, {"error": "protocol must be webrtc or plaintext", "protocol": proto})
        contract_body = _contract_notify_body(raw_payload, req)
        raw_payload = _merge_headers(raw_payload, req)
        payload = _normalize_notify_payload(raw_payload)
        # Auth headers may only exist on the outer envelope — merge again after unwrap.
        payload = _merge_headers(payload, req)
        log.info(f"NOTIFY parsed {_summarize_notify(raw_payload, payload, raw_len)}")

        if proto == "plaintext":
            return await _forward_plaintext(req, payload, contract_body)

        msg_type = str(payload.get("type") or "offer").strip().lower()
        notify_port, port_src = logic_client.resolve_notify_port(req)
        port_provider = policy.logic_provider_for_notify_port(notify_port)
        logic_sp = str((port_provider or {}).get("id") or "")
        service_id = logic_sp or str(payload.get("serviceId") or "").strip()
        raw_from = payload.get("from")
        raw_to = payload.get("to")
        from_id = str(raw_from or "").strip()
        to_id = str(raw_to or "").strip()
        session_id = payload.get("sessionId")
        signaling_sid = str(session_id or "")
        sdp = _body_text(payload.get("sdp"))
        if sdp.strip():
            _log_sdp(f"NOTIFY HTTP {msg_type} SDP in from={from_id} to={to_id}", sdp)

        # ice-batch / cancel / reject — no initial-offer auth when session exists
        if msg_type == "ice-batch":
            log.info(f"NOTIFY ice-batch sessionId={session_id!r} from={from_id!r} to={to_id!r}")
            wire_id = str(session_id or "") or _stable_key(from_id, to_id)
            session, ice_why = _select_attempt(
                from_id, to_id, session_id, payload, role="ice"
            )
            if session is None and ice_why == "missing":
                only = _attempts_for_keys(wire_id, _stable_key(from_id, to_id))
                if len(only) == 1:
                    session = only[0]
                    ice_why = "only"
            session_id = str((session or {}).get("sessionId") or wire_id)
            if ice_why in ("stale", "ambiguous"):
                held = _hold_early_ice(payload)
                log.info(
                    f"NOTIFY hold {ice_why} ice-batch session={session_id} "
                    f"nonce={payload.get('callNonce')!r} callId={payload.get('callId')!r} "
                    f"ufrags={sorted(_request_ufrags(payload))} held={held}"
                )
                return _json_response(
                    200,
                    {
                        "ok": True,
                        "ignored": True,
                        "reason": "stale-nonce" if ice_why == "stale" else "ambiguous-attempt",
                        "type": "ice-batch",
                        "sessionId": session_id,
                    },
                )
            # Outbound phone=PC1; inbound phone=PC-callee (per-seat ring leg).
            ring_leg = (
                _ring_leg_for(
                    session,
                    from_id=from_id,
                    to_id=to_id,
                    session_id=signaling_sid,
                )
                if session
                else None
            )
            pc_target = (
                (ring_leg.pc if ring_leg is not None else None)
                or (session or {}).get("pcCallee")
                or (session or {}).get("pc")
            )
            if not session or pc_target is None:
                return _json_response(
                    200,
                    {
                        "ok": True,
                        "ignored": True,
                        "reason": "session-not-ready",
                        "type": "ice-batch",
                        "sessionId": session_id,
                    },
                )
            candidates = payload.get("candidates") or []
            if session.get("pcCallee") is pc_target or (
                ring_leg is not None and ring_leg.pc is pc_target
            ):
                applied = await _await_on_session_loop(
                    session,
                    webrtc_pc.add_ice_candidates_to_pc(
                        session, pc_target, candidates, label="PC-callee"
                    ),
                )
            else:
                applied = await _await_on_session_loop(
                    session, webrtc_pc.add_ice_candidates(session, candidates)
                )
            session.setdefault("iceBatches", []).append(candidates)
            conn = getattr(pc_target, "connectionState", "?")
            ours: list[Any] = []
            try:
                from webrtc_pc_worker import peer_call

                ice = await peer_call(
                    "pc.localIce",
                    {
                        "sessionId": getattr(pc_target, "session_id", "")
                        or session.get("workerSessionId")
                        or session_id,
                        "leg": getattr(pc_target, "leg", "pc1"),
                        "waitRelay": True,
                        "timeoutMs": 3500,
                    },
                    timeout=8.0,
                )
                ours = list((ice or {}).get("candidates") or [])
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY ice-batch localIce failed: {exc}")
            log.info(
                f"NOTIFY ice-batch applied sessionId={session_id!r} n={len(candidates)} "
                f"applied={applied} types[{webrtc_pc.candidate_type_counts(candidates)}] "
                f"ours={len(ours)} types[{webrtc_pc.candidate_type_counts(ours)}] "
                f"connectionState={conn} (not skipped when connected)"
            )
            return _json_response(
                200,
                {
                    "ok": True,
                    "applied": applied,
                    "type": "ice-batch",
                    "sessionId": session_id,
                    "from": to_id,
                    "to": from_id,
                    "candidates": ours,
                },
            )

        if msg_type in ("cancel", "reject"):
            log.info(f"NOTIFY {msg_type} sessionId={session_id!r} from={from_id!r} to={to_id!r}")
            wire_id = str(session_id or "") or _stable_key(from_id, to_id)
            req_nonce, req_call_id = _request_ids(payload)
            has_ids = bool(req_nonce or req_call_id)
            session, bind_why = _select_attempt(
                from_id, to_id, session_id, payload, role=msg_type
            )
            if (
                session is None
                and bind_why == "missing"
                and msg_type == "reject"
            ):
                # Single live attempt: a callee reject still declines that call.
                only = _attempts_for_keys(
                    wire_id,
                    _stable_key(from_id, to_id),
                    _directional_key(from_id, to_id),
                    _directional_key(to_id, from_id),
                )
                if len(only) == 1:
                    session = only[0]
                    bind_why = "only"
            if session is not None and not has_ids and _attempt_connected(session):
                # Id-less cancel/reject never ends a picked-up call.
                session = None
                bind_why = "connected"
            session_id = str((session or {}).get("sessionId") or wire_id)
            if session is None:
                if bind_why == "connected":
                    log.info(
                        f"{msg_type.upper()}: nonce-less {msg_type} ignored; attempt connected "
                        f"session={session_id} from={from_id!r} to={to_id!r}"
                    )
                else:
                    log.info(
                        f"NOTIFY ignore {bind_why} {msg_type} session={session_id} "
                        f"got={req_nonce or None!r} callId={req_call_id or None!r}"
                    )
                return _json_response(
                    200,
                    {
                        "ok": True,
                        "ignored": True,
                        "reason": "stale-nonce" if bind_why == "stale" else "no-attempt",
                        "type": msg_type,
                        "sessionId": session_id,
                    },
                )
            log.info(
                f"NOTIFY {msg_type} bound attempt={_storage_key(session)} by={bind_why}"
            )
            if session:
                caller = identity.identity_label(session.get("from") or "")
                from_label = identity.identity_label(from_id)
                legs = session.get("ringLegs") or {}
                ring_leg = legs.get(from_id) or legs.get(from_label)
                if ring_leg is None:
                    for ident, candidate in legs.items():
                        if identity.identity_label(ident) == from_label:
                            ring_leg = candidate
                            break
                if (
                    ring_leg is not None
                    and from_label
                    and from_label != caller
                ):
                    log.info(
                        f"NOTIFY {msg_type} per-leg decline ident={ring_leg.ident!r} "
                        f"session={session_id}"
                    )
                    ring_leg._mark_declined()
                    return _json_response(
                        200,
                        {
                            "ok": True,
                            "type": msg_type,
                            "sessionId": str(session.get("sessionId") or session_id),
                            "declinedIdent": ring_leg.ident,
                        },
                    )
                session["declinedBeforePickup"] = True
            body = await _teardown(
                _storage_key(session), cancel_sip=(msg_type == "cancel")
            )
            body["type"] = msg_type
            return _json_response(200, body)

        if msg_type == "answer":
            log.info(
                f"NOTIFY answer sessionId={session_id!r} from={from_id!r} to={to_id!r} sdp_len={len(sdp)}"
            )
            wire_id = str(session_id or "") or _stable_key(from_id, to_id)
            # Callee answers the attempt they were invited to, not their own offer.
            session, ans_why = _select_attempt(
                from_id, to_id, session_id, payload, role="answer"
            )
            session_id = str((session or {}).get("sessionId") or wire_id)
            if ans_why == "stale" or (session is None and ans_why == "ambiguous"):
                log.info(
                    f"NOTIFY ignore {ans_why} answer session={session_id} "
                    f"got={payload.get('callNonce')!r}"
                )
                return _json_response(
                    200,
                    {
                        "ok": True,
                        "ignored": True,
                        "reason": "stale-nonce" if ans_why == "stale" else "ambiguous-attempt",
                        "type": "answer",
                        "sessionId": session_id,
                    },
                )
            if not session:
                log.info(
                    f"NOTIFY answer miss why={ans_why} session={session_id} "
                    f"from={from_id!r} to={to_id!r}"
                )
                return _json_response(404, {"error": "Session not found for answer", "sessionId": session_id})
            if not sdp:
                return _json_response(400, {"error": "Missing sdp on answer"})
            _remember_attempt_ids(session, ufrag=_sdp_ufrag(sdp))
            result = await _handle_callee_answer(
                session,
                sdp,
                payload.get("candidates") or [],
                from_id=from_id,
                to_id=to_id,
                session_id=signaling_sid,
            )
            return _json_response(200, result)

        if msg_type and msg_type != "offer":
            return _json_response(400, {"error": f"Unsupported signaling type over HTTP: {msg_type}"})

        inbound_offer = await _try_inbound_callee_http_offer(
            payload,
            from_id=from_id,
            to_id=to_id,
            session_id=session_id,
            signaling_sid=signaling_sid,
            sdp=sdp,
        )
        if inbound_offer is not None:
            return _json_response(200, inbound_offer)

        # Initial offer — /auth. A named serviceProvider is tried first. Unknown
        # or failed pins fan out. No name keeps the listen-port pin, else fan-out.
        auth_sp, named = _auth_logic_sp(payload, logic_sp)
        log.info(
            f"NOTIFY offer auth begin from={from_id!r} to={to_id!r} "
            f"port={notify_port if notify_port is not None else '-'} "
            f"portSrc={port_src} sp={auth_sp or 'fan-out'} "
            f"serviceProvider={payload.get('serviceProvider') or '-'} "
            f"xdata={_clip(payload.get('xdata') or payload.get('x-data'), 80)!r} "
            f"xsign_len={len(str(payload.get('xsign') or payload.get('x-sign') or ''))} "
            f"sdp_len={len(sdp)}"
        )
        auth = await _authenticate_notify(payload, auth_sp, fallback=named)
        log.info(
            f"NOTIFY auth: ok from={from_id!r} sp={auth.get('logicSp') or logic_sp} "
            f"mode={auth.get('mode')} signer={auth.get('signer')}"
        )
        if not from_id:
            return _json_response(400, {"error": "Missing required field: from"})
        if not to_id:
            return _json_response(400, {"error": "Missing required field: to"})
        if not sdp:
            return _json_response(400, {"error": "Missing required field: sdp"})

        parsed_to = logic_client.parse_address(to_id)
        parsed_from = logic_client.parse_address(from_id)
        route = await logic_client.resolve_destination(
            parsed_to,
            parsed_from,
            origin="client",
            to=to_id,
            from_id=from_id,
            session_id=str(session_id or ""),
            kind="outbound",
            logic_sp=logic_sp or str(auth.get("logicSp") or ""),
        )
        log.info(
            f"NOTIFY: route={route.get('route')} from={from_id} to={to_id} "
            f"wallet={route.get('wallet')} host={route.get('host') or '-'} "
            f"targets={len(route.get('targets') or [])} "
            f"sp={route.get('logicSp') or logic_sp} service={service_id}"
        )

        if route.get("route") == "reject":
            return _json_response(
                int(route.get("statusCode") or 403),
                {"error": route.get("reason") or "rejected", "route": "reject"},
            )
        if logic_client.is_product_route(route) and not (route.get("sipUri") or route.get("uri")):
            return _json_response(
                501,
                {
                    "error": f"Route {route.get('route')} needs sipUri on SIPhon ingress",
                    "route": route.get("route"),
                },
            )
        if logic_client.is_product_route(route):
            sip_uri = str(route.get("sipUri") or route.get("uri") or "").strip()
            user, _, rest = sip_uri.replace("sip:", "", 1).partition("@")
            host = rest.split(";", 1)[0].split(":", 1)[0]
            number = str(user or "").strip()
            did = str(route.get("number") or to_id or "").strip()
            if not number or not host:
                return _json_response(
                    501,
                    {
                        "error": f"Route {route.get('route')} sipUri needs user@host",
                        "route": route.get("route"),
                    },
                )
            route = {
                **route,
                "productKind": route.get("route"),
                "route": "sbc",
                "number": did or number,
                "host": host,
                "sbcAddress": host,
                "sipUri": sip_uri,
            }
            log.info(
                f"NOTIFY: product→openai sipUri user={number!r} host={host!r} "
                f"did={did or '-'} to={to_id}"
            )

        if route.get("route") not in ("sbc", "webrtc", "webrtc-multiring"):
            return _json_response(500, {"error": f"Unhandled route: {route.get('route')}"})

        session_id = _stable_key(from_id, to_id)
        # Same caller + same ICE ufrag may reuse one PC. The opposite offer is a
        # different attempt: route it, do not 486, do not cancel the other leg.
        # Polite (lower identity yields) applies only inside glare_keep when one
        # shared PC must choose setRemote. Higher identity keeps its offer.
        prior = _same_direction_attempt(from_id, to_id)
        others = [
            s
            for s in _attempts_for_keys(session_id, _directional_key(to_id, from_id))
            if s is not prior
            and _dialog_originator(s) != identity.identity_label(from_id)
            and _dialog_inflight(s)
        ]
        if others:
            log.info(
                f"DIALOG-GLARE: route both offers from={identity.identity_label(from_id)} "
                f"to={identity.identity_label(to_id)} "
                f"also={[ _storage_key(s) for s in others ]} (no 486)"
            )
        reused = False
        if _http_offer_can_reuse(prior, from_id, to_id, route, sdp):
            session = prior
            reused = True
            session_id = str(session.get("sessionId") or session_id)
            await _reset_webrtc_session_for_redial(
                session,
                route=route,
                to_id=to_id,
                payload=payload,
                logic_sp=str(logic_sp or ""),
            )
            offer_ids = _offer_ids(payload, sdp)
            _remember_attempt_ids(
                session,
                nonce=offer_ids["nonce"],
                call_id=offer_ids["call_id"],
                ufrag=offer_ids["ufrag"],
                fresh=True,
            )
            caller_cid = webrtc_pc._normalize_call_id(offer_ids.get("call_id"))
            if caller_cid is not None:
                session["legCallId:pc1"] = caller_cid
                session["activeCallId"] = caller_cid
            _apply_recording_policy(session, route)
        else:
            media_call_id = f"{uuid.uuid4().hex}@{policy.local_domain()}"
            from_tag = uuid.uuid4().hex[:8]
            session = {
                "sessionId": session_id,
                "workerSessionId": f"{session_id}:{uuid.uuid4().hex[:10]}",
                "dialogEpoch": _alloc_direction_epoch(from_id, to_id),
                "dialogOriginator": identity.identity_label(from_id),
                "from": from_id,
                "to": to_id,
                "dialedTo": to_id,
                "route": route,
                "productKind": route.get("productKind"),
                "mediaCallId": media_call_id,
                "fromTag": from_tag,
                "toTag": uuid.uuid4().hex[:8],
                "state": "created",
                "createdAt": time.time(),
                "logicSp": route.get("logicSp") or logic_sp,
                "callerLogicSp": str(logic_sp or ""),
                "serviceId": route.get("logicSp") or logic_sp or service_id,
                "callNonce": payload.get("callNonce"),
                "xdata": payload.get("xdata") or payload.get("x-data"),
                "xsign": payload.get("xsign") or payload.get("x-sign"),
                "originTo": to_id,
                "originRoute": json.loads(json.dumps(route)),
                "dtmfCount": 0,
                "dtmfLog": [],
                "transferLog": [],
            }
            offer_ids = _offer_ids(payload, sdp)
            _remember_attempt_ids(
                session,
                nonce=offer_ids["nonce"],
                call_id=offer_ids["call_id"],
                ufrag=offer_ids["ufrag"],
                fresh=True,
            )
            caller_cid = webrtc_pc._normalize_call_id(offer_ids.get("call_id"))
            if caller_cid is not None:
                session["legCallId:pc1"] = caller_cid
                session["activeCallId"] = caller_cid
            _put_session(session)
            _apply_recording_policy(session, route)

        candidates = list(payload.get("candidates") or [])
        held = _take_held_ice(
            call_id=str(offer_ids.get("call_id") or ""),
            ufrag=str(offer_ids.get("ufrag") or ""),
        )
        if held:
            log.info(
                f"NOTIFY: replay held ice session={session_id} "
                f"n={len(held)} callId={offer_ids.get('call_id')!r} "
                f"ufrag={offer_ids.get('ufrag')!r}"
            )
            candidates.extend(held)
        log.info(
            f"NOTIFY: PC1 handshake begin session={session_id} "
            f"worker={session.get('workerSessionId')} route={route.get('route')} "
            f"offer_bytes={len(sdp)} candidates={len(candidates)} reused={reused}"
        )
        try:
            session["on_dc_end"] = _on_dc_end
            session["on_dc_action"] = _on_dc_action
            hs = await webrtc_pc.handshake(
                session,
                sdp,
                candidates,
                on_dc_ring=_on_dc_ring,
                reuse_pc=reused,
            )
        except Exception:
            await webrtc_pc.close(session)
            _pop_session(_storage_key(session) or session_id)
            raise

        return _json_response(
            200,
            {
                "type": "answer",
                "from": to_id,
                "to": from_id,
                "sessionId": session_id,
                "sdp": hs["sdp"],
                "offerUfrag": payload.get("offerUfrag"),
                "callNonce": payload.get("callNonce"),
                "candidates": hs.get("candidates") or [],
                "route": route.get("route"),
                "ok": True,
            },
        )

    except identity.IdentityError as exc:
        log.warn(f"NOTIFY auth: {exc}")
        return _json_response(exc.status_code, {"error": str(exc)})
    except (json.JSONDecodeError, ValueError) as exc:
        log.warn(f"NOTIFY bad json: {exc}")
        return _json_response(400, {"error": "Invalid JSON"})
    except Exception as exc:  # noqa: BLE001
        log.error(f"NOTIFY error: {type(exc).__name__}: {exc}")
        return _json_response(500, {"error": str(exc)})


def _arnaserver_age(created_at):
    try:
        seconds = max(0, int(time.time() - float(created_at or 0)))
    except (TypeError, ValueError):
        return "-"
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _arnaserver_text(value):
    return str(value or "").strip()


def _arnaserver_snapshot():
    """Read-only copy of the session table. Does not write or signal a call."""
    copied = []
    seen = set()
    with _sessions_lock:
        for session in list(_sessions.values()):
            marker = id(session)
            if marker in seen or not isinstance(session, dict):
                continue
            seen.add(marker)
            route = session.get("route") if isinstance(session.get("route"), dict) else {}
            route_name = _arnaserver_text(
                route.get("route") or session.get("routeKind")
            ).lower()
            to_sp = _arnaserver_text(
                session.get("logicSp") or route.get("logicSp")
            ).lower()
            # SBC is the default trunk. logicSp on that route is the caller wrapper.
            if route_name == "sbc":
                to_sp = ""
            copied.append(
                {
                    "id": _arnaserver_text(
                        session.get("b2buaCallId")
                        or session.get("mediaCallId")
                        or session.get("sessionId")
                    ),
                    "from": _arnaserver_text(session.get("from")),
                    "to": _arnaserver_text(session.get("to")),
                    "fromSp": _arnaserver_text(
                        session.get("callerLogicSp")
                        or session.get("logicSp")
                        or route.get("logicSp")
                    ).lower(),
                    "toSp": to_sp,
                    "product": _arnaserver_text(
                        session.get("productKind")
                        or route.get("productKind")
                        or route.get("route")
                        or session.get("routeKind")
                    ).lower(),
                    "state": _arnaserver_text(session.get("state")),
                    "createdAt": session.get("createdAt") or 0,
                }
            )
    calls = []
    products = []
    product_kinds = {"openai-sip", "openai", "ivr", "external-sip"}
    for row in copied:
        if not row["id"] and not row["from"] and not row["to"]:
            continue
        call = {
            "id": row["id"],
            "from": row["from"],
            "fromSp": row["fromSp"],
            "to": row["to"],
            "toSp": row["toSp"],
            "product": row["product"] or "sbc",
            "state": row["state"],
            "age": _arnaserver_age(row["createdAt"]),
        }
        calls.append(call)
        if row["product"] in product_kinds:
            products.append(
                {
                    "product": row["product"],
                    "sp": row["toSp"] or row["fromSp"],
                    "call": row["id"],
                    "from": row["from"],
                    "to": row["to"],
                }
            )
    return {"calls": calls, "products": products}


@http.route("/arnaserver/status", methods=["GET"])
async def arnaserver_status(_req):
    return _json_response(200, _arnaserver_snapshot())


@http.route("/healthz", methods=["GET"])
async def healthz(_req):
    extra = b""
    try:
        from webrtc_pc_worker import peer_call

        ping = await peer_call("ping", {}, timeout=2.0)
        extra = f" peer={ping}".encode()
    except Exception as exc:  # noqa: BLE001
        extra = f" peer-err={exc}".encode()
    return http.Response(status=200, body=b"ok" + extra)


log.info("client_ingress: /notify registered (auth = GCP /auth)")
