"""PC1 WebRTC termination for secnum /notify (aiortc).

Mirrors Node WebRtcHandshakeUseCase + PeerConnectionFactory DC ingress:
  HTTP DC-only offer → createAnswer → ICE → datachannel
  DC signaling offer with active audio → on_dc_ring callback (SBC/webrtc dial)
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import random
import re
import threading
import time
import uuid
import wave
from typing import Any, Awaitable, Callable, Optional

from siphon import log

import identity


def _note_dc_ring_sent(
    session: dict[str, Any],
    ident: str,
    sdp: str,
    ice: Any,
    *,
    invert_caller: bool = False,
    wallet: Any = None,
) -> None:
    try:
        from client_ingress import note_dc_ring_sent

        note_dc_ring_sent(
            session,
            ident,
            {"sdp": sdp, "candidates": ice or []},
            invert_caller=invert_caller,
            wallet=wallet,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC: DC RING silence watch arm failed ident={ident!r} "
            f"session={session.get('sessionId')}: {exc}"
        )


def _note_dc_peer_alive(session: dict[str, Any], ident: str) -> None:
    try:
        from client_ingress import note_dc_peer_alive

        note_dc_peer_alive(session, ident)
    except Exception:  # noqa: BLE001
        pass


try:
    from aiortc import (
        AudioStreamTrack,
        RTCConfiguration,
        RTCIceServer,
        RTCPeerConnection,
        RTCSessionDescription,
    )
    from aiortc.sdp import candidate_from_sdp
except ImportError as exc:  # pragma: no cover
    AudioStreamTrack = None  # type: ignore[misc, assignment]
    RTCConfiguration = None  # type: ignore[misc, assignment]
    RTCIceServer = None  # type: ignore[misc, assignment]
    RTCPeerConnection = None  # type: ignore[misc, assignment]
    RTCSessionDescription = None  # type: ignore[misc, assignment]
    candidate_from_sdp = None  # type: ignore[misc, assignment]
    _AIORTC_IMPORT_ERROR = exc
else:
    _AIORTC_IMPORT_ERROR = None

try:
    from aiortc.contrib.media import MediaRelay
except ImportError:  # pragma: no cover
    MediaRelay = None  # type: ignore[misc, assignment]

# aiortc does not trickle — wait for full gather (TURN can be slow).
ICE_GATHER_TIMEOUT_SECS = float(os.environ.get("WEBRTC_ICE_GATHER_TIMEOUT_SECS", "10") or "10")

OnDcRing = Callable[[dict[str, Any], dict[str, Any]], Awaitable[None]]


class _SilentAudioTrack(AudioStreamTrack if AudioStreamTrack is not None else object):  # type: ignore[misc]
    """Blank outbound audio until media bridge replaceTrack (Node MediaStreamTrack).

    8kHz mono — matches G711 PC1/PC2 path. 48kHz silence before replaceTrack
    has been correlated with PC2 outbound stalling at ~1 RTP packet.
    """

    kind = "audio"

    def __init__(self) -> None:
        if AudioStreamTrack is None:
            raise RuntimeError("aiortc AudioStreamTrack unavailable")
        super().__init__()
        self._timestamp = 0
        self._sample_rate = 8000
        self._samples = 160  # 20ms @ 8kHz

    async def recv(self) -> Any:  # noqa: ANN401
        import fractions

        from av import AudioFrame

        await asyncio.sleep(0.02)
        frame = AudioFrame(format="s16", layout="mono", samples=self._samples)
        frame.planes[0].update(bytes(self._samples * 2))
        frame.pts = self._timestamp
        frame.sample_rate = self._sample_rate
        frame.time_base = fractions.Fraction(1, self._sample_rate)
        self._timestamp += self._samples
        return frame


class _SwitchableAudioTrack(AudioStreamTrack if AudioStreamTrack is not None else object):  # type: ignore[misc]
    """PC1 outbound: one track for the life of the PC. Swap MediaRelay sources
    in recv() — never replaceTrack. replaceTrack(Relay) then later another
    source kills aiortc's send loop and changes SSRC (iOS drops the new stream).
    """

    kind = "audio"

    def __init__(self) -> None:
        if AudioStreamTrack is None:
            raise RuntimeError("aiortc AudioStreamTrack unavailable")
        super().__init__()
        self._src: Any = None
        self._timestamp = 0
        self._sample_rate = 8000
        self._samples = 160

    def set_source(self, track: Any) -> None:
        self._src = track

    async def recv(self) -> Any:  # noqa: ANN401
        src = self._src
        if src is not None:
            try:
                frame = await src.recv()
                if frame is not None:
                    return self._as_g711_frame(frame)
                log.warn("MEDIA: tap src.recv returned None; silence")
            except Exception as exc:  # noqa: BLE001
                log.warn(f"MEDIA: tap src.recv failed ({type(exc).__name__}: {exc}); keep source")
        await asyncio.sleep(0.02)
        return self._silence_frame()

    def _silence_frame(self) -> Any:
        import fractions

        from av import AudioFrame

        frame = AudioFrame(format="s16", layout="mono", samples=self._samples)
        frame.planes[0].update(bytes(self._samples * 2))
        frame.pts = self._timestamp
        frame.sample_rate = self._sample_rate
        frame.time_base = fractions.Fraction(1, self._sample_rate)
        self._timestamp += self._samples
        return frame

    def _as_g711_frame(self, frame: Any) -> Any:
        """PC1/PC2 send G.711 @ 8 kHz. iOS/aiortc remote is often 48 kHz.

        Passing those frames through unchanged makes packet counters climb
        while the G.711 encoder emits silence / garbage — callee 'mute'.
        """
        import fractions

        from av import AudioFrame

        rate = int(getattr(frame, "sample_rate", 8000) or 8000)
        layout = getattr(frame, "layout", None)
        channels = int(
            getattr(layout, "nb_channels", None) or getattr(layout, "channels", 1) or 1
        )
        fmt = str(getattr(getattr(frame, "format", None), "name", "") or "")
        if rate == self._sample_rate and channels == 1 and fmt in ("s16", "s16p"):
            samples = int(getattr(frame, "samples", 0) or self._samples)
            self._timestamp += samples
            try:
                frame.pts = self._timestamp - samples
            except Exception:  # noqa: BLE001
                pass
            return frame
        pcm = _pcm_s16_mono_8k(frame)
        if not pcm:
            return self._silence_frame()
        samples = max(1, len(pcm) // 2)
        out = AudioFrame(format="s16", layout="mono", samples=samples)
        out.planes[0].update(pcm)
        out.pts = self._timestamp
        out.sample_rate = self._sample_rate
        out.time_base = fractions.Fraction(1, self._sample_rate)
        self._timestamp += samples
        return out


def _relay_subscribe(relay: Any, track: Any) -> Any:
    """MediaRelay.subscribe — never stop the source track on consumer replace."""
    try:
        return relay.subscribe(track, stop_on_cancel=False)
    except TypeError:
        wrapper = _KeepAliveRelayTrack(track)
        return relay.subscribe(wrapper)


class _KeepAliveRelayTrack(AudioStreamTrack if AudioStreamTrack is not None else object):  # type: ignore[misc]
    """MediaRelay.stop() must not kill the PC receiver (redial has no ontrack)."""

    kind = "audio"

    def __init__(self, src: Any) -> None:
        if AudioStreamTrack is None:
            raise RuntimeError("aiortc AudioStreamTrack unavailable")
        super().__init__()
        self._src = src

    async def recv(self) -> Any:  # noqa: ANN401
        return await self._src.recv()


def session_should_record(session: dict[str, Any]) -> bool:
    if session.get("voicemailActive"):
        return True
    if "callRecordingEnabled" in session:
        return bool(session.get("callRecordingEnabled"))
    route = session.get("route") or {}
    return bool(route.get("callRecordingEnabled"))


def _pcm_s16_mono_8k(frame: Any) -> bytes:
    """Best-effort PCM for the wrapper wav (8 kHz s16le mono)."""
    rate = int(getattr(frame, "sample_rate", 8000) or 8000)
    raw = b""
    channels = 1
    try:
        nd = frame.to_ndarray()
        if hasattr(nd, "shape") and len(getattr(nd, "shape", ())) == 2:
            channels = int(nd.shape[0]) or 1
            nd = nd[0]
        if hasattr(nd, "tobytes"):
            if str(getattr(nd, "dtype", "")) not in ("int16", "dtype('int16')"):
                try:
                    nd = nd.astype("int16")
                except Exception:  # noqa: BLE001
                    pass
            raw = bytes(nd.tobytes())
    except Exception:  # noqa: BLE001
        raw = b""
    if not raw:
        try:
            raw = bytes(frame.planes[0])
        except Exception:  # noqa: BLE001
            return b""
        layout = getattr(frame, "layout", None)
        channels = int(getattr(layout, "nb_channels", None) or getattr(layout, "channels", 1) or 1)
    if channels > 1 and len(raw) >= 4:
        # drop extra interleaved channels → mono
        out = bytearray()
        step = channels * 2
        for i in range(0, len(raw) - 1, step):
            out.extend(raw[i : i + 2])
        raw = bytes(out)
    if rate == 8000 or rate <= 0:
        return raw
    step = max(1, int(round(rate / 8000.0)))
    if step <= 1:
        return raw
    out = bytearray()
    for i in range(0, len(raw) - 1, 2 * step):
        out.extend(raw[i : i + 2])
    return bytes(out)


class CallRecorder:
    """Tee PCM from the existing MediaRelay consumers (no second subscribe)."""

    RATE = 8000
    MAX_BYTES = 8000 * 2 * 60 * 30  # 30 min mono per leg

    def __init__(self) -> None:
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self._left = bytearray()
        self._right = bytearray()
        self._stopped = False
        self._wav: Optional[bytes] = None

    def push(self, leg: str, frame: Any) -> None:
        if self._stopped:
            return
        pcm = _pcm_s16_mono_8k(frame)
        if not pcm:
            return
        buf = self._left if leg == "sbc" else self._right
        if len(buf) >= self.MAX_BYTES:
            return
        room = self.MAX_BYTES - len(buf)
        buf.extend(pcm[:room])

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self.ended_at = time.time()

    def wav_bytes(self) -> bytes:
        if self._wav is not None:
            return self._wav
        self.stop()
        n = max(len(self._left), len(self._right))
        if n < 2:
            self._wav = b""
            return self._wav
        left = self._left + (b"\x00" * (n - len(self._left)))
        right = self._right + (b"\x00" * (n - len(self._right)))
        stereo = bytearray(n * 2)
        for i in range(0, n, 2):
            stereo[i * 2 : i * 2 + 2] = left[i : i + 2]
            stereo[i * 2 + 2 : i * 2 + 4] = right[i : i + 2]
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(2)
            wf.setsampwidth(2)
            wf.setframerate(self.RATE)
            wf.writeframes(bytes(stereo))
        self._wav = buf.getvalue()
        return self._wav

    def had_audio(self) -> bool:
        return len(self._left) >= 320 or len(self._right) >= 320


class _TeeAudioTrack(AudioStreamTrack if AudioStreamTrack is not None else object):  # type: ignore[misc]
    kind = "audio"

    def __init__(self, source: Any, recorder: CallRecorder, leg: str) -> None:
        if AudioStreamTrack is None:
            raise RuntimeError("aiortc AudioStreamTrack unavailable")
        super().__init__()
        self._source = source
        self._recorder = recorder
        self._leg = leg

    async def recv(self) -> Any:  # noqa: ANN401
        frame = await self._source.recv()
        try:
            self._recorder.push(self._leg, frame)
        except Exception:  # noqa: BLE001
            pass
        return frame


def _maybe_tee_recording(session: dict[str, Any], track: Any, leg: str) -> Any:
    if not session_should_record(session) or AudioStreamTrack is None:
        return track
    rec = session.get("callRecorder")
    if rec is None:
        rec = CallRecorder()
        session["callRecorder"] = rec
        session["recordingStartedAt"] = rec.started_at
        log.info(f"RECORD: tee armed session={session.get('sessionId')} leg={leg}")
    return _TeeAudioTrack(track, rec, leg)


def finalize_recording(session: Optional[dict[str, Any]]) -> Optional[bytes]:
    if not session:
        return None
    rec = session.get("callRecorder")
    if rec is None:
        return session.get("recordingWav")
    rec.stop()
    if not rec.had_audio():
        session["recordingWav"] = b""
        return b""
    wav = rec.wav_bytes()
    session["recordingWav"] = wav
    session["recordingEndedAt"] = rec.ended_at or time.time()
    log.info(
        f"RECORD: finalized session={session.get('sessionId')} bytes={len(wav)} "
        f"secs={int((session['recordingEndedAt'] - rec.started_at))}"
    )
    return wav


def use_media_worker() -> bool:
    """True only when siphon.peer is loaded. There is no aiortc fallback."""
    try:
        from siphon import peer

        if peer.available():
            return True
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "siphon.peer is not available. Build siphon-edge; there is no aiortc fallback."
        ) from exc
    raise RuntimeError(
        "siphon.peer is not available. Build siphon-edge; there is no aiortc fallback."
    )


use_media_worker()


def _require_aiortc() -> None:
    if use_media_worker():
        return
    if _AIORTC_IMPORT_ERROR is not None or RTCPeerConnection is None:
        raise RuntimeError(
            f"aiortc is required for PC1 handshake: {_AIORTC_IMPORT_ERROR}"
        )


def _ice_servers() -> list[Any]:
    _require_aiortc()
    import media_worker as _mw

    out: list[Any] = []
    for entry in _mw.ice_servers():
        kwargs: dict[str, Any] = {"urls": entry["urls"]}
        if entry.get("username") is not None:
            kwargs["username"] = entry["username"]
            kwargs["credential"] = entry.get("credential")
        out.append(RTCIceServer(**kwargs))
    return out


def _pc_config() -> Any:
    """max-bundle: RING audio must ride the DC ICE/DTLS, not a second port.

    Default aiortc max-compat gave us `BUNDLE 0 1` + `m=audio 47166` while iOS
    answered `m=audio 9`. RTP went to the DC 5-tuple; we listened on 47166.
    """
    servers = _ice_servers()
    try:
        return RTCConfiguration(iceServers=servers, bundlePolicy="max-bundle")
    except TypeError:
        cfg = RTCConfiguration(iceServers=servers)
        try:
            cfg.bundlePolicy = "max-bundle"
        except Exception:  # noqa: BLE001
            pass
        return cfg


def _sdp_has_active_audio(sdp: str) -> bool:
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


def is_inactive_offer(sdp: str) -> bool:
    """True when offer has no active sendrecv audio (teardown / DC-only reneg)."""
    text = str(sdp or "").replace("\r\n", "\n")
    sections = re.split(r"(?=^m=)", text, flags=re.M)
    audio = next((s for s in sections if s.startswith("m=audio ")), "")
    if not audio:
        return True
    return bool(re.search(r"^a=inactive", audio, re.M)) and not bool(
        re.search(r"^a=sendrecv", audio, re.M)
    )


def _split_sdp_sections(sdp: str) -> tuple[str, list[str]]:
    """Node sdp.js splitSdpSections — session + media m-lines."""
    normalized = str(sdp or "").replace("\r\n", "\n").replace("\n", "\r\n")
    parts = re.split(r"\r\n(?=m=)", normalized)
    if not parts:
        return "", []
    return parts[0], parts[1:]


def _media_kind(section: str) -> Optional[str]:
    m = re.match(r"^m=([^\s]+)", section or "", re.M)
    return m.group(1) if m else None


def _media_mid(section: str) -> Optional[str]:
    m = re.search(r"^a=mid:([^\r\n]+)", section or "", re.M)
    return m.group(1) if m else None


def _bundle_mids(sdp: str) -> list[str]:
    match = re.search(r"^a=group:BUNDLE\s+([^\r\n]+)", str(sdp or ""), re.M)
    if not match:
        return []
    return [part for part in match.group(1).split() if part]


def stamp_answer_mids(answer: str, offer: str) -> str:
    """Copy each offer m-line's mid onto the answer section.

    Android's RING answer omits ``a=mid`` on ``m=audio``. str0m then rejects
    the whole answer (``Media is missing a=mid``) and the callee never bridges.
    Offer mids win. ``a=group:BUNDLE`` on the answer is the fallback when the
    stored offer is missing.
    """
    if not answer:
        return answer
    _, offer_media = _split_sdp_sections(offer)
    offer_mids = [_media_mid(section) or "" for section in offer_media]
    bundle = _bundle_mids(offer) or _bundle_mids(answer)
    session, answer_media = _split_sdp_sections(answer)
    if not answer_media:
        return answer
    stamped: list[str] = []
    changed = False
    for index, section in enumerate(answer_media):
        mid = offer_mids[index] if index < len(offer_mids) else ""
        if not mid and index < len(bundle):
            mid = bundle[index]
        if not mid or _media_mid(section) == mid:
            stamped.append(section)
            continue
        changed = True
        body = re.sub(r"^a=mid:[^\r\n]*\r\n", "", section, flags=re.M)
        stamped.append(_replace_or_insert_mid(body, mid))
    if not changed:
        return answer
    ending = "\r\n" if str(answer).endswith("\r\n") else ""
    return session.rstrip("\r\n") + "\r\n" + "\r\n".join(stamped) + ending


def _replace_or_insert_mid(section: str, mid: Optional[str]) -> str:
    if not mid:
        return section
    if re.search(r"^a=mid:", section, re.M):
        return re.sub(r"^a=mid:[^\r\n]+", f"a=mid:{mid}", section, count=1, flags=re.M)
    updated = re.sub(
        r"^(m=[^\r\n]+)(?:\r\n)?",
        rf"\1\r\na=mid:{mid}\r\n",
        section,
        count=1,
        flags=re.M,
    )
    if updated == section and section.startswith("m="):
        return f"{section}\r\na=mid:{mid}\r\n"
    return updated


def _sdp_parts(sdp: str) -> tuple[str, list[str], str]:
    raw = str(sdp or "")
    ending = "\r\n" if "\r\n" in raw else "\n"
    text = raw.replace("\r\n", "\n")
    parts = re.split(r"(?=^m=)", text, flags=re.M)
    session = parts[0] if parts else ""
    media = [part for part in parts[1:] if part.startswith("m=")]
    return session, media, ending


def _join_sdp(session: str, media: list[str], ending: str) -> str:
    body = session.rstrip("\n")
    chunks = [body]
    for section in media:
        chunks.append(section.strip("\n"))
    text = "\n".join(chunks) + "\n"
    if ending == "\r\n":
        text = text.replace("\n", "\r\n")
    return text


def _reject_mline(section: str) -> str:
    """Port 0 this section so its mid stays in the m-line order."""
    lines: list[str] = []
    inactive = False
    for line in section.replace("\r\n", "\n").split("\n"):
        if line.startswith("m="):
            bits = line.split()
            if len(bits) >= 2:
                bits[1] = "0"
                line = " ".join(bits)
        if line.startswith(("a=sendrecv", "a=sendonly", "a=recvonly")):
            line = "a=inactive"
            inactive = True
        elif line.startswith("a=inactive"):
            inactive = True
        if line.startswith("a=candidate:"):
            continue
        lines.append(line)
    while lines and lines[-1] == "":
        lines.pop()
    if not inactive:
        lines.append("a=inactive")
    return "\n".join(lines) + "\n"


def pin_established_mlines(offer: str, previous: str) -> str:
    """Keep mids str0m already accepted, then append the new ones.

    A redial that puts a new audio mid where mid 1 used to be is rejected
    with ``Changed order for m-line with mid``. The remote should have
    left the old m-line at port 0. Do that before setRemote.
    """
    if not previous or not offer:
        return offer
    session, offer_media, ending = _sdp_parts(offer)
    _, prev_media, _ = _sdp_parts(previous)
    prev_mids = [_media_mid(section) or "" for section in prev_media]
    offer_mids = [_media_mid(section) or "" for section in offer_media]
    if not any(prev_mids) or offer_mids[: len(prev_mids)] == prev_mids:
        return offer
    offer_by_mid = {
        mid: section for mid, section in zip(offer_mids, offer_media) if mid
    }
    rebuilt: list[str] = []
    used: set[str] = set()
    for mid, section in zip(prev_mids, prev_media):
        if not mid:
            continue
        if mid in offer_by_mid:
            rebuilt.append(offer_by_mid[mid])
        else:
            rebuilt.append(_reject_mline(section))
        used.add(mid)
    for mid, section in zip(offer_mids, offer_media):
        if mid and mid not in used:
            rebuilt.append(section)
            used.add(mid)
    return _join_sdp(session, rebuilt, ending)


def answer_for_client_mids(answer: str, client_offer: str) -> str:
    """Drop m-lines we inserted only so str0m would keep its order."""
    if not answer or not client_offer:
        return answer
    _, offer_media, _ = _sdp_parts(client_offer)
    want = [mid for mid in (_media_mid(section) for section in offer_media) if mid]
    session, answer_media, ending = _sdp_parts(answer)
    have = [_media_mid(section) or "" for section in answer_media]
    if have == want:
        return answer
    by_mid = {mid: section for mid, section in zip(have, answer_media) if mid}
    if any(mid not in by_mid for mid in want):
        return answer
    bundle = _bundle_mids(client_offer) or want
    session = re.sub(
        r"^a=group:BUNDLE[^\n]*",
        "a=group:BUNDLE " + " ".join(bundle),
        session,
        count=1,
        flags=re.M,
    )
    return _join_sdp(session, [by_mid[mid] for mid in want], ending)


def _keep_inactive_audio_reusable(answer_section: str, offer_section: str) -> str:
    """Port 0 → 9 on inactive audio so the mid stays reusable for the next call."""
    if _media_kind(answer_section) != "audio":
        return answer_section
    if not re.search(r"^a=inactive", offer_section or "", re.M):
        return answer_section
    return re.sub(r"^m=audio\s+0\s+", "m=audio 9 ", answer_section, count=1, flags=re.M)


def _keep_generated_inactive_audio_reusable(section: str) -> str:
    if _media_kind(section) != "audio":
        return section
    return re.sub(r"^m=audio\s+0\s+", "m=audio 9 ", section, count=1, flags=re.M)


def _set_bundle_mids(session_section: str, mids: list[str]) -> str:
    if not mids:
        return session_section
    bundle = f"a=group:BUNDLE {' '.join(mids)}"
    if re.search(r"^a=group:BUNDLE\s+", session_section, re.M):
        return re.sub(
            r"^a=group:BUNDLE\s+[^\r\n]+",
            bundle,
            session_section,
            count=1,
            flags=re.M,
        )
    return session_section.rstrip("\r\n") + "\r\n" + bundle + "\r\n"


def normalize_end_call_offer_sdp(offer_sdp: str) -> str:
    """Node normalizeEndCallOfferSdp — BUNDLE mids + keep inactive audio port 9."""
    session, media = _split_sdp_sections(offer_sdp)
    mids = [m for m in (_media_mid(s) for s in media) if m]
    session = _set_bundle_mids(session, mids)
    media = [_keep_generated_inactive_audio_reusable(s) for s in media]
    out = "\r\n".join([session, *media])
    return re.sub(r"(\r\n){3,}", "\r\n\r\n", out)


def align_end_call_answer_sdp(answer_sdp: str, offer_sdp: str) -> str:
    """Node alignEndCallAnswerSdp — copy offer BUNDLE/mids + port-9 reuse."""
    offer_session, offer_media = _split_sdp_sections(offer_sdp)
    answer_session, answer_media = _split_sdp_sections(answer_sdp)
    bundle_m = re.search(r"^a=group:BUNDLE\s+([^\r\n]+)", offer_session, re.M)
    offer_bundle = bundle_m.group(1) if bundle_m else None
    session = answer_session
    if offer_bundle:
        if re.search(r"^a=group:BUNDLE\s+", session, re.M):
            session = re.sub(
                r"^a=group:BUNDLE\s+[^\r\n]+",
                f"a=group:BUNDLE {offer_bundle}",
                session,
                count=1,
                flags=re.M,
            )
        else:
            session = session.rstrip("\r\n") + f"\r\na=group:BUNDLE {offer_bundle}\r\n"
    media: list[str] = []
    for index, section in enumerate(answer_media):
        offer_section = offer_media[index] if index < len(offer_media) else ""
        mid = _media_mid(offer_section)
        media.append(
            _keep_inactive_audio_reusable(_replace_or_insert_mid(section, mid), offer_section)
        )
    out = "\r\n".join([session, *media])
    return re.sub(r"(\r\n){3,}", "\r\n\r\n", out)


def format_ice_candidates(raw: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in raw or []:
        if c is None:
            continue
        if isinstance(c, dict):
            cand = c.get("candidate")
            if not cand:
                continue
            out.append(
                {
                    "sdpMid": str(c.get("sdpMid") if c.get("sdpMid") is not None else "0"),
                    "sdpMLineIndex": c.get("sdpMLineIndex"),
                    "candidate": cand,
                }
            )
            continue
        cand = getattr(c, "candidate", None)
        if not cand:
            continue
        out.append(
            {
                "sdpMid": str(getattr(c, "sdpMid", None) if getattr(c, "sdpMid", None) is not None else "0"),
                "sdpMLineIndex": getattr(c, "sdpMLineIndex", None),
                "candidate": cand,
            }
        )
    return out


def candidates_from_sdp(sdp: str) -> list[dict[str, Any]]:
    """Parse a=candidate lines out of SDP (aiortc embeds them; no trickle events).

    str0m prints `a=candidate` above `a=mid`. The mid for that section is the
    one that follows, not the default "0" still in scope when the candidate
    line is seen. Android matches trickle on sdpMid and drops "0" against
    `a=mid:6Bv`.
    """
    out: list[dict[str, Any]] = []
    line_ending = "\r\n" if "\r\n" in (sdp or "") else "\n"
    section_idx = -1
    mid = "0"
    pending: list[dict[str, Any]] = []

    def _flush() -> None:
        for cand in pending:
            cand["sdpMid"] = mid
            out.append(cand)
        pending.clear()

    for raw_line in str(sdp or "").split(line_ending):
        line = raw_line.strip()
        if line.startswith("m="):
            if section_idx >= 0:
                _flush()
            section_idx += 1
            mid = "0"
            continue
        if line.startswith("a=mid:"):
            mid = line.split(":", 1)[1].strip() or "0"
            continue
        if not line.startswith("a=candidate:"):
            continue
        cand = re.sub(r"\s+ufrag\s+\S+", "", line[len("a=") :])
        pending.append(
            {
                "sdpMid": mid,
                "sdpMLineIndex": max(section_idx, 0),
                "candidate": cand,
            }
        )
    if section_idx >= 0:
        _flush()
    return out


def prefer_relay_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Node getRelayCandidates: prefer typ relay when any exist (relay-only mobiles)."""
    relay = [
        c
        for c in (candidates or [])
        if "typ relay" in str(c.get("candidate") or "")
    ]
    return relay if relay else list(candidates or [])


def candidates_for_client(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Candidates the phone will actually add.

    iOS and Android strip a=candidate out of the remote SDP and install this
    array. Relay-only leaves no pair when that socket resets. Match the
    client's own offer filter: drop TCP and IPv6, keep every relay, 2 srflx, 1 host.
    """
    relay: list[dict[str, Any]] = []
    srflx: list[dict[str, Any]] = []
    host: list[dict[str, Any]] = []
    for c in candidates or []:
        text = str(c.get("candidate") or "").lower()
        if " tcp " in f" {text} ":
            continue
        head = text.split(" typ ", 1)[0]
        if head.count(":") > 1:
            continue
        if "typ relay" in text:
            relay.append(c)
        elif "typ srflx" in text:
            srflx.append(c)
        elif "typ host" in text:
            host.append(c)
    picked = relay + srflx[:2] + host[:1]
    if picked:
        return picked
    rest = [
        c
        for c in (candidates or [])
        if " tcp " not in f" {str(c.get('candidate') or '').lower()} "
    ]
    return rest[:5]


def sdp_media_summary(sdp: str) -> str:
    """One-line m=/BUNDLE/ufrag/direction for RING logs."""
    text = str(sdp or "")
    bits: list[str] = []
    bundle = re.search(r"^a=group:BUNDLE\s+([^\r\n]+)", text, re.M)
    bits.append(f"bundle={(bundle.group(1).strip() if bundle else '-')!r}")
    ufrag = re.search(r"^a=ice-ufrag:([^\r\n]+)", text, re.M)
    bits.append(f"ufrag={ufrag.group(1) if ufrag else '-'}")
    for line in text.replace("\r\n", "\n").split("\n"):
        s = line.strip()
        if s.startswith("m=") or s.startswith("a=mid:"):
            bits.append(s[:72])
        elif s in ("a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"):
            bits.append(s)
        elif s.startswith("a=ssrc:") and "cname:" in s:
            bits.append(s.split()[0])
    return " ".join(bits)


def ensure_bundle_all_mids(sdp: str) -> str:
    """BUNDLE every mid and set non-first m-line ports to 9 (RFC 8843).

    A BUNDLE group with `m=audio <realport>` is not bundled — iOS answers
    `m=audio 9` and sends RTP on the DC transport; we never see PC2:in.
    """
    session, media = _split_sdp_sections(sdp)
    mids = [m for m in (_media_mid(s) for s in media) if m]
    if not mids:
        return sdp
    session = _set_bundle_mids(session, mids)
    bundled = [media[0]]
    for sec in media[1:]:
        bundled.append(re.sub(r"^m=(\S+)\s+\d+\s+", r"m=\1 9 ", sec, count=1, flags=re.M))
    line_ending = "\r\n" if "\r\n" in str(sdp or "") else "\n"
    return session.rstrip("\r\n") + line_ending + line_ending.join(bundled)


def force_bundle_ports(sdp: str) -> str:
    """Renegotiation: every m-line port 9 so audio stays on the live DC ICE.

    HTTP answer is already `m=audio 9`. RING with `m=audio <hostport>` makes
    iOS gather a new audio ICE (e.g. 62778) → we send RTP at a LAN port and
    PC2:in=0. First invite still uses a real tag port for the initial gather.
    """
    session, media = _split_sdp_sections(sdp)
    if not media:
        return sdp
    bundled = [
        re.sub(r"^m=(\S+)\s+\d+\s+", r"m=\1 9 ", sec, count=1, flags=re.M)
        for sec in media
    ]
    line_ending = "\r\n" if "\r\n" in str(sdp or "") else "\n"
    return session.rstrip("\r\n") + line_ending + line_ending.join(bundled)


def _sdp_ice_ufrag_pwd(sdp: str) -> tuple[Optional[str], Optional[str]]:
    u = re.search(r"^a=ice-ufrag:(\S+)", str(sdp or ""), re.M)
    p = re.search(r"^a=ice-pwd:(\S+)", str(sdp or ""), re.M)
    return (u.group(1) if u else None), (p.group(1) if p else None)


def _set_sdp_ice_ufrag_pwd(sdp: str, ufrag: str, pwd: str) -> str:
    sdp = re.sub(r"^a=ice-ufrag:\S+", f"a=ice-ufrag:{ufrag}", str(sdp or ""), flags=re.M)
    sdp = re.sub(r"^a=ice-pwd:\S+", f"a=ice-pwd:{pwd}", sdp, flags=re.M)
    return sdp


def _sdp_attr_line(section: str, name: str) -> Optional[str]:
    m = re.search(rf"^a={re.escape(name)}:[^\r\n]+", section or "", re.M)
    return m.group(0) if m else None


def strip_audio_sections_for_wire(sdp: str) -> str:
    """HTTP invite stays DC-only. Local PC still has the inactive audio m-line."""
    session, media = _split_sdp_sections(sdp)
    kept = [s for s in media if _media_kind(s) != "audio"]
    if not media or len(kept) == len(media):
        return sdp
    mids = [m for m in (_media_mid(s) for s in kept) if m]
    session = _set_bundle_mids(session, mids)
    return session.rstrip("\r\n") + "\r\n" + "\r\n".join(kept)


def inject_inactive_audio_into_answer(answer_sdp: str, local_sdp: str) -> str:
    """Match a DC-only HTTP answer to a local offer that reserved m=audio.

    aiortc allocates a new IceTransport when addTrack invents m=audio after
    DC is up (ice=new + 300ms gather). iOS then answers bundled `m=audio 9`
    on the live DC 5-tuple → PC2:in=0. Reserve the mid in the first
    setLocal, strip it from the wire, and splice inactive audio into the
    HTTP answer so RING only changes direction.
    """
    ans_session, ans_media = _split_sdp_sections(answer_sdp)
    _, loc_media = _split_sdp_sections(local_sdp)
    if any(_media_kind(s) == "audio" for s in ans_media):
        return answer_sdp
    loc_audio = next((s for s in loc_media if _media_kind(s) == "audio"), None)
    if not loc_audio:
        return answer_sdp
    bundle_src = ans_media[0] if ans_media else ans_session
    audio = re.sub(r"^m=audio\s+\d+\s+", "m=audio 9 ", loc_audio, count=1, flags=re.M)
    audio = re.sub(
        r"^a=(sendrecv|sendonly|recvonly|inactive)[^\r\n]*",
        "a=inactive",
        audio,
        flags=re.M,
    )
    if not re.search(r"^a=inactive", audio, re.M):
        audio = audio.rstrip("\r\n") + "\r\na=inactive"
    audio = re.sub(r"^a=candidate:[^\r\n]*\r\n?", "", audio, flags=re.M)
    audio = re.sub(r"^a=ssrc:[^\r\n]*\r\n?", "", audio, flags=re.M)
    audio = re.sub(r"^a=ssrc-group:[^\r\n]*\r\n?", "", audio, flags=re.M)
    audio = re.sub(r"^a=msid:[^\r\n]*\r\n?", "", audio, flags=re.M)
    audio = re.sub(r"^a=rtcp:[^\r\n]*\r\n?", "", audio, flags=re.M)
    for name in ("ice-ufrag", "ice-pwd", "ice-options", "fingerprint"):
        line = _sdp_attr_line(bundle_src, name) or _sdp_attr_line(ans_session, name)
        if not line:
            continue
        if re.search(rf"^a={re.escape(name)}:", audio, re.M):
            audio = re.sub(rf"^a={re.escape(name)}:[^\r\n]+", line, audio, flags=re.M)
        else:
            audio = audio.rstrip("\r\n") + "\r\n" + line
    setup = _sdp_attr_line(bundle_src, "setup") or "a=setup:active"
    if re.search(r"^a=setup:", audio, re.M):
        audio = re.sub(r"^a=setup:[^\r\n]+", setup, audio, flags=re.M)
    else:
        audio = audio.rstrip("\r\n") + "\r\n" + setup
    media = list(ans_media) + [audio.rstrip("\r\n") + "\r\n"]
    mids = [m for m in (_media_mid(s) for s in media) if m]
    session = _set_bundle_mids(ans_session, mids)
    return session.rstrip("\r\n") + "\r\n" + "\r\n".join(
        s.rstrip("\r\n") + "\r\n" for s in media
    )


def _reserve_inactive_audio_transceiver(pc: Any, track: Any = None) -> None:
    """Add m=audio on the first local offer so ICE/DTLS already includes it.

    werift addTrack after DC reuses the live DTLS. aiortc does not — RING
    addTrack → ice=new → PC2:in=0/out dead. HTTP still has the audio m-line
    (inactive). Do not strip it.
    """
    if track is not None:
        try:
            pc.addTransceiver(track, direction="inactive")
            return
        except TypeError:
            try:
                pc.addTransceiver(track)
            except Exception:  # noqa: BLE001
                pc.addTrack(track)
            tr = _audio_transceiver(pc)
            try:
                if tr is not None:
                    tr.direction = "inactive"
            except Exception:  # noqa: BLE001
                pass
            return
    try:
        pc.addTransceiver("audio", direction="inactive")
        return
    except TypeError:
        pass
    tr = pc.addTransceiver("audio")
    try:
        tr.direction = "inactive"
    except Exception:  # noqa: BLE001
        pass


def udp_ice_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """RING renegotiation: keep host. srflx+relay-only is for the first DC invite."""
    return [
        c
        for c in (candidates or [])
        if " tcp " not in str(c.get("candidate") or "").lower()
    ]


async def create_sdp_offer(pc: Any, *, ice_restart: Optional[bool] = None) -> Any:
    if ice_restart is None:
        return await pc.createOffer()
    try:
        return await pc.createOffer(iceRestart=ice_restart)
    except TypeError:
        try:
            from aiortc import RTCOfferOptions

            return await pc.createOffer(RTCOfferOptions(iceRestart=ice_restart))
        except Exception:  # noqa: BLE001
            return await pc.createOffer()


def prefer_srflx_and_relay(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Node outbound WebRTC invite: srflx+relay (not relay-only) — avoids TURN hairpin fail."""
    filtered = []
    for c in candidates or []:
        text = str(c.get("candidate") or "")
        if " tcp " in text.lower():
            continue
        if "typ srflx" in text or "typ relay" in text:
            filtered.append(c)
    return filtered if filtered else [
        c
        for c in (candidates or [])
        if " tcp " not in str(c.get("candidate") or "").lower()
    ]


def _ice_candidate_text(c: Any) -> str:
    if isinstance(c, dict):
        return str(c.get("candidate") or "")
    return str(getattr(c, "candidate", None) or "")


def ice_has_relay(candidates: Optional[list[Any]]) -> bool:
    return any("typ relay" in _ice_candidate_text(c) for c in candidates or [])


def ice_has_srflx_or_relay(candidates: Optional[list[Any]]) -> bool:
    for c in candidates or []:
        text = _ice_candidate_text(c)
        if "typ srflx" in text or "typ relay" in text:
            return True
    return False


def merge_ice_array_and_sdp(
    sdp: str, candidates: Optional[list[Any]] = None
) -> list[dict[str, Any]]:
    """Client ICE can live in the array XOR in SDP — apply both."""
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for c in list(candidates or []) + candidates_from_sdp(sdp):
        if not c:
            continue
        if isinstance(c, dict):
            text = str(c.get("candidate") or "")
            item = c
        else:
            text = str(getattr(c, "candidate", None) or "")
            item = {
                "candidate": text,
                "sdpMid": getattr(c, "sdpMid", "0"),
                "sdpMLineIndex": getattr(c, "sdpMLineIndex", 0),
            }
        if not text or text in seen:
            continue
        seen.add(text)
        merged.append(item)
    return merged


def candidate_type_counts(candidates: list[dict[str, Any]]) -> str:
    counts = {"host": 0, "srflx": 0, "relay": 0, "prflx": 0, "other": 0}
    for c in candidates or []:
        text = _ice_candidate_text(c)
        if "typ relay" in text:
            counts["relay"] += 1
        elif "typ srflx" in text:
            counts["srflx"] += 1
        elif "typ prflx" in text:
            counts["prflx"] += 1
        elif "typ host" in text:
            counts["host"] += 1
        else:
            counts["other"] += 1
    return (
        f"host={counts['host']} srflx={counts['srflx']} "
        f"relay={counts['relay']} prflx={counts['prflx']} other={counts['other']}"
    )


def embed_candidates_in_sdp(sdp: str, candidates: list[dict[str, Any]]) -> str:
    """Ensure candidates are present in SDP (idempotent if already embedded)."""
    if not candidates:
        return sdp

    def _cand_key(raw: str) -> str:
        s = str(raw or "").strip()
        if s.startswith("a="):
            s = s[2:].strip()
        return s.split(" ufrag ", 1)[0].strip()

    existing = {_cand_key(str(c.get("candidate") or "")) for c in candidates_from_sdp(sdp)}
    to_add = [
        c
        for c in candidates
        if _cand_key(str(c.get("candidate") or "")) not in existing
    ]
    if not to_add:
        return sdp

    by_section: dict[int, list[str]] = {}
    for c in to_add:
        idx = int(c.get("sdpMLineIndex") if c.get("sdpMLineIndex") is not None else 0)
        raw = str(c.get("candidate") or "")
        if raw.startswith("candidate:"):
            raw = raw[len("candidate:") :]
        by_section.setdefault(idx, []).append(raw)

    line_ending = "\r\n" if "\r\n" in sdp else "\n"
    # Strip prior end-of-candidates so we can re-append after new lines.
    lines = [ln for ln in sdp.split(line_ending) if ln.strip() != "a=end-of-candidates"]
    result: list[str] = []
    section_idx = -1
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("m="):
            if section_idx >= 0 and section_idx in by_section:
                for c in by_section[section_idx]:
                    result.append(f"a=candidate:{c}")
                result.append("a=end-of-candidates")
            section_idx += 1
        if line != "":
            result.append(line)
    if section_idx >= 0 and section_idx in by_section:
        for c in by_section[section_idx]:
            result.append(f"a=candidate:{c}")
        result.append("a=end-of-candidates")
    return line_ending.join(result) + line_ending


async def _wait_ice_gathering(pc: Any, timeout_s: float = ICE_GATHER_TIMEOUT_SECS) -> None:
    """Poll iceGatheringState — aiortc does not reliably fire icecandidate events."""
    deadline = asyncio.get_running_loop().time() + timeout_s
    while pc.iceGatheringState != "complete":
        if asyncio.get_running_loop().time() >= deadline:
            log.warn(
                f"PC1: ICE gather timeout state={pc.iceGatheringState}; "
                "continuing with whatever is in localDescription"
            )
            return
        await asyncio.sleep(0.05)


def _bind_pc_events(session: dict[str, Any], pc: Any) -> None:
    session_id = session.get("sessionId") or "?"
    session.setdefault("iceCandidates", [])

    @pc.on("icegatheringstatechange")
    def _on_gather() -> None:
        log.info(
            f"PC1: session={session_id} iceGatheringState={pc.iceGatheringState}"
        )

    @pc.on("iceconnectionstatechange")
    def _on_ice_conn() -> None:
        log.info(
            f"PC1: session={session_id} iceConnectionState={getattr(pc, 'iceConnectionState', '?')}"
        )

    @pc.on("connectionstatechange")
    def _on_conn() -> None:
        state = getattr(pc, "connectionState", "?")
        log.info(f"PC1: session={session_id} connectionState={state}")

    @pc.on("datachannel")
    def _on_dc(channel: Any) -> None:
        label = getattr(channel, "label", "") or ""
        log.info(f"PC1: session={session_id} datachannel received label={label!r}")
        session["dataChannel"] = channel

        @channel.on("open")
        def _on_open() -> None:
            log.info(f"PC1: session={session_id} datachannel OPEN")
            session["dcOpen"] = True

        @channel.on("close")
        def _on_close() -> None:
            log.info(f"PC1: session={session_id} datachannel CLOSED")
            session["dcOpen"] = False

        @channel.on("message")
        def _on_message(message: Any) -> None:
            raw = message.decode() if isinstance(message, (bytes, bytearray)) else str(message)
            _handle_dc_message(session, raw)

        if str(getattr(channel, "readyState", "") or "").lower() == "open":
            session["dcOpen"] = True
            log.info(f"PC1: session={session_id} datachannel already open")


def _session_loop(session: dict[str, Any]) -> Optional[asyncio.AbstractEventLoop]:
    loop = session.get("eventLoop")
    if loop is not None:
        return loop
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _running_loop() -> Optional[asyncio.AbstractEventLoop]:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _resolve_future(fut: Optional[asyncio.Future], value: Any = True) -> None:
    """Complete a future on the loop that owns it (HTTP / aiortc may differ)."""
    if fut is None or fut.done():
        return

    def _set() -> None:
        if not fut.done():
            fut.set_result(value)

    loop = fut.get_loop()
    running = _running_loop()
    if running is loop:
        _set()
    elif loop.is_running():
        loop.call_soon_threadsafe(_set)
    else:
        _set()


def _schedule(session: dict[str, Any], coro: Awaitable[Any], *, label: str) -> None:
    session_id = session.get("sessionId") or "?"
    loop = _session_loop(session)
    if loop is None:
        log.error(f"PC1: session={session_id} no event loop for {label}")
        return

    async def _run() -> None:
        try:
            await coro
        except Exception as exc:  # noqa: BLE001
            log.error(f"PC1: session={session_id} {label} failed: {exc}")

    def _start() -> None:
        loop.create_task(_run())

    running = _running_loop()
    if running is loop:
        _start()
    elif loop.is_running():
        loop.call_soon_threadsafe(_start)
    else:
        log.error(f"PC1: session={session_id} session loop not running for {label}")


def _normalize_call_id(value: Any) -> Optional[int]:
    """Client WebRtcNegotiation only accepts positive ints (parseInt)."""
    if value is None or value == "":
        return None
    try:
        n = int(str(value).strip(), 10)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _ensure_session_call_id(session: dict[str, Any]) -> int:
    call_id = _normalize_call_id(session.get("activeCallId"))
    if call_id is None:
        call_id = _normalize_call_id(session.get("callNonce"))
    if call_id is None:
        call_id = max(1, (int(time.time() * 1000) % 1_000_000_000) + random.randint(0, 999))
    session["activeCallId"] = call_id
    return call_id


def _leg_ident(session: dict[str, Any], leg: str) -> str:
    leg = str(leg or "")
    if leg == "pc1":
        return "pc1"
    if leg.startswith("callee:"):
        return leg.split(":", 1)[1]
    if leg and leg != "callee":
        return leg
    return str(session.get("multiringWinner") or session.get("to") or "")


def _other_seat_ring_id(session: dict[str, Any], ident: str, cid: Optional[int]) -> bool:
    """True when cid is a RING id we minted for a different seat.

    The caller keeps the id from its own offer. iOS drops call/end and
    end-call when the id is the callee RING id. Android does the same for
    signaling/end-call.
    """
    if cid is None:
        return False
    for key, val in session.items():
        if not isinstance(key, str) or not key.startswith("ringCallId:"):
            continue
        seat = key.split(":", 1)[1]
        if seat == ident:
            continue
        if _normalize_call_id(val) == cid:
            return True
    return False


def _fresh_audio_offer(msg: dict[str, Any]) -> bool:
    """A new call attempt from this phone. That id replaces the previous one."""
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    action = str(msg.get("action") or payload.get("type") or "").lower()
    if action == "end-call":
        return False
    sdp = str(payload.get("sdp") or "")
    return (
        str(payload.get("type") or "").lower() == "offer"
        and bool(sdp.strip())
        and not is_inactive_offer(sdp)
        and _sdp_has_active_audio(sdp)
    )


def _note_leg_call_id(session: dict[str, Any], leg: str, msg: dict[str, Any]) -> None:
    """Remember the callId this phone put on its own DC message.

    Hangup must echo that id. The callee RING id is a different number and
    the other phone ignores it.
    """
    if not isinstance(msg, dict):
        return
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    cid = _normalize_call_id(msg.get("callId"))
    if cid is None:
        cid = _normalize_call_id(payload.get("callId"))
    if cid is None:
        return
    ident = _leg_ident(session, leg)
    if not ident:
        return
    if _other_seat_ring_id(session, ident, cid):
        return
    existing = _normalize_call_id(session.get(f"legCallId:{ident}"))
    own_ring = _normalize_call_id(session.get(f"ringCallId:{ident}"))
    # Latest RING we sent this seat is the id they adopted. A reused session
    # keeps the previous legCallId via setdefault; the answer has to replace it.
    if (
        existing is not None
        and existing != cid
        and cid != own_ring
        and not _fresh_audio_offer(msg)
    ):
        return
    session[f"legCallId:{ident}"] = cid


def _call_id_for_leg(session: dict[str, Any], leg: str) -> Optional[int]:
    """Id this leg will accept on call/end and signaling/end-call.

    The callee's own messages win. Otherwise the RING id we sent them, which
    they adopted. Never the other leg's id, and never a freshly minted one.
    """
    ident = _leg_ident(session, leg)
    if not ident:
        return None
    cid = _normalize_call_id(session.get(f"legCallId:{ident}"))
    if cid is not None and _other_seat_ring_id(session, ident, cid):
        cid = None
    if cid is not None:
        return cid
    if ident != "pc1":
        return _normalize_call_id(session.get(f"ringCallId:{ident}"))
    return None


def _with_call_id(message: dict[str, Any], call_id: Optional[int]) -> dict[str, Any]:
    if call_id is not None:
        message["callId"] = call_id
    return message


def send_dc_end_call(session: dict[str, Any], reason: str = "hangup") -> None:
    """Node sendEndCallSignal + iOS call/end (CallKit only ends on call/end).

    Outbound: PC1 DC (caller). Inbound SBC→WebRTC: callee DC (phone).
    """
    if session.get("clientEnded"):
        return
    call_id = _ensure_session_call_id(session)
    msg_signaling = {
        "msgType": "signaling",
        "action": "end-call",
        "callId": call_id,
        "reason": reason,
        "payload": {"callId": call_id, "type": "end-call", "reason": reason},
    }
    msg_end = {
        "msgType": "call",
        "action": "end",
        "callId": call_id,
        "reason": reason,
    }
    sent = False
    if _dc_is_open(session):
        try:
            send_dc_json(session, msg_signaling)
            send_dc_json(session, msg_end)
            sent = True
        except Exception as exc:  # noqa: BLE001
            log.warn(f"PC1: end-call send failed session={session.get('sessionId')}: {exc}")
    # Inbound phone leg lives on PC-callee.
    callee_dc = session.get("calleeDataChannel")
    callee_open = bool(session.get("calleeDcOpen"))
    if callee_dc is not None and callee_open:
        try:
            send_callee_dc_json(session, msg_signaling)
            send_callee_dc_json(session, msg_end)
            sent = True
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"PC-callee: end-call send failed session={session.get('sessionId')}: {exc}"
            )
    if not sent:
        log.info(
            f"PC: skip end-call session={session.get('sessionId')} "
            f"(no open DC reason={reason})"
        )
    return sent  # callers must not set endCallSent unless this is True


def send_leg_ui_hangup(
    session: dict[str, Any], *, leg: str, reason: str = "hangup"
) -> bool:
    """Tell the *other* UA the call is over, without touching the ending leg.

    iOS CallKit only drops in-call on ``msgType=call action=end``.
    Android still honors that as legacy; ``signaling/end-call`` + matching
    ``callId`` (inactive offer) is its primary hangup and follows this.
    """
    if not _leg_dc_open(session, leg):
        return False
    call_id = _call_id_for_leg(session, leg)
    # call/end drops CallKit. A bare signaling/end-call (no payload) is what
    # iOS treats as hang-up-now and what Android applies when callId matches.
    end_msg = _with_call_id(
        {"msgType": "call", "action": "end", "reason": reason},
        call_id,
    )
    bare = _with_call_id(
        {"msgType": "signaling", "action": "end-call", "reason": reason},
        call_id,
    )
    try:
        _send_leg_dc_json(session, leg, end_msg)
        _send_leg_dc_json(session, leg, bare)
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC: UI hangup send failed session={session.get('sessionId')} "
            f"leg={leg}: {exc}"
        )
        return False
    log.info(
        f"PC: UI hangup call/end session={session.get('sessionId')} "
        f"leg={leg} callId={call_id}"
    )
    return True


async def send_dc_cancel_for_identity(
    session: dict[str, Any], ident: str, reason: str = "answered-elsewhere"
) -> bool:
    """Cancel a multi-ring loser over DC if we own an open channel *for that ident*.

    Shared pcCallee/PC1 is the winner after first answer — never send loser
    cancel on those or we hang up the connected call.
    """
    ident = str(ident or "")
    winner = str(session.get("multiringWinner") or "")
    if not ident or (winner and ident == winner):
        return False
    ring = (session.get("ringLegs") or {}).get(ident)
    if ring is not None and getattr(ring, "callerEndDumped", False):
        return True
    dc = None
    by_id = session.get("dcByIdentity")
    if isinstance(by_id, dict):
        dc = by_id.get(ident)
    if dc is None:
        return False
    state = str(getattr(dc, "readyState", "") or "").lower()
    if state != "open":
        return False
    # Set before the await. drive() and DC-open both call this; the second
    # must not send another end-call offer while the first is still in flight.
    if ring is not None:
        ring.callerEndDumped = True
    call_id = session.get(f"ringCallId:{ident}")
    if not isinstance(call_id, int) or call_id <= 0:
        call_id = _ensure_session_call_id(session)
    worker_leg = str(getattr(dc, "leg", "") or "")
    try:
        if getattr(dc, "worker", False) and worker_leg:
            from webrtc_pc_worker import hangup_loser_leg

            ok = await hangup_loser_leg(
                session,
                ident=ident,
                worker_leg=worker_leg,
                call_id=call_id,
                reason=reason,
            )
            if ok and ring is not None:
                ring.callerEndDumped = True
            return bool(ok)
        dc.send(
            json.dumps(
                {
                    "msgType": "call",
                    "action": "end",
                    "callId": call_id,
                    "reason": reason,
                }
            )
        )
        dc.send(
            json.dumps(
                {
                    "msgType": "signaling",
                    "action": "end-call",
                    "callId": call_id,
                    "reason": reason,
                    "payload": {"callId": call_id, "type": "end-call", "reason": reason},
                }
            )
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PC: loser DC cancel failed ident={ident!r}: {exc}")
        return False
    if ring is not None:
        ring.callerEndDumped = True
    log.info(
        f"PC: loser cancel via DC ident={ident!r} session={session.get('sessionId')} "
        f"callId={call_id} reason={reason}"
    )
    return True


class RingLeg:
    """One multi-ring seat: own PC + DC, own RING, own cancel.

    HTTP `/notify` answer completes the DC handshake. Pickup is the DC
    signaling answer after RING. First pickup wins; losers are ended on DC.
    """

    def __init__(
        self,
        session: dict[str, Any],
        *,
        ident: str,
        wallet: Any,
        signaling_session_id: str,
    ) -> None:
        self.session = session
        self.ident = ident
        self.wallet = wallet
        self.signaling_session_id = signaling_session_id
        self.pc: Any = None
        self.dc: Any = None
        self.invite: Optional[dict[str, Any]] = None
        self.dc_open_fut: Optional[asyncio.Future] = None
        self.pickup_fut: Optional[asyncio.Future] = None
        self.pending_pickup_sdp: Optional[str] = None
        self.pickup_candidates: list[Any] = []
        self.cancelled = False
        self.declined = False
        self.promoted = False
        self.ring_sent = False
        self.ring_sent_at: Optional[float] = None
        self.reuse_started_at: Optional[float] = None
        self.dc_seen = False
        self.remote_track = None
        self.remote_ice: list[dict[str, Any]] = []
        self.ice_ready_fut: Optional[asyncio.Future] = None
        self._drive_started = False
        self.drive_task: Optional[asyncio.Task[Any]] = None

    def _label(self) -> str:
        return f"PC-callee[{self.ident}]"

    async def create_offer(self) -> dict[str, Any]:
        if use_media_worker():
            from webrtc_pc_worker import ringleg_create_offer

            return await ringleg_create_offer(self)
        _require_aiortc()
        loop = asyncio.get_running_loop()
        self.session["eventLoop"] = loop
        self.dc_open_fut = loop.create_future()
        pc = RTCPeerConnection(configuration=_pc_config())
        self.pc = pc
        dc = pc.createDataChannel("chat")
        self.dc = dc
        self._bind_dc(dc)
        sid = self.session.get("sessionId") or "?"

        @pc.on("icegatheringstatechange")
        def _on_gather() -> None:
            log.info(f"{self._label()}: session={sid} iceGatheringState={pc.iceGatheringState}")

        @pc.on("iceconnectionstatechange")
        def _on_ice() -> None:
            log.info(
                f"{self._label()}: session={sid} "
                f"iceConnectionState={getattr(pc, 'iceConnectionState', '?')}"
            )

        @pc.on("connectionstatechange")
        def _on_conn() -> None:
            state = str(getattr(pc, "connectionState", "") or "")
            log.info(f"{self._label()}: session={sid} connectionState={state}")
            if self.promoted:
                if state == "connected":
                    self.session["pc2Connected"] = True
                    if self.session.get("calleeRingAnswered"):
                        _schedule(
                            self.session,
                            _bridge_media(self.session),
                            label="media-bridge-pc2-conn",
                        )
                elif state in ("failed", "closed"):
                    self.session["pc2Connected"] = False

        bound_key = f"ringTrackBound:{self.ident}"
        if not self.session.get(bound_key):
            self.session[bound_key] = True

            @pc.on("track")
            def _on_track(track: Any) -> None:
                kind = getattr(track, "kind", "") or ""
                log.info(f"{self._label()}: session={sid} track received kind={kind!r}")
                if kind != "audio":
                    return
                self.remote_track = track
                if self.promoted:
                    self.session["pc2RemoteTrack"] = track
                    _schedule(self.session, _bridge_media(self.session), label="media-bridge")

        # aiortc cannot add m=audio after DC is up (unlike werift). Reserve
        # inactive audio on this first offer and SEND it — do not strip.
        # RING only flips sendrecv on the same mid (one ICE, one SSRC).
        key = f"pc2LocalTrack:{self.ident}"
        track = _SwitchableAudioTrack()
        self.session[key] = track
        self.session["pc2SendTap"] = track
        _reserve_inactive_audio_transceiver(pc, track)
        _prefer_g711_codecs(pc, label=self._label())
        offer = await pc.createOffer()
        raw = (offer.sdp if offer else "") or ""
        try:
            from client_ingress import _narrow_telephony_audio_sdp

            raw = _narrow_telephony_audio_sdp(raw)
        except Exception:  # noqa: BLE001
            pass
        raw = ensure_bundle_all_mids(raw)
        await pc.setLocalDescription(RTCSessionDescription(sdp=raw, type="offer"))
        await _wait_ice_gathering(pc)
        local = pc.localDescription
        sdp = local.sdp if local else raw
        try:
            from client_ingress import _narrow_telephony_audio_sdp

            sdp = _narrow_telephony_audio_sdp(sdp)
        except Exception:  # noqa: BLE001
            pass
        sdp = ensure_bundle_all_mids(sdp)
        ice = prefer_srflx_and_relay(candidates_from_sdp(sdp))
        sdp = embed_candidates_in_sdp(sdp, ice)
        self.invite = {"sdp": sdp, "candidates": ice}
        log.info(
            f"{self._label()}: invite session={sid} bytes={len(sdp)} "
            f"candidates={len(ice)} types[{candidate_type_counts(ice)}] "
            f"{sdp_media_summary(sdp)}"
        )
        return self.invite

    def _bind_dc(self, dc: Any) -> None:
        session = self.session
        session_id = session.get("sessionId") or "?"

        @dc.on("open")
        def _on_open() -> None:  # noqa: ANN202
            log.info(f"{self._label()}: session={session_id} datachannel OPEN")
            session.setdefault("dcByIdentity", {})[self.ident] = dc
            _resolve_future(self.dc_open_fut, True)
            if self.promoted:
                session["calleeDataChannel"] = dc
                session["calleeDcOpen"] = True
                _resolve_future(session.get("calleeDcOpenFut"), True)
            if (
                self.cancelled
                or session.get("clientEnded")
                or session.get("callerCancelForwarded")
            ):
                task = self.drive_task
                if task is not None and not task.done():
                    return
                _schedule(
                    session,
                    send_dc_cancel_for_identity(session, self.ident, "cancelled"),
                    label="caller-cancel-on-dc-open",
                )

        @dc.on("close")
        def _on_close() -> None:  # noqa: ANN202
            log.info(f"{self._label()}: session={session_id} datachannel CLOSED")
            by_id = session.get("dcByIdentity")
            if isinstance(by_id, dict):
                by_id.pop(self.ident, None)
            if self.promoted:
                session["calleeDcOpen"] = False

        @dc.on("message")
        def _on_message(message: Any) -> None:  # noqa: ANN401
            try:
                text = (
                    message
                    if isinstance(message, str)
                    else bytes(message).decode("utf-8", "replace")
                )
                data = json.loads(text)
            except Exception:  # noqa: BLE001
                return
            if not isinstance(data, dict):
                return
            self._on_dc_payload(data)

    def _on_dc_payload(self, data: dict[str, Any]) -> None:
        session = self.session
        session_id = session.get("sessionId") or "?"
        msg_type = data.get("msgType") or data.get("type")
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        action = data.get("action") or payload.get("type")
        action_l = str(action or "").lower()
        payload_type = str(payload.get("type") or "").lower()
        sdp = str(payload.get("sdp") or "")
        log.info(
            f"{self._label()}: session={session_id} DC-IN msgType={msg_type!r} "
            f"action={action!r} sdp_len={len(sdp)}"
        )
        self.dc_seen = True
        _note_dc_peer_alive(session, self.ident)
        _note_leg_call_id(session, f"callee:{self.ident}", data)
        data["_dcLeg"] = "callee"
        data["_dcIdent"] = str(self.ident or "")
        if (
            not self.promoted
            and (
                self.cancelled
                or getattr(self, "callerEndDumped", False)
                or getattr(self, "transferredOut", False)
            )
            and msg_type == "signaling"
            and action_l == "end-call"
            and payload_type == "answer"
            and sdp.strip()
        ):
            if session.get("mediaWorker") or use_media_worker():
                from webrtc_pc_worker import apply_loser_end_call_answer

                _schedule(
                    session,
                    apply_loser_end_call_answer(self, payload),
                    label="loser-end-call-answer",
                )
                return
        if getattr(self, "declined", False) and not self.promoted:
            if msg_type == "call" and action_l in ("end", "hangup"):
                return
            if msg_type == "signaling" and action_l == "end-call":
                log.info(
                    f"{self._label()}: absorb end-call on declined seat "
                    f"session={session_id}"
                )
                return
        if getattr(self, "transferredOut", False) and not self.promoted:
            if msg_type == "call" and action_l in ("end", "hangup"):
                log.info(
                    f"{self._label()}: absorb call/end on transferred-out PC "
                    f"session={session_id}"
                )
                return
            if (
                msg_type == "signaling"
                and payload_type == "offer"
                and sdp.strip()
                and not is_inactive_offer(sdp)
                and _sdp_has_active_audio(sdp)
            ):
                self.transferredOut = False
                self.attach_kept_callee()
                _handle_callee_dc_payload(session, data)
                return
            return
        # Caller already gone: this seat is a kept callee PC, not a hunt winner.
        if self._is_kept_callee():
            if msg_type == "call" and action_l in ("end", "hangup"):
                log.info(
                    f"{self._label()}: absorb call/end on kept PC "
                    f"session={session_id}"
                )
                return
            self.attach_kept_callee()
            _handle_callee_dc_payload(session, data)
            return
        # Callback is already up. Do not re-attach: that aliases pc2 over the SBC PC.
        if self._is_bound_callee():
            _handle_callee_dc_payload(session, data)
            return
        if (
            msg_type == "signaling"
            and payload_type == "answer"
            and action_l != "end-call"
            and sdp.strip()
            and not is_inactive_offer(sdp)
        ):
            cands = payload.get("candidates") or []
            self.pickup_candidates = cands if isinstance(cands, list) else []
            fut = self.pickup_fut
            if fut is not None and not fut.done():
                _resolve_future(fut, sdp)
            else:
                # Reuse: callee_audio_ring_and_answer waits on session fut,
                # not RingLeg.pickup_fut (completed on the first RING).
                sess_fut = session.get("calleeRingAnswerFut")
                if sess_fut is not None and not sess_fut.done():
                    _resolve_future(sess_fut, sdp)
                else:
                    self.pending_pickup_sdp = sdp
            return
        if msg_type == "call" and action_l in ("end", "hangup"):
            if self.promoted or getattr(self, "isTransferSurvivor", False):
                reason = str(data.get("reason") or action or "hangup")
                end_cb = session.get("on_dc_end")
                if callable(end_cb):
                    _schedule(
                        session,
                        end_cb(session, reason, ended_leg="callee"),
                        label="callee_on_dc_end",
                    )
            else:
                self._mark_declined()
            return
        if self.promoted or getattr(self, "isTransferSurvivor", False):
            _handle_callee_dc_payload(session, data)
            return
        if msg_type == "signaling" and action_l == "end-call" and not sdp.strip():
            self._mark_declined()

    def _is_kept_callee(self) -> bool:
        """Caller hung up before pickup. PC stays; hunt was not won."""
        if (
            self.promoted
            or self._pc_is_dead()
            or getattr(self, "declined", False)
            or getattr(self, "transferredOut", False)
            or getattr(self, "isTransferSurvivor", False)
        ):
            return False
        if (
            self.session.get("dcRingStarted")
            or self.session.get("calleeRingAnswered")
            or self.session.get("declinedBeforePickup")
            or self.session.get("voicemailActive")
            or self.session.get("clientTransferInProgress")
        ):
            return False
        return bool(getattr(self, "callerEndDumped", False) or self.cancelled)

    def _is_bound_callee(self) -> bool:
        """Answered callee PC. Do not treat a fresh hunt RING as already bound.

        ``dcRingStarted`` is set when the caller offers. The reused seat is
        still waiting for its pickup answer, and that answer must resolve the
        hunt future. Binding on that flag swallows it.
        """
        if self._pc_is_dead() or self.session.get("pcCallee") is not self.pc:
            return False
        if self.promoted:
            return True
        return bool(self.session.get("calleeRingAnswered"))

    def still_ringing(self) -> bool:
        """True while this seat can still answer (not cancelled, not winner)."""
        return not self.cancelled and not self.promoted

    def _mark_declined(self) -> None:
        self.cancelled = True
        self.declined = True
        session = self.session
        _resolve_future(self.pickup_fut, "")
        if session.get("multiringWinner"):
            log.info(
                f"{self._label()}: declined after winner "
                f"{session.get('multiringWinner')!r} session={session.get('sessionId')}"
            )
            _schedule(
                session,
                self._finish_declined_leg(),
                label="ring-leg-declined-after-winner",
            )
            return
        others = [
            ident
            for ident, leg in (session.get("ringLegs") or {}).items()
            if ident != self.ident and getattr(leg, "still_ringing", lambda: False)()
        ]
        if others:
            log.info(
                f"{self._label()}: declined before pickup — others still ringing "
                f"{others} session={session.get('sessionId')}"
            )
            _schedule(
                session,
                self._finish_declined_leg(),
                label="ring-leg-declined",
            )
            return
        log.info(f"{self._label()}: declined before pickup (last seat)")
        session["declinedBeforePickup"] = True
        ev = session.get("pickupEvent")
        if ev is not None:
            try:
                ev.set()
            except Exception:  # noqa: BLE001
                pass
        _schedule(
            session,
            self._finish_declined_leg(),
            label="ring-leg-declined-last",
        )

    async def _finish_declined_leg(self) -> None:
        try:
            await self.close()
        except Exception as exc:  # noqa: BLE001
            log.warn(f"{self._label()}: decline close failed: {exc}")
        drop = self.session.get("on_ring_leg_dropped")
        if callable(drop):
            try:
                result = drop(self.session, self.ident)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:  # noqa: BLE001
                log.warn(f"{self._label()}: decline occupancy release failed: {exc}")

    def add_remote_ice(self, candidates: Optional[list[Any]] = None) -> None:
        """Accumulate trickle ICE; resolve wait when srflx/relay shows up."""
        for c in merge_ice_array_and_sdp("", candidates or []):
            text = str(c.get("candidate") or "")
            if not text:
                continue
            if any(str(x.get("candidate") or "") == text for x in self.remote_ice):
                continue
            self.remote_ice.append(c)
        if ice_has_relay(self.remote_ice):
            _resolve_future(self.ice_ready_fut, True)

    async def wait_routable_ice(self, timeout: float = 2.0) -> None:
        """Wait for TURN when HTTP is host/srflx-only. Working calls had relay."""
        types = candidate_type_counts(self.remote_ice)
        if ice_has_relay(self.remote_ice):
            log.info(
                f"{self._label()}: HTTP ICE ready types[{types}] "
                f"session={self.session.get('sessionId')}"
            )
            return
        log.info(
            f"{self._label()}: waiting ICE relay types[{types}] "
            f"session={self.session.get('sessionId')} timeout={timeout}s"
        )
        loop = asyncio.get_running_loop()
        if self.ice_ready_fut is None or self.ice_ready_fut.done():
            self.ice_ready_fut = loop.create_future()
        try:
            await asyncio.wait_for(asyncio.shield(self.ice_ready_fut), timeout=timeout)
            log.info(
                f"{self._label()}: ICE relay arrived "
                f"types[{candidate_type_counts(self.remote_ice)}] "
                f"session={self.session.get('sessionId')}"
            )
        except asyncio.TimeoutError:
            log.warn(
                f"{self._label()}: ICE wait timeout no relay "
                f"types[{candidate_type_counts(self.remote_ice)}] "
                f"session={self.session.get('sessionId')} — RING anyway"
            )

    async def apply_http_answer(self, sdp: str, candidates: Optional[list[Any]] = None) -> None:
        if getattr(self.pc, "worker", False) or self.session.get("mediaWorker"):
            from webrtc_pc_worker import ringleg_apply_http_answer

            await ringleg_apply_http_answer(self, sdp, candidates)
            return
        if self.pc is None:
            raise RuntimeError(f"{self._label()}: PC missing for HTTP answer")
        ans = str(sdp or "")
        merged = merge_ice_array_and_sdp(ans, candidates)
        self.add_remote_ice(merged)
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=ans, type="answer"))
        to_add = prefer_srflx_and_relay(merged)
        applied = await add_ice_candidates_to_pc(
            self.session, self.pc, to_add, label=self._label()
        )
        log.info(
            f"{self._label()}: setRemote HTTP answer session="
            f"{self.session.get('sessionId')} bytes={len(ans)} "
            f"candidates={len(merged)} applied={applied} "
            f"types[{candidate_type_counts(merged)}]"
        )

    def _pc_is_dead(self) -> bool:
        pc = self.pc
        if pc is None:
            return True
        conn = str(getattr(pc, "connectionState", "") or "").lower()
        ice = str(getattr(pc, "iceConnectionState", "") or "").lower()
        return conn in ("closed", "failed") or ice in ("closed", "failed")

    def dc_reusable(self) -> bool:
        """True if this seat still has a live PC + open DC (iOS session reuse)."""
        dcs = [self.dc]
        by_id = self.session.get("dcByIdentity")
        if isinstance(by_id, dict):
            dcs.append(by_id.get(self.ident))
        if self.promoted:
            dcs.append(self.session.get("calleeDataChannel"))
        open_dc = None
        for dc in dcs:
            if str(getattr(dc, "readyState", "") or "").lower() == "open":
                open_dc = dc
                break
        if open_dc is None:
            return False
        if self.pc is None or self._pc_is_dead():
            log.info(
                f"{self._label()}: DC open but PC dead — not reusable "
                f"session={self.session.get('sessionId')}"
            )
            return False
        self.dc = open_dc
        return True

    def prepare_for_reuse_ring(self) -> None:
        self.cancelled = False
        self.callerEndDumped = False
        self.transferredOut = False
        self.isTransferSurvivor = False
        self.promoted = False
        if self.session.get("pcCallee") is self.pc:
            self.session["calleeRingAnswered"] = False
        self.answered_via_http_offer = False
        self._http_offer_pickup_done = False
        self.pending_pickup_sdp = None
        self.pickup_candidates = []
        self.ring_sent = False
        self.ring_sent_at = None
        self.reuse_started_at = time.monotonic()
        self.dc_seen = False
        self._drive_started = True
        self.remote_track = None
        if not getattr(self.pc, "worker", False):
            _revive_audio_receiver(self.pc, label=self._label())

    def _bind_http_answer_pc(self, pc: Any) -> None:
        sid = self.session.get("sessionId") or "?"
        self.session.pop(f"ringTrackBound:{self.ident}", None)

        @pc.on("icegatheringstatechange")
        def _on_gather() -> None:
            log.info(f"{self._label()}: session={sid} iceGatheringState={pc.iceGatheringState}")

        @pc.on("iceconnectionstatechange")
        def _on_ice() -> None:
            log.info(
                f"{self._label()}: session={sid} "
                f"iceConnectionState={getattr(pc, 'iceConnectionState', '?')}"
            )

        @pc.on("connectionstatechange")
        def _on_conn() -> None:
            state = str(getattr(pc, "connectionState", "") or "")
            log.info(f"{self._label()}: session={sid} connectionState={state}")
            if self.promoted:
                if state == "connected":
                    self.session["pc2Connected"] = True
                    if self.session.get("calleeRingAnswered"):
                        _schedule(
                            self.session,
                            _bridge_media(self.session),
                            label="media-bridge-pc2-conn",
                        )
                elif state in ("failed", "closed"):
                    self.session["pc2Connected"] = False

        @pc.on("datachannel")
        def _on_dc(channel: Any) -> None:
            self.dc = channel
            self._bind_dc(channel)
            if self.promoted:
                self.session["calleeDataChannel"] = channel

        bound_key = f"ringTrackBound:{self.ident}"
        self.session[bound_key] = True

        @pc.on("track")
        def _on_track(track: Any) -> None:
            kind = getattr(track, "kind", "") or ""
            log.info(f"{self._label()}: session={sid} track received kind={kind!r}")
            if kind != "audio":
                return
            self.remote_track = track
            if self.promoted:
                self.session["pc2RemoteTrack"] = track
                _schedule(self.session, _bridge_media(self.session), label="media-bridge")

    async def _remint_pc_for_http_offer(self) -> None:
        old = self.pc
        self.pc = None
        self.dc = None
        if old is not None:
            try:
                await old.close()
            except Exception as exc:  # noqa: BLE001
                log.warn(f"{self._label()}: remint close old PC: {exc}")
        loop = asyncio.get_running_loop()
        self.session["eventLoop"] = loop
        old_dc_fut = self.dc_open_fut
        self.dc_open_fut = loop.create_future()
        if old_dc_fut is not None and not old_dc_fut.done():
            _resolve_future(old_dc_fut, False)
        pc = RTCPeerConnection(configuration=_pc_config())
        self.pc = pc
        self._bind_http_answer_pc(pc)
        if self.promoted:
            self.session["pcCallee"] = pc
            self.session["pc2"] = pc
            self.session["calleeDataChannel"] = None
            self.session["calleeDcOpen"] = False
            self.session["pc2Connected"] = False
            self.session.pop("pc2RemoteTrack", None)
        log.info(
            f"{self._label()}: reminted PC for HTTP offer "
            f"session={self.session.get('sessionId')} promoted={self.promoted}"
        )

    async def apply_http_offer(
        self, sdp: str, candidates: Optional[list[Any]] = None
    ) -> dict[str, Any]:
        """Answer a callee HTTP offer on a fresh PC.

        Android remints and POSTs type=offer instead of answering RING on the
        existing PC. That is a new offerer PC — Siphon cannot rollback/reuse
        leftover transceivers from call N-1 (m-line/mid mismatch). iOS reuse
        never hits this path (it answers RING). On the in-process peer the
        new PC stays on ``callee:<ident>`` so the bridge can see it.
        """
        offer_sdp = str(sdp or "")
        merged = merge_ice_array_and_sdp(offer_sdp, candidates)
        pc = self.pc
        sig = str(getattr(pc, "signalingState", "") or "") if pc is not None else ""
        conn = str(getattr(pc, "connectionState", "") or "") if pc is not None else ""
        log.info(
            f"{self._label()}: HTTP offer session={self.session.get('sessionId')} "
            f"bytes={len(offer_sdp)} signalingState={sig or '-'} "
            f"connectionState={conn or '-'} "
            f"candidates={len(merged)} types[{candidate_type_counts(merged)}]"
        )
        self.answered_via_http_offer = False
        self._http_offer_pickup_done = False
        if self.session.get("mediaWorker") or getattr(pc, "worker", False):
            from webrtc_pc_worker import answer_callee_http_offer

            out = await answer_callee_http_offer(self, offer_sdp, merged)
            ans = str(out.get("sdp") or "")
            ice = list(out.get("candidates") or [])
            applied = int(out.get("applied") or 0)
        else:
            _require_aiortc()
            await self._remint_pc_for_http_offer()
            pc = self.pc
            if pc is None:
                raise RuntimeError(f"{self._label()}: PC missing for HTTP offer")
            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=offer_sdp, type="offer")
            )
            applied = await add_ice_candidates_to_pc(
                self.session, pc, merged, label=self._label()
            )
            # Answerer m-lines must equal the offer. addTrack after setRemote
            # invents m=audio on a DC-only offer → Media sections do not match.
            if _audio_transceiver(pc) is not None:
                await _ensure_local_audio_on_pc(
                    self.session, pc, key=f"pc2LocalTrack:{self.ident}", remint=False
                )
            _prefer_g711_codecs(pc, label=self._label())
            answer = await pc.createAnswer()
            raw = (answer.sdp if answer else "") or ""
            try:
                from client_ingress import _narrow_telephony_audio_sdp

                raw = _narrow_telephony_audio_sdp(raw)
            except Exception:  # noqa: BLE001
                pass
            raw = ensure_bundle_all_mids(raw)
            await pc.setLocalDescription(RTCSessionDescription(sdp=raw, type="answer"))
            await _wait_ice_gathering(pc)
            local = pc.localDescription
            ans = local.sdp if local else raw
            try:
                from client_ingress import _narrow_telephony_audio_sdp

                ans = _narrow_telephony_audio_sdp(ans)
            except Exception:  # noqa: BLE001
                pass
            ans = ensure_bundle_all_mids(ans)
            ice = prefer_srflx_and_relay(candidates_from_sdp(ans))
            ans = embed_candidates_in_sdp(ans, ice)
        self.answered_via_http_offer = True
        fut = self.pickup_fut
        if fut is not None and not fut.done():
            _resolve_future(fut, "__http_offer__")
        else:
            self.pending_pickup_sdp = "__http_offer__"
        if not self._drive_started:
            _schedule(
                self.session,
                self._complete_http_offer_pickup(),
                label="http-offer-pickup",
            )
        log.info(
            f"{self._label()}: HTTP offer answered session="
            f"{self.session.get('sessionId')} bytes={len(ans)} "
            f"trickle_applied={applied} candidates={len(ice)} "
            f"types[{candidate_type_counts(ice)}] {sdp_media_summary(ans)}"
        )
        return {"sdp": ans, "candidates": ice}

    async def wait_dc_open(self, timeout: float = 30.0) -> None:
        state = str(getattr(self.dc, "readyState", "") or "").lower() if self.dc else ""
        if state == "open":
            return
        fut = self.dc_open_fut
        if fut is None:
            raise RuntimeError(f"{self._label()}: dc open future missing")
        await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)

    def _dc_send(self, message: dict[str, Any]) -> None:
        if getattr(self.pc, "worker", False) or self.session.get("mediaWorker"):
            from webrtc_pc_worker import send_dc_json as _send

            _send(self.session, message, leg=getattr(self.pc, "leg", f"callee:{self.ident}"))
            return
        dc = self.dc
        state = str(getattr(dc, "readyState", "") or "").lower() if dc else ""
        if dc is None or state != "open":
            raise RuntimeError(f"{self._label()}: no open DC")
        action = message.get("action") or (message.get("payload") or {}).get("type") or "unknown"
        log.info(
            f"{self._label()}: session={self.session.get('sessionId')} "
            f"DC-OUT msgType={message.get('msgType')!r} action={action!r}"
        )
        dc.send(json.dumps(message))

    async def send_ring_and_wait_pickup(self, timeout: float) -> str:
        if getattr(self.pc, "worker", False) or use_media_worker():
            from webrtc_pc_worker import ringleg_send_ring

            loop = asyncio.get_running_loop()
            self.pickup_fut = loop.create_future()
            if self.pending_pickup_sdp:
                self.pickup_fut.set_result(self.pending_pickup_sdp)
                self.pending_pickup_sdp = None
            if getattr(self, "answered_via_http_offer", False):
                return "__http_offer__"
            return await ringleg_send_ring(self, timeout)
        _require_aiortc()
        pc = self.pc
        if pc is None:
            raise RuntimeError(f"{self._label()}: PC missing for RING")
        session = self.session
        loop = asyncio.get_running_loop()
        self.pickup_fut = loop.create_future()
        if self.pending_pickup_sdp:
            self.pickup_fut.set_result(self.pending_pickup_sdp)
            self.pending_pickup_sdp = None
        if getattr(self, "answered_via_http_offer", False):
            return "__http_offer__"
        if (
            self.pickup_fut.done()
            and not self.pickup_fut.cancelled()
            and self.pickup_fut.result() == "__http_offer__"
        ):
            return "__http_offer__"
        if session.get("routeKind") == "inbound":
            session["inboundSipAnswered"] = False
        bound_key = f"ringTrackBound:{self.ident}"
        if not session.get(bound_key):
            session[bound_key] = True
            sid = session.get("sessionId") or "?"

            @pc.on("track")
            def _on_track(track: Any) -> None:
                kind = getattr(track, "kind", "") or ""
                log.info(f"{self._label()}: session={sid} track received kind={kind!r}")
                if kind != "audio":
                    return
                self.remote_track = track
                if self.promoted:
                    session["pc2RemoteTrack"] = track
                    _schedule(session, _bridge_media(session), label="media-bridge")

        session["calleeRingAnswered"] = False
        prev_sdp = str(getattr(pc.localDescription, "sdp", "") or "")
        prev_ufrag, prev_pwd = _sdp_ice_ufrag_pwd(prev_sdp)
        prev_ice = prefer_srflx_and_relay(candidates_from_sdp(prev_sdp))
        remint = False
        _revive_audio_receiver(pc, label=self._label())
        await _ensure_local_audio_on_pc(
            session, pc, key=f"pc2LocalTrack:{self.ident}", remint=False
        )
        _prefer_g711_codecs(pc, label=self._label())
        # werift addTrack reuses the live DTLS (findOrCreateTransport). aiortc
        # invents a new IceTransport unless we keep the DC ufrag/pwd.
        offer = await pc.createOffer()
        raw_sdp = (offer.sdp if offer else "") or ""
        try:
            from client_ingress import _narrow_telephony_audio_sdp

            narrowed = _narrow_telephony_audio_sdp(raw_sdp)
            if narrowed != raw_sdp:
                raw_sdp = narrowed
                log.info(
                    f"{self._label()}: narrowed RING offer to G711 "
                    f"{len(offer.sdp or '')}→{len(raw_sdp)} bytes"
                )
        except Exception:  # noqa: BLE001
            pass
        if prev_ufrag and prev_pwd:
            raw_sdp = _set_sdp_ice_ufrag_pwd(raw_sdp, prev_ufrag, prev_pwd)
        raw_sdp = force_bundle_ports(ensure_bundle_all_mids(raw_sdp))
        offer = RTCSessionDescription(sdp=raw_sdp, type="offer")
        try:
            await pc.setLocalDescription(offer)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"{self._label()}: RING setLocal reused-ICE failed: {exc}")
            offer = await pc.createOffer()
            raw_sdp = force_bundle_ports(
                ensure_bundle_all_mids((offer.sdp if offer else "") or "")
            )
            if prev_ufrag and prev_pwd:
                raw_sdp = _set_sdp_ice_ufrag_pwd(raw_sdp, prev_ufrag, prev_pwd)
            await pc.setLocalDescription(RTCSessionDescription(sdp=raw_sdp, type="offer"))
        if str(getattr(pc, "iceGatheringState", "") or "") != "complete":
            await _wait_ice_gathering(pc)
        local = pc.localDescription
        sdp = local.sdp if local else raw_sdp
        sdp = force_bundle_ports(ensure_bundle_all_mids(sdp))
        if prev_ufrag and prev_pwd:
            sdp = _set_sdp_ice_ufrag_pwd(sdp, prev_ufrag, prev_pwd)
        ice = prev_ice or prefer_srflx_and_relay(candidates_from_sdp(sdp))
        sdp = embed_candidates_in_sdp(sdp, ice)
        log.info(
            f"{self._label()}: RING offer SDP {sdp_media_summary(sdp)} "
            f"reused_ufrag={prev_ufrag or '-'} remint={remint}"
        )
        call_id = _allocate_leg_call_id(session, self.ident)
        from_label = identity.callkit_handle(session.get("from"))
        self._dc_send(
            {
                "msgType": "signaling",
                "callId": call_id,
                "payload": {
                    "type": "offer",
                    "from": from_label,
                    "to": self.ident,
                    "sessionId": self.signaling_session_id,
                    "sdp": sdp,
                    "candidates": ice,
                    "callId": call_id,
                    "label": from_label,
                    "isCall": True,
                },
            }
        )
        self.ring_sent = True
        self.ring_sent_at = time.monotonic()
        _note_dc_ring_sent(
            session, self.ident, sdp, ice, wallet=getattr(self, "wallet", None)
        )
        log.info(
            f"{self._label()}: RING offer sent session={session.get('sessionId')} "
            f"callId={call_id} bytes={len(sdp)}"
        )
        try:
            answer_sdp = await asyncio.wait_for(
                asyncio.shield(self.pickup_fut), timeout=timeout
            )
        except asyncio.CancelledError:
            raise RuntimeError(f"{self._label()}: RING answer cancelled") from None
        except asyncio.TimeoutError as exc:
            raise RuntimeError(f"{self._label()}: RING answer timeout") from exc
        return str(answer_sdp or "")

    async def complete_pickup(self, answer_sdp: str) -> None:
        if getattr(self.pc, "worker", False) or self.session.get("mediaWorker"):
            from webrtc_pc_worker import ringleg_complete_pickup

            await ringleg_complete_pickup(self, answer_sdp)
            try:
                call_id = _call_id_for_leg(self.session, f"callee:{self.ident}")
                _send_leg_dc_json(
                    self.session,
                    "callee",
                    _with_call_id(
                        {
                            "msgType": "call",
                            "action": "ack",
                            "ackFor": "answer",
                        },
                        call_id,
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                log.warn(f"{self._label()}: RING answer ack failed: {exc}")
            return
        pc = self.pc
        if pc is None:
            raise RuntimeError(f"{self._label()}: PC missing for pickup")
        await apply_callee_ring_answer(
            self.session,
            pc,
            str(answer_sdp),
            self.pickup_candidates,
            label=self._label(),
        )
        session = self.session
        session["calleeRingAnswered"] = True
        log.info(
            f"{self._label()}: RING answer applied "
            f"session={session.get('sessionId')} bytes={len(answer_sdp)} "
            f"{sdp_media_summary(str(answer_sdp))}"
        )
        try:
            call_id = _call_id_for_leg(session, f"callee:{self.ident}")
            _send_leg_dc_json(
                session,
                "callee",
                _with_call_id(
                    {
                        "msgType": "call",
                        "action": "ack",
                        "ackFor": "answer",
                    },
                    call_id,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"{self._label()}: RING answer ack failed "
                f"session={session.get('sessionId')}: {exc}"
            )
        session["pc2OfferReady"] = True
        live = _live_remote_audio(pc)
        if live is not None:
            self.remote_track = live
        remote = live or self.remote_track
        if remote is not None:
            session["pc2RemoteTrack"] = remote
        local = session.get(f"pc2LocalTrack:{self.ident}") or session.get("pc2LocalTrack")
        if local is not None:
            session["pc2LocalTrack"] = local
        connected = await _wait_pc_connected(pc, label=self._label(), timeout_s=8.0)
        session["pc2Connected"] = bool(connected)
        await _bridge_media(session)

    def attach_kept_callee(self) -> None:
        """Publish this seat as the callee PC. Does not win the hunt."""
        session = self.session
        if self.pc is not None:
            session["pcCallee"] = self.pc
            existing = session.get("pc2")
            if existing is None or existing is self.pc:
                session["pc2"] = self.pc
        dc = self.dc
        if dc is None:
            by_id = session.get("dcByIdentity")
            if isinstance(by_id, dict):
                dc = by_id.get(self.ident)
        if dc is not None:
            self.dc = dc
            session["calleeDataChannel"] = dc
            session["calleeDcOpen"] = (
                str(getattr(dc, "readyState", "") or "").lower() == "open"
            )
        log.info(
            f"{self._label()}: attached kept callee PC "
            f"session={session.get('sessionId')}"
        )

    def promote(self) -> None:
        session = self.session
        self.promoted = True
        session["pcCallee"] = self.pc
        session["pc2"] = self.pc
        session["calleeDataChannel"] = self.dc
        session["calleeDcOpen"] = True
        session["pc2OfferReady"] = True
        session["to"] = self.ident
        session["multiringWinner"] = self.ident
        ring_cid = session.get(f"ringCallId:{self.ident}")
        if isinstance(ring_cid, int) and ring_cid > 0:
            session.setdefault(f"legCallId:{self.ident}", ring_cid)
        win = session.get("on_ring_winner")
        if callable(win):
            try:
                win(session, self.ident)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"{self._label()}: on_ring_winner failed: {exc}")
        log.info(
            f"{self._label()}: promoted to session pcCallee "
            f"session={session.get('sessionId')}"
        )

    async def send_cancel(self, reason: str = "answered-elsewhere") -> bool:
        if self.promoted:
            return False
        if getattr(self, "callerEndDumped", False):
            return True
        self.cancelled = True
        sent = await send_dc_cancel_for_identity(self.session, self.ident, reason)
        if sent:
            self.callerEndDumped = True
            _resolve_future(self.pickup_fut, "")
        # Do not cancel dc_open_fut / drive_task. Invite may already be out;
        # when they register we still need call/end on that DC.
        return sent

    async def close(self, *, force: bool = False) -> None:
        if getattr(self.pc, "worker", False) or self.session.get("mediaWorker"):
            from webrtc_pc_worker import ringleg_close

            await ringleg_close(self, force=force)
            return
        if self.promoted and not force:
            return
        self.cancelled = True
        self.promoted = False
        pc = self.pc
        self.pc = None
        self.dc = None
        if pc is None:
            return
        session = self.session
        if session.get("pcCallee") is pc:
            session["pcCallee"] = None
            session["pc2"] = None
        try:
            await pc.close()
            log.info(f"{self._label()}: closed")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"{self._label()}: close failed: {exc}")

    async def _complete_http_offer_pickup(self) -> None:
        if getattr(self, "_http_offer_pickup_done", False) or self.cancelled:
            return
        self._http_offer_pickup_done = True
        session = self.session
        log.info(
            f"{self._label()}: pickup via HTTP offer "
            f"session={session.get('sessionId')}"
        )
        lock = session.get("ringLock")
        if lock is None:
            lock = asyncio.Lock()
            session["ringLock"] = lock
        async with lock:
            if not session.get("multiringWinner"):
                self.promote()
        ev = session.get("pickupEvent")
        if ev is not None:
            ev.set()
        session["calleeRingAnswered"] = True
        session["pc2OfferReady"] = True
        live = _live_remote_audio(self.pc)
        if live is not None:
            self.remote_track = live
        remote = live or getattr(self, "remote_track", None)
        if remote is not None:
            session["pc2RemoteTrack"] = remote
        local = session.get(f"pc2LocalTrack:{self.ident}") or session.get("pc2LocalTrack")
        if local is not None:
            session["pc2LocalTrack"] = local
        connected = await _wait_pc_connected(self.pc, label=self._label(), timeout_s=8.0)
        session["pc2Connected"] = bool(connected)
        await _bridge_media(session)

    async def drive(self, http_sdp: str, http_candidates: Optional[list[Any]], timeout: float) -> None:
        """HTTP DC-answer → RING → claim winner on first pickup.

        Caller already gone: still finish the handshake, then ``call/end`` +
        end-call on that DC. Do not RING, and do not close before the answer
        is applied — that is the only path that dismisses CallKit.
        """
        session = self.session
        caller_gone = bool(
            self.cancelled
            or session.get("clientEnded")
            or session.get("callerCancelForwarded")
        )
        winner = str(session.get("multiringWinner") or "")
        if caller_gone and not winner:
            try:
                await self.apply_http_answer(http_sdp, http_candidates)
                await self.wait_dc_open(30.0)
                await self.send_cancel("cancelled")
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"{self._label()}: cancel-on-dc failed "
                    f"session={session.get('sessionId')}: {exc}"
                )
            return
        # Someone else already picked up. Same as caller-cancel: apply this
        # answer, wait for the DC, then call/end there. Closing first leaves
        # CallKit up until the slow cancel push finishes.
        if winner and winner != str(self.ident):
            try:
                await self.apply_http_answer(http_sdp, http_candidates)
                await self.wait_dc_open(30.0)
                await self.send_cancel("answered-elsewhere")
            except Exception as exc:  # noqa: BLE001
                log.warn(
                    f"{self._label()}: answered-elsewhere on DC failed "
                    f"session={session.get('sessionId')}: {exc}"
                )
            return
        try:
            await self.apply_http_answer(http_sdp, http_candidates)
            await self.wait_dc_open(30.0)
            if (
                self.cancelled
                or session.get("multiringWinner")
                or session.get("clientEnded")
                or session.get("callerCancelForwarded")
            ):
                reason = (
                    "cancelled"
                    if session.get("clientEnded") or session.get("callerCancelForwarded")
                    else "answered-elsewhere"
                )
                await self.send_cancel(reason)
                return
            # HTTP answer can have m=audio (first invite is not DC-only) and
            # still be muted: iOS only audioCapability.enable()s on RING
            # (attachCallMedia). Skip RING → PC2:in=0. Always RING after DC.
            pickup = await self.send_ring_and_wait_pickup(timeout)
            if (
                self.cancelled
                or session.get("clientEnded")
                or session.get("callerCancelForwarded")
            ):
                await self.send_cancel("cancelled")
                return
            if getattr(self, "answered_via_http_offer", False) or pickup == "__http_offer__":
                await self._complete_http_offer_pickup()
                return
            await self._claim_and_complete_pickup(pickup)
        except asyncio.CancelledError:
            await self.close()
            raise
        except Exception as exc:  # noqa: BLE001
            log.warn(f"{self._label()}: drive failed: {type(exc).__name__}: {exc}")
            if (
                not self.promoted
                and not self.cancelled
                and not session.get("callerCancelForwarded")
            ):
                await self.close()

    async def drive_reused_ring(self, timeout: float) -> None:
        """iOS session reuse: RING on the live DC, no new HTTP invite/VoIP push."""
        session = self.session
        log.info(
            f"{self._label()}: reuse RING on live DC "
            f"session={session.get('sessionId')}"
        )
        if (
            self.cancelled
            or session.get("clientEnded")
            or session.get("callerCancelForwarded")
        ):
            await self.send_cancel("cancelled")
            return
        winner = str(session.get("multiringWinner") or "")
        if winner and winner != str(self.ident):
            await self.send_cancel("answered-elsewhere")
            return
        try:
            await wait_until_callee_rungable(session, timeout)
            if _callee_ending(session):
                session["endingAwaitAnswerCallee"] = False
                session["endingAwaitAnswerPc1"] = False
                session["softEndInProgress"] = False
                session["endCallRenegotiating"] = False
                log.info(
                    f"{self._label()}: RING despite unanswered end-call "
                    f"session={session.get('sessionId')}"
                )
            if (
                self.cancelled
                or session.get("multiringWinner")
                or session.get("clientEnded")
                or session.get("callerCancelForwarded")
            ):
                winner = str(session.get("multiringWinner") or "")
                if winner and winner != str(self.ident):
                    await self.send_cancel("answered-elsewhere")
                elif not winner:
                    await self.send_cancel("cancelled")
                return
            pickup = await self.send_ring_and_wait_pickup(timeout)
            if getattr(self, "answered_via_http_offer", False) or pickup == "__http_offer__":
                await self._complete_http_offer_pickup()
                return
            await self._claim_and_complete_pickup(pickup)
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            log.warn(f"{self._label()}: reuse RING failed: {exc}")

    async def _claim_and_complete_pickup(self, pickup: str) -> None:
        session = self.session
        if not pickup or self.cancelled:
            if not self.promoted:
                await self.close()
            return
        lock = session.get("ringLock")
        if lock is None:
            lock = asyncio.Lock()
            session["ringLock"] = lock
        async with lock:
            if session.get("multiringWinner") and session.get("multiringWinner") != self.ident:
                await self.send_cancel("answered-elsewhere")
                await self.close()
                return
            self.promote()
        await self.complete_pickup(pickup)
        ev = session.get("pickupEvent")
        if ev is not None:
            ev.set()


def _handle_callee_dc_payload(session: dict[str, Any], data: dict[str, Any]) -> None:
    """Winner-leg DC after promote (end-call / dtmf / inactive)."""
    session_id = session.get("sessionId") or "?"
    msg_type = data.get("msgType") or data.get("type")
    payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    action = data.get("action") or payload.get("type")
    action_l = str(action or "").lower()
    payload_type = str(payload.get("type") or "").lower()
    sdp = str(payload.get("sdp") or "")
    _note_leg_call_id(
        session, f"callee:{session.get('to') or session.get('multiringWinner') or ''}", data
    )
    if msg_type == "call" and action_l in ("end", "hangup"):
        reason = str(data.get("reason") or action or "hangup")
        end_cb = session.get("on_dc_end")
        if callable(end_cb):
            _schedule(
                session,
                end_cb(session, reason, ended_leg="callee"),
                label="callee_on_dc_end",
            )
        return
    if msg_type == "signaling" and action_l == "end-call":
        if payload_type == "answer" and sdp.strip():
            _schedule(
                session,
                apply_end_call_answer(session, payload, leg="callee"),
                label="apply_end_call_answer_callee",
            )
            return
        if sdp.strip() and (is_inactive_offer(sdp) or not _sdp_has_active_audio(sdp)):
            reason = str(data.get("reason") or "hangup")
            _schedule(
                session,
                _client_inactive_end(session, payload, leg="callee", reason=reason),
                label="client_inactive_end_callee",
            )
            return
        reason = str(data.get("reason") or "hangup")
        end_cb = session.get("on_dc_end")
        if callable(end_cb):
            _schedule(
                session,
                end_cb(session, reason, ended_leg="callee"),
                label="callee_on_dc_end",
            )
        return
    if (
        msg_type == "signaling"
        and payload_type == "offer"
        and sdp.strip()
        and not is_inactive_offer(sdp)
        and _sdp_has_active_audio(sdp)
    ):
        if session.get("dcRingStarted"):
            if session.get("clientEnded") or session.get("softEnded") or session.get("softEndInProgress"):
                session["dcRingStarted"] = False
            else:
                log.info(
                    f"PC-callee: session={session_id} audio RING already in progress; ignoring"
                )
                return
        try:
            from client_ingress import _sdp_ios_split_leftover_audio

            if _sdp_ios_split_leftover_audio(sdp):
                log.info(
                    f"PC-callee: session={session_id} skip iOS split leftover RING"
                )
                return
        except Exception:  # noqa: BLE001
            pass
        try:
            ack_id = _call_id_for_leg(session, f"callee:{session.get('to') or ''}")
            if ack_id is None:
                ack_id = _allocate_leg_call_id(
                    session, str(session.get("to") or "")
                )
            send_callee_dc_json(
                session,
                _with_call_id(
                    {
                        "msgType": "call",
                        "action": "ack",
                        "ackFor": "ring",
                    },
                    ack_id,
                ),
            )
            session["ringAckSent"] = True
            log.info(f"PC-callee: session={session_id} RING ack sent")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"PC-callee: RING ack failed session={session_id}: {exc}")
        note_glare_offer(
            session,
            str(session.get("to") or ""),
            sdp,
            leg="callee",
            call_id=_normalize_call_id(payload.get("callId") or data.get("callId")),
        )
        session["dialogOriginator"] = str(session.get("to") or "")
        session["dcRingStarted"] = True
        offered_epoch = int(session.get("dialogEpoch") or 0)
        _schedule(
            session,
            handle_callee_originated_ring(session, payload, offered_epoch),
            label="callee_originated_ring",
        )
        return
    if (
        msg_type == "signaling"
        and payload_type == "offer"
        and sdp.strip()
        and (is_inactive_offer(sdp) or not _sdp_has_active_audio(sdp))
    ):
        reason = str(data.get("reason") or "hangup")
        _schedule(
            session,
            _client_inactive_end(session, payload, leg="callee", reason=reason),
            label="client_inactive_end_callee",
        )
        return
    action_cb = session.get("on_dc_action")
    if callable(action_cb) and (
        session.get("productKind")
        or msg_type in ("dtmf", "digit", "action")
        or payload.get("digit") is not None
        or action_l in ("dtmf", "digit", "transfer", "redirect")
    ):
        data.setdefault("_dcLeg", "callee")
        data.setdefault(
            "_dcIdent",
            str(session.get("multiringWinner") or session.get("to") or ""),
        )
        action_cb(session, data)


def _leg_pc(session: dict[str, Any], leg: str) -> Any:
    if leg == "callee":
        return session.get("pcCallee") or session.get("pc2")
    return session.get("pc")


def _leg_track_key(leg: str) -> str:
    return "pc2LocalTrack" if leg == "callee" else "localAudioTrack"


def _leg_ending_key(leg: str) -> str:
    return "endingAwaitAnswerCallee" if leg == "callee" else "endingAwaitAnswerPc1"


def _callee_ending(session: dict[str, Any]) -> bool:
    return bool(
        session.get("endingAwaitAnswerCallee")
        or session.get("endingAwaitAnswerPc1")
        or session.get("softEndInProgress")
        or session.get("endCallRenegotiating")
    )


async def wait_until_callee_rungable(
    session: dict[str, Any], timeout: float = 1.0
) -> None:
    """CALLING + peer ENDING → wait for the end-call answer, then RING.

    iOS answers that offer in a few hundred ms. Android does not. Cap at 1s
    so a missing answer cannot hold the next RING. Callers dial after this
    returns whether or not the answer arrived.
    """
    timeout = min(1.0, max(0.0, float(timeout)))
    if not _callee_ending(session):
        return
    log.info(
        f"PC-callee: wait ENDING before RING session={session.get('sessionId')} "
        f"endingAwaitCallee={bool(session.get('endingAwaitAnswerCallee'))} "
        f"endingAwaitPc1={bool(session.get('endingAwaitAnswerPc1'))} "
        f"softEnd={bool(session.get('softEndInProgress'))} "
        f"endCallReneg={bool(session.get('endCallRenegotiating'))}"
    )
    deadline = time.monotonic() + max(0.0, float(timeout))
    while _callee_ending(session) and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    log.info(
        f"PC-callee: ENDING wait done session={session.get('sessionId')} "
        f"still_ending={_callee_ending(session)}"
    )


def _send_leg_dc_json(session: dict[str, Any], leg: str, message: dict[str, Any]) -> None:
    if leg == "callee":
        send_callee_dc_json(session, message)
    else:
        send_dc_json(session, message)


def _leg_dc_open(session: dict[str, Any], leg: str) -> bool:
    if leg == "pc1" or (session.get("mediaWorker") and leg == "pc1"):
        return _dc_is_open(session)
    if session.get("mediaWorker") or leg.startswith("callee:") or leg == "callee":
        if session.get("mediaWorker") and leg != "pc1":
            return _callee_transport_open(session, leg)
    if leg == "callee" or leg.startswith("callee:"):
        return _callee_transport_open(session, leg)
    return _dc_is_open(session)


def _callee_transport_open(session: dict[str, Any], leg: str = "callee") -> bool:
    """Live callee DC. Worker stores it on the ring, not only calleeDataChannel."""
    ident = _leg_ident(session, leg)

    def _open(dc: Any) -> bool:
        return str(getattr(dc, "readyState", "") or "").lower() == "open"

    found: list[Any] = []
    if ident:
        by_id = session.get("dcByIdentity")
        if isinstance(by_id, dict):
            found.append(by_id.get(ident))
        ring = (session.get("ringLegs") or {}).get(ident)
        if ring is not None:
            found.append(getattr(ring, "dc", None))
    found.append(session.get("calleeDataChannel"))
    for dc in found:
        if dc is not None and _open(dc):
            return True
    if session.get("calleeDcOpen"):
        winner = str(session.get("multiringWinner") or session.get("to") or "")
        if not ident or ident == winner or ident == str(session.get("to") or ""):
            return True
    return False


async def _set_audio_inactive(
    session: dict[str, Any],
    pc: Any,
    *,
    track_key: str,
) -> bool:
    """Node _setAudioInactive — transceiver inactive + null track for reuse."""
    if pc is None:
        return False
    tr = _audio_transceiver(pc)
    if tr is None:
        session[track_key] = None
        return False
    try:
        tr.direction = "inactive"
    except Exception:  # noqa: BLE001
        pass
    try:
        set_dir = getattr(tr, "setDirection", None)
        if callable(set_dir):
            set_dir("inactive")
    except Exception:  # noqa: BLE001
        pass
    sender = getattr(tr, "sender", None)
    if sender is not None:
        # replaceTrack(null) emits RTCP BYE → aiortc __stop_decoder() which
        # ends RemoteStreamTrack. Second call then has packetsReceived with
        # tap.recv() raising → silence. Keep the Switchable tap; mute via
        # set_source(None) in unbridge.
        try:
            sender._enabled = False
        except Exception:  # noqa: BLE001
            pass
    rec = getattr(tr, "receiver", None)
    if rec is not None:
        try:
            rec._enabled = False
        except Exception:  # noqa: BLE001
            pass
    return True


def _live_remote_audio(pc: Any) -> Any:
    """Receiver audio still on the PC even if session keys were cleared."""
    if pc is None:
        return None
    for tr in pc.getTransceivers() or []:
        rec = getattr(tr, "receiver", None)
        track = getattr(rec, "track", None) if rec is not None else None
        if track is None or getattr(track, "kind", "") != "audio":
            continue
        if str(getattr(track, "readyState", "live") or "live") == "ended":
            continue
        return track
    return None


def _restore_audio_sendrecv(pc: Any) -> None:
    tr = _audio_transceiver(pc)
    if tr is None:
        return
    try:
        tr.direction = "sendrecv"
    except Exception:  # noqa: BLE001
        pass
    try:
        set_dir = getattr(tr, "setDirection", None)
        if callable(set_dir):
            set_dir("sendrecv")
    except Exception:  # noqa: BLE001
        pass


def _unend_remote_track(track: Any) -> None:
    if track is None:
        return
    for cls in type(track).__mro__:
        ended_attr = f"_{cls.__name__}__ended"
        if hasattr(track, ended_attr):
            try:
                setattr(track, ended_attr, False)
            except Exception:  # noqa: BLE001
                pass
    try:
        track._ended = False
    except Exception:  # noqa: BLE001
        pass


def _drain_track_queue(track: Any) -> int:
    """Drop poison Nones (and stale frames) after RTCP BYE / __stop_decoder."""
    q_out = getattr(track, "_queue", None)
    if q_out is None:
        return 0
    drained = 0
    while True:
        try:
            q_out.get_nowait()
        except Exception:  # noqa: BLE001
            break
        drained += 1
    return drained


def _revive_audio_receiver(pc: Any, *, label: str) -> None:
    """Restart aiortc audio decoder after hangup.

    End-call / RTCP BYE calls RTCRtpReceiver.__stop_decoder(), which puts None
    on the track queue (readyState=ended). RTP still updates packetsReceived
    but the tap gets None → silence frames (PC2:out climbs, nobody hears).
    'already live' is not enough — drain the poison and restart if the worker
    died.
    """
    tr = _audio_transceiver(pc)
    if tr is None:
        return
    rec = getattr(tr, "receiver", None)
    sender = getattr(tr, "sender", None)
    if rec is not None:
        try:
            rec._enabled = True
        except Exception:  # noqa: BLE001
            pass
    if sender is not None:
        try:
            sender._enabled = True
        except Exception:  # noqa: BLE001
            pass
    _restore_audio_sendrecv(pc)
    track = getattr(rec, "track", None) if rec is not None else None
    if track is None:
        return
    was_ended = str(getattr(track, "readyState", "live") or "live") == "ended"
    _unend_remote_track(track)
    drained = _drain_track_queue(track)
    thread = getattr(rec, "_RTCRtpReceiver__decoder_thread", None)
    alive = bool(thread is not None and getattr(thread, "is_alive", lambda: False)())
    q_in = getattr(rec, "_RTCRtpReceiver__decoder_queue", None)
    # First RING: aiortc already started a healthy worker. Do not kill it
    # (put(None)+join on the event loop deadlocks decoder_worker ↔ loop).
    if alive and not was_ended and drained == 0:
        log.info(f"{label}: audio decoder already live")
        return
    if alive:
        if q_in is not None:
            try:
                q_in.put_nowait(None)
            except Exception:  # noqa: BLE001
                pass
            while True:
                try:
                    q_in.get_nowait()
                except Exception:  # noqa: BLE001
                    break
        log.info(
            f"{label}: bouncing audio decoder "
            f"ended={was_ended} drained={drained} prior_alive={alive}"
        )
    q_out = asyncio.Queue()
    try:
        track._queue = q_out
    except Exception:  # noqa: BLE001
        q_out = getattr(track, "_queue", None)
    if q_in is None or q_out is None:
        log.warn(f"{label}: cannot revive decoder (missing queues)")
        return
    try:
        import aiortc.rtcrtpreceiver as rr

        worker = rr.decoder_worker
    except Exception as exc:  # noqa: BLE001
        log.warn(f"{label}: decoder_worker import failed: {exc}")
        return
    loop = asyncio.get_event_loop()
    t = threading.Thread(
        target=worker,
        name=f"{label}-decoder-revive",
        args=(loop, q_in, q_out),
        daemon=True,
    )
    t.start()
    try:
        rec._RTCRtpReceiver__decoder_thread = t
    except Exception:  # noqa: BLE001
        pass
    log.info(
        f"{label}: revived audio decoder thread "
        f"ended={was_ended} drained={drained} prior_alive={alive}"
    )


async def keep_pc1_sender_alive(session: dict[str, Any]) -> None:
    """Silence PC1 without replaceTrack (keep send loop + SSRC)."""
    sid = session.get("sessionId") or "?"
    tap = session.get("pc1SendTap")
    set_src = getattr(tap, "set_source", None)
    if callable(set_src):
        set_src(None)
        log.info(f"MEDIA: PC1 tap silenced (pre-BYE, no replaceTrack) session={sid}")
        return
    log.warn(f"MEDIA: PC1 tap missing — cannot silence without replaceTrack session={sid}")


async def unbridge_media(
    session: dict[str, Any], *, keep_pc1_audio: bool = False
) -> None:
    """Drop MediaRelay bridge. Soft-end inactivates both legs.

    IVR→WebRTC xfer: keep_pc1_audio=True — caller already has audio up; only
    drop PC2. Call keep_pc1_sender_alive() BEFORE OpenAI BYE.
    """
    if session.get("mediaWorker"):
        from webrtc_pc_worker import unbridge_media as _u

        await _u(session, keep_pc1_audio=keep_pc1_audio)
        return
    finalize_recording(session)
    sid = session.get("sessionId") or "?"
    legs = (("callee", "pc2LocalTrack"),)
    if not keep_pc1_audio:
        legs = (("pc1", "localAudioTrack"),) + legs
    for leg, key in legs:
        pc = _leg_pc(session, "callee" if leg == "callee" else "pc1")
        if pc is None:
            session[key] = None
            continue
        try:
            await _set_audio_inactive(session, pc, track_key=key)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"MEDIA: unbridge inactive failed session={sid} leg={leg}: {exc}")
            session[key] = None
        tap = session.get("pc1SendTap" if key == "localAudioTrack" else "pc2SendTap")
        set_src = getattr(tap, "set_source", None)
        if callable(set_src):
            set_src(None)
    session["bridgedClientToSbc"] = False
    session["bridgedSbcToClient"] = False
    session["mediaBridged"] = False
    session.pop("bridgePc1TrackId", None)
    session.pop("bridgePc2TrackId", None)
    if not keep_pc1_audio:
        session.pop("pc1RemoteTrack", None)
    session.pop("pc2RemoteTrack", None)
    session.pop("pc1RemoteTrackBound", None)
    session.pop("pc2RemoteTrackBound", None)
    session.pop("mediaRelay", None)
    session["mediaStatsScheduled"] = False
    session["calleeRingAnswered"] = False
    session.pop("activeCallId", None)
    session.pop("remintAudio", None)
    log.info(f"MEDIA: unbridged session={sid} keep_pc1_audio={keep_pc1_audio}")


def _end_call_identities(session: dict[str, Any], payload: Optional[dict[str, Any]] = None) -> tuple[Any, Any]:
    payload = payload or {}
    local_from = payload.get("to") or session.get("to") or session.get("from")
    remote_to = payload.get("from") or session.get("from") or session.get("to")
    return local_from, remote_to


async def answer_end_call_offer(
    session: dict[str, Any],
    payload: dict[str, Any],
    *,
    leg: str = "pc1",
) -> None:
    if session.get("mediaWorker"):
        from webrtc_pc_worker import answer_end_call_offer as _a

        await _a(session, payload, leg=leg)
        return
    """Answer client's inactive end-call offer (audio off, DC/transport kept)."""
    _require_aiortc()
    pc = _leg_pc(session, leg)
    if pc is None:
        raise RuntimeError(f"no peer connection for end-call answer leg={leg}")
    offer_sdp = str(payload.get("sdp") or "")
    if not offer_sdp.strip():
        raise RuntimeError("end-call offer missing sdp")
    track_key = _leg_track_key(leg)
    call_id = _normalize_call_id(payload.get("callId")) or _call_id_for_leg(session, leg)
    session["endCallRenegotiating"] = True
    session[_leg_ending_key(leg)] = True
    log.info(
        f"PC: END-CALL ANSWER begin session={session.get('sessionId')} "
        f"leg={leg} offer_bytes={len(offer_sdp)}"
    )
    await pc.setRemoteDescription(RTCSessionDescription(sdp=offer_sdp, type="offer"))
    await _set_audio_inactive(session, pc, track_key=track_key)
    answer = await pc.createAnswer()
    answer_sdp = align_end_call_answer_sdp(answer.sdp if answer else "", offer_sdp)
    await pc.setLocalDescription(RTCSessionDescription(sdp=answer_sdp, type="answer"))
    local = pc.localDescription
    if local is not None and local.sdp:
        answer_sdp = align_end_call_answer_sdp(local.sdp, offer_sdp)
    local_from, remote_to = _end_call_identities(session, payload)
    answer_payload = {
        "type": "answer",
        "from": local_from,
        "to": remote_to,
        "sessionId": payload.get("sessionId") or session.get("sessionId"),
        "sdp": answer_sdp,
    }
    if call_id is not None:
        answer_payload["callId"] = call_id
    msg = _with_call_id(
        {
            "msgType": "signaling",
            "action": "end-call",
            "payload": answer_payload,
        },
        call_id,
    )
    _send_leg_dc_json(session, leg, msg)
    session[_leg_ending_key(leg)] = False
    session["endCallRenegotiating"] = False
    log.info(
        f"PC: END-CALL ANSWER sent session={session.get('sessionId')} "
        f"leg={leg} bytes={len(answer_sdp)}"
    )


async def initiate_end_call_offer(
    session: dict[str, Any],
    *,
    leg: str = "pc1",
    reason: str = "hangup",
) -> bool:
    """Server-driven inactive end-call offer toward a WebRTC leg. Returns False if no DC/PC."""
    if session.get("mediaWorker"):
        from webrtc_pc_worker import initiate_end_call_offer as _i

        return await _i(session, leg=leg, reason=reason)
    _require_aiortc()
    if not _leg_dc_open(session, leg):
        log.info(
            f"PC: END-CALL OFFER skip session={session.get('sessionId')} "
            f"leg={leg} (no open DC)"
        )
        return False
    pc = _leg_pc(session, leg)
    if pc is None:
        return False
    track_key = _leg_track_key(leg)
    call_id = _call_id_for_leg(session, leg)
    await _set_audio_inactive(session, pc, track_key=track_key)
    offer = await pc.createOffer()
    offer_sdp = normalize_end_call_offer_sdp(offer.sdp if offer else "")
    await pc.setLocalDescription(RTCSessionDescription(sdp=offer_sdp, type="offer"))
    local = pc.localDescription
    if local is not None and local.sdp:
        offer_sdp = normalize_end_call_offer_sdp(local.sdp)
    # PC1: gateway speaks as the number the caller dialed. promote()
    # overwrites `to` with the extension, and that phone is not in a
    # session with sys… — it is in a session with originTo (the DID).
    if leg == "callee":
        local_from, remote_to = session.get("from"), session.get("to")
    else:
        local_from = session.get("originTo") or session.get("dialedTo") or session.get("to")
        remote_to = session.get("from")
    payload = {
        "type": "offer",
        "from": local_from,
        "to": remote_to,
        "sessionId": session.get("sessionId"),
        "sdp": offer_sdp,
    }
    if call_id is not None:
        payload["callId"] = call_id
    msg = _with_call_id(
        {
            "msgType": "signaling",
            "action": "end-call",
            "reason": reason,
            "payload": payload,
        },
        call_id,
    )
    _send_leg_dc_json(session, leg, msg)
    session[_leg_ending_key(leg)] = True
    log.info(
        f"PC: END-CALL OFFER sent session={session.get('sessionId')} "
        f"leg={leg} bytes={len(offer_sdp)} reason={reason}"
    )
    return True


async def apply_end_call_answer(
    session: dict[str, Any],
    payload: dict[str, Any],
    *,
    leg: str = "pc1",
) -> None:
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import apply_end_call_answer as _a

        await _a(session, payload, leg=leg)
        return
    _require_aiortc()
    pc = _leg_pc(session, leg)
    if pc is None:
        return
    answer_sdp = str(payload.get("sdp") or "")
    if answer_sdp.strip():
        await pc.setRemoteDescription(
            RTCSessionDescription(sdp=answer_sdp, type="answer")
        )
    session[_leg_ending_key(leg)] = False
    session["endCallRenegotiating"] = False
    call_id = _normalize_call_id(payload.get("callId")) or _call_id_for_leg(session, leg)
    # Node WebRtcNegotiation.endCall(mode=remote) answer branch: bare
    # signaling/end-call only. Extra call/end races iOS async removeAudio vs RING.
    try:
        _send_leg_dc_json(
            session,
            leg,
            _with_call_id(
                {"msgType": "signaling", "action": "end-call"},
                call_id,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC: bare end-call after answer failed session={session.get('sessionId')} "
            f"leg={leg}: {exc}"
        )
    log.info(
        f"PC: END-CALL answer applied session={session.get('sessionId')} "
        f"leg={leg} bytes={len(answer_sdp)}"
    )


def reset_soft_end_for_reuse(session: dict[str, Any]) -> None:
    """Clear call-level flags so a later DC RING can reuse the same PC/DC."""
    session["dcRingStarted"] = False
    session["ringAckSent"] = False
    session["softEnded"] = True
    session["dialogOriginator"] = None
    session["state"] = "connected"
    session["activeCallId"] = None
    session.pop("activeCallIdRaw", None)
    session["pendingAnswerSdp"] = None
    session["lastRingPayload"] = None
    session["endCallSent"] = False
    session["failureNotified"] = False
    session["failureCleanupDone"] = False
    for fut_key in ("calleeRingAnswerFut", "pc1RingAnswerFut"):
        fut = session.get(fut_key)
        if fut is not None and not fut.done():
            try:
                fut.cancel()
            except Exception:  # noqa: BLE001
                pass
        session[fut_key] = None
    for ring_leg in (session.get("ringLegs") or {}).values():
        try:
            ring_leg.answered_via_http_offer = False
            ring_leg._http_offer_pickup_done = False
            ring_leg.declined = False
        except Exception:  # noqa: BLE001
            pass


async def _client_inactive_end(
    session: dict[str, Any],
    payload: dict[str, Any],
    *,
    leg: str,
    reason: str = "hangup",
) -> None:
    """Answer client inactive end-call offer; soft-end peer/SIP if not already ended."""
    try:
        await answer_end_call_offer(session, payload, leg=leg)
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC: answer inactive end-call failed session={session.get('sessionId')} "
            f"leg={leg}: {exc}"
        )
    if session.get("softEnded") or session.get("softEndInProgress"):
        return
    end_cb = session.get("on_dc_end")
    if callable(end_cb):
        await end_cb(session, reason, ended_leg=leg)


def _handle_dc_message(session: dict[str, Any], raw: str) -> None:
    session_id = session.get("sessionId") or "?"
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        log.warn(f"PC1: session={session_id} DC non-JSON message bytes={len(raw)}")
        return
    if not isinstance(msg, dict):
        return

    msg_type = msg.get("msgType")
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    action = msg.get("action") or payload.get("type")
    action_l = str(action or "").lower()
    payload_type = str(payload.get("type") or "").lower()
    sdp = str(payload.get("sdp") or "")
    log.info(
        f"PC1: session={session_id} DC-IN msgType={msg_type!r} action={action!r} "
        f"sdp_len={len(sdp)}"
    )
    _note_dc_peer_alive(session, str(session.get("from") or ""))
    _note_leg_call_id(session, "pc1", msg)

    # Bare call/end — soft end (SIP hard + peer soft); trailing inactive offer answered below.
    if msg_type == "call" and action_l in ("end", "hangup"):
        if session.get("pc1TransferredOut"):
            log.info(
                f"PC1: session={session_id} absorb call/end on transferred-out PC1"
            )
            return
        reason = str(msg.get("reason") or action or "hangup")
        log.info(f"PC1: session={session_id} DC bare end reason={reason}")
        end_cb = session.get("on_dc_end")
        if callable(end_cb):
            _schedule(
                session,
                end_cb(session, reason, ended_leg="pc1"),
                label="on_dc_end",
            )
        return

    # signaling/end-call: answer | inactive offer | bare
    if msg_type == "signaling" and action_l == "end-call":
        if payload_type == "answer" and sdp.strip():
            _schedule(
                session,
                apply_end_call_answer(session, payload, leg="pc1"),
                label="apply_end_call_answer_pc1",
            )
            return
        if session.get("pc1TransferredOut"):
            log.info(
                f"PC1: session={session_id} absorb signaling/end-call on transferred-out PC1"
            )
            return
        if sdp.strip() and (is_inactive_offer(sdp) or not _sdp_has_active_audio(sdp)):
            # Answer inactive + soft-end peer/SIP (Node END_RENEGOTIATION).
            reason = str(msg.get("reason") or "hangup")
            _schedule(
                session,
                _client_inactive_end(session, payload, leg="pc1", reason=reason),
                label="client_inactive_end_pc1",
            )
            return
        # Bare signaling/end-call (no usable SDP) → soft end like call/end.
        reason = str(msg.get("reason") or "hangup")
        end_cb = session.get("on_dc_end")
        if callable(end_cb):
            _schedule(
                session,
                end_cb(session, reason, ended_leg="pc1"),
                label="on_dc_end",
            )
        return

    if msg_type != "signaling":
        if msg_type == "call" and action_l == "ack":
            log.info(
                f"PC1: session={session_id} DC ack ackFor={msg.get('ackFor')!r}"
            )
            return
        action_cb = session.get("on_dc_action")
        if callable(action_cb) and (
            session.get("productKind")
            or msg_type in ("dtmf", "digit", "action")
            or payload.get("digit") is not None
            or action_l in ("dtmf", "digit", "transfer", "redirect")
        ):
            msg["_dcLeg"] = "pc1"
            msg["_dcIdent"] = str(session.get("from") or "")
            action_cb(session, msg)
            return
        log.info(f"PC1: session={session_id} DC action ignored (no handler) action={action!r}")
        return
    if (
        payload_type == "answer"
        and action_l != "end-call"
        and sdp.strip()
        and not is_inactive_offer(sdp)
    ):
        fut = session.get("pc1RingAnswerFut")
        if fut is not None and not fut.done():
            _resolve_future(fut, sdp)
        return
    if payload_type != "offer":
        return
    if is_inactive_offer(sdp) or not _sdp_has_active_audio(sdp):
        # Inactive offer without end-call action — still soft-absorb (Node END_RENEGOTIATION).
        log.info(f"PC1: session={session_id} inactive signaling offer → end-call answer")
        reason = str(msg.get("reason") or "hangup")
        _schedule(
            session,
            _client_inactive_end(session, payload, leg="pc1", reason=reason),
            label="client_inactive_end_pc1",
        )
        return

    ring_call_id = _normalize_call_id(payload.get("callId"))
    if ring_call_id is not None and not _other_seat_ring_id(session, "pc1", ring_call_id):
        session["activeCallId"] = ring_call_id
        session["legCallId:pc1"] = ring_call_id
    elif payload.get("callId") is not None:
        session["activeCallIdRaw"] = payload.get("callId")

    cb = session.get("on_dc_ring")
    if not callable(cb):
        log.warn(f"PC1: session={session_id} audio RING but no on_dc_ring handler")
        return
    if session.get("dcRingStarted"):
        if session.get("clientEnded") or session.get("softEnded") or session.get("softEndInProgress"):
            session["dcRingStarted"] = False
        else:
            log.info(f"PC1: session={session_id} audio RING already in progress; ignoring")
            return
    # RING handler logs reuse from softEnded — do not clear it here.
    session["clientEnded"] = False
    session["dcRingStarted"] = True
    session["lastRingPayload"] = payload
    _schedule(session, cb(session, payload), label="on_dc_ring")


async def handshake(
    session: dict[str, Any],
    offer_sdp: str,
    candidates: Optional[list[Any]] = None,
    *,
    on_dc_ring: Optional[OnDcRing] = None,
    reuse_pc: bool = False,
) -> dict[str, Any]:
    """PC1 handshake for HTTP DC-only offer. Returns answer sdp + candidates."""
    if use_media_worker():
        from webrtc_pc_worker import handshake as _hs

        return await _hs(
            session, offer_sdp, candidates, on_dc_ring=on_dc_ring, reuse_pc=reuse_pc
        )
    _require_aiortc()
    session_id = session.get("sessionId") or "?"
    # Preserve end handler across PC recreate (set by ingress before handshake).
    on_dc_end = session.get("on_dc_end")
    on_dc_action = session.get("on_dc_action")
    if not (reuse_pc and session.get("pc") is not None):
        await close_pcs(session, pc1=True, callee=True)

    session["on_dc_ring"] = on_dc_ring
    session["on_dc_end"] = on_dc_end
    session["on_dc_action"] = on_dc_action
    session["eventLoop"] = asyncio.get_running_loop()
    session["iceCandidates"] = []
    session["dcRingStarted"] = False
    if not (reuse_pc and session.get("pc") is not None):
        session["dcOpen"] = False

    if session.get("pc") is None:
        pc = RTCPeerConnection(configuration=_pc_config())
        session["pc"] = pc
        _bind_pc_events(session, pc)
    else:
        pc = session["pc"]

    ufrag, _pwd = _sdp_ice_ufrag_pwd(str(offer_sdp or ""))
    session["pc1RemoteUfrag"] = str(ufrag or "")
    log.info(f"PC1: handshake begin session={session_id} offer_bytes={len(offer_sdp or '')}")
    await pc.setRemoteDescription(RTCSessionDescription(sdp=str(offer_sdp or ""), type="offer"))
    # Client sent trickle candidates with the offer — apply before answer.
    applied = await add_ice_candidates(session, candidates or [])
    log.info(f"PC1: applied offer trickle candidates={applied}")

    answer = await pc.createAnswer()
    # setLocalDescription gathers ICE and embeds candidates into localDescription.sdp.
    await pc.setLocalDescription(answer)
    await _wait_ice_gathering(pc)

    local = pc.localDescription
    answer_sdp = local.sdp if local else (answer.sdp if answer else "")
    # aiortc does not emit icecandidate events — parse SDP (Node parity: also return array).
    ice = candidates_from_sdp(answer_sdp)
    ice_for_client = candidates_for_client(ice)
    answer_sdp = embed_candidates_in_sdp(answer_sdp, ice_for_client)

    session["state"] = "pc1-answered"
    log.info(
        f"PC1: createAnswer done session={session_id} answer_bytes={len(answer_sdp)} "
        f"candidates={len(ice_for_client)} types[{candidate_type_counts(ice)}] "
        f"gather={pc.iceGatheringState}"
    )
    if not any("typ relay" in str(c.get("candidate") or "") for c in ice):
        log.warn(
            "PC1: no TURN relay candidate in answer — relay-only clients may stay "
            "connecting forever (Node always gathers via cellact TURN)"
        )
    # Trim log: first candidate lines for debugging.
    cand_lines = [
        ln.strip()
        for ln in answer_sdp.replace("\r\n", "\n").split("\n")
        if ln.startswith("a=candidate:")
    ][:6]
    log.info(f"PC1: answer candidates sample={cand_lines}")
    return {"sdp": answer_sdp, "candidates": ice_for_client}


async def add_ice_candidates(session: dict[str, Any], candidates: list[Any]) -> int:
    if use_media_worker() and session.get("mediaWorker"):
        from webrtc_pc_worker import add_ice_candidates as _add

        return await _add(session, candidates)
    _require_aiortc()
    pc = session.get("pc")
    if pc is None or candidate_from_sdp is None:
        return 0
    added = 0
    for c in candidates or []:
        if not c:
            continue
        if isinstance(c, dict):
            cand = c.get("candidate")
            mid = c.get("sdpMid")
            mline = c.get("sdpMLineIndex")
        else:
            cand = getattr(c, "candidate", None)
            mid = getattr(c, "sdpMid", None)
            mline = getattr(c, "sdpMLineIndex", None)
        if not cand:
            continue
        raw = str(cand)
        if raw.startswith("candidate:"):
            raw = raw[len("candidate:") :]
        try:
            ice = candidate_from_sdp(raw)
            ice.sdpMid = str(mid) if mid is not None else "0"
            if mline is not None:
                ice.sdpMLineIndex = int(mline)
            await pc.addIceCandidate(ice)
            added += 1
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if re.search(r"m[-\s]?line|iceParams|media section|kind", msg, re.I):
                continue
            log.warn(f"PC1: addIceCandidate failed: {exc}")
    return added


def _dc_is_open(session: dict[str, Any]) -> bool:
    if session.get("mediaWorker"):
        return bool(session.get("dcOpen"))
    dc = session.get("dataChannel")
    if dc is None:
        return False
    state = str(getattr(dc, "readyState", "") or "").lower()
    return state == "open" or bool(session.get("dcOpen"))


def _dc_send_bytes(session: dict[str, Any], dc: Any, raw: str) -> None:
    """aiortc DataChannel.send must run on the PC event loop (not tokio Dummy-N)."""
    def _do() -> None:
        dc.send(raw)

    loop = session.get("eventLoop") if isinstance(session, dict) else None
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is not None and (loop is None or loop is running):
        _do()
        return
    if loop is not None and loop.is_running():
        done = threading.Event()
        err: list[BaseException] = []

        def _wrap() -> None:
            try:
                _do()
            except BaseException as exc:  # noqa: BLE001
                err.append(exc)
            finally:
                done.set()

        loop.call_soon_threadsafe(_wrap)
        if not done.wait(timeout=5.0):
            raise RuntimeError("datachannel send timed out on session loop")
        if err:
            raise err[0]
        return
    raise RuntimeError("There is no current event loop in thread")


def send_dc_json(session: dict[str, Any], message: dict[str, Any]) -> None:
    if session.get("mediaWorker"):
        from webrtc_pc_worker import send_dc_json as _send

        _send(session, message, leg="pc1")
        return
    dc = session.get("dataChannel")
    session_id = session.get("sessionId") or "?"
    if not _dc_is_open(session) or dc is None:
        raise RuntimeError(f"[{session_id}] no open data channel")
    raw = json.dumps(message)
    action = message.get("action") or (message.get("payload") or {}).get("type") or "unknown"
    log.info(
        f"PC1: session={session_id} DC-OUT msgType={message.get('msgType')!r} "
        f"action={action!r}"
    )
    _dc_send_bytes(session, dc, raw)


def send_dc_ack_ring(session: dict[str, Any]) -> None:
    """Node ackConnected — tell client we heard the RING (before SIP completes)."""
    # Echo the id the caller already put on its offer. Do not mint one:
    # iOS ignores call/end whose callId it never adopted.
    call_id = _call_id_for_leg(session, "pc1")
    send_dc_json(
        session,
        _with_call_id(
            {
                "msgType": "call",
                "action": "ack",
                "ackFor": "ring",
            },
            call_id,
        ),
    )


def send_dc_signaling_answer(session: dict[str, Any], answer_sdp: str) -> None:
    send_dc_json(
        session,
        {
            "msgType": "signaling",
            "payload": {
                "type": "answer",
                "from": session.get("to"),
                "to": session.get("from"),
                "sessionId": session.get("sessionId"),
                "sdp": answer_sdp,
            },
        },
    )


def send_dc_ack_and_answer(session: dict[str, Any], answer_sdp: str) -> None:
    # Ring ack is sent immediately on RING ingress; only re-ack if we skipped it.
    if not session.get("ringAckSent"):
        send_dc_ack_ring(session)
        session["ringAckSent"] = True
    send_dc_signaling_answer(session, answer_sdp)


def send_dc_ack_answer(session: dict[str, Any]) -> None:
    """Node WebRtcNegotiation.answer() — ackFor=answer after flushing held SDP."""
    call_id = _call_id_for_leg(session, "pc1")
    send_dc_json(
        session,
        {
            "msgType": "call",
            "action": "ack",
            "ackFor": "answer",
            "callId": call_id,
        },
    )


async def _replace_track(sender: Any, track: Any) -> None:
    """aiortc replaceTrack is sync (returns None); browser WebRTC is async."""
    if sender is None:
        return
    result = sender.replaceTrack(track)
    if asyncio.iscoroutine(result):
        await result


def _audio_sender(pc: Any) -> Any:
    if pc is None:
        return None
    for tr in pc.getTransceivers() or []:
        kind = getattr(tr, "kind", None)
        if kind == "audio" and getattr(tr, "sender", None) is not None:
            return tr.sender
    for sender in pc.getSenders() or []:
        track = getattr(sender, "track", None)
        if track is not None and getattr(track, "kind", None) == "audio":
            return sender
        # sender with null track still usable for replaceTrack
        if track is None and getattr(sender, "track", None) is None:
            # prefer transceiver path above; skip ambiguous senders
            continue
    return None


def _audio_transceiver(pc: Any) -> Any:
    if pc is None:
        return None
    for tr in pc.getTransceivers() or []:
        if getattr(tr, "kind", None) == "audio":
            return tr
        recv = getattr(tr, "receiver", None)
        rtrack = getattr(recv, "track", None) if recv is not None else None
        if rtrack is not None and getattr(rtrack, "kind", None) == "audio":
            return tr
    return None


def _random_ssrc() -> int:
    n = 0
    while n == 0:
        n = random.randint(1, 0xFFFFFFFF)
    return n


def _setattr_first(obj: Any, names: tuple[str, ...], value: Any) -> bool:
    for name in names:
        try:
            setattr(obj, name, value)
            return True
        except Exception:  # noqa: BLE001
            continue
    for cls in type(obj).__mro__:
        for raw in names:
            priv = f"_{cls.__name__}__{raw.lstrip('_')}"
            try:
                setattr(obj, priv, value)
                return True
            except Exception:  # noqa: BLE001
                continue
    return False


def _rotate_audio_sender_identity(sender: Any, track: Any) -> dict[str, Any]:
    """Node _rotateAudioSenderIdentity — replaceTrack does not change SSRC/msid."""
    ssrc = _random_ssrc()
    stream_id = str(uuid.uuid4())
    track_id = str(getattr(track, "id", "") or uuid.uuid4())
    old = getattr(sender, "_ssrc", None) or getattr(sender, "ssrc", None)
    _setattr_first(sender, ("_ssrc", "ssrc"), ssrc)
    _setattr_first(sender, ("_rtx_ssrc", "rtxSsrc"), _random_ssrc())
    _setattr_first(sender, ("_stream_id", "streamId", "stream_id"), stream_id)
    if track is not None:
        track_id = str(getattr(track, "id", None) or track_id)
        _setattr_first(sender, ("_track_id", "trackId"), track_id)
        _setattr_first(track, ("_ssrc", "ssrc"), ssrc)
    enc = getattr(sender, "_RTCRtpSender__encoder", None)
    if enc is not None:
        try:
            sender._RTCRtpSender__encoder = None
        except Exception:  # noqa: BLE001
            pass
    # Node zeros seq/ts so the new SSRC doesn't stitch onto the hangup timeline.
    _setattr_first(sender, ("_RTCRtpSender__rtp_history",), {})
    for name in (
        "__sequence_number",
        "_RTCRtpSender__sequence_number",
        "sequenceNumber",
        "_timestamp",
        "timestamp",
    ):
        try:
            setattr(sender, name, 0)
        except Exception:  # noqa: BLE001
            continue
    return {
        "ssrc": ssrc,
        "stream_id": stream_id,
        "track_id": track_id,
        "old_ssrc": old,
    }


def rewrite_audio_identity(
    sdp: str, ssrc: int, stream_id: str, track_id: str
) -> str:
    """Force audio a=ssrc / a=msid after remint (aiortc createOffer may snapshot)."""
    session, media = _split_sdp_sections(sdp)
    if not media:
        return sdp
    out: list[str] = []
    for sec in media:
        if _media_kind(sec) != "audio":
            out.append(sec)
            continue
        sec = re.sub(r"^a=ssrc:\d+", f"a=ssrc:{ssrc}", sec, flags=re.M)
        if re.search(r"^a=msid:", sec, re.M):
            sec = re.sub(
                r"^a=msid:[^\r\n]+",
                f"a=msid:{stream_id} {track_id}",
                sec,
                flags=re.M,
            )
        else:
            sec = sec.rstrip("\r\n") + f"\r\na=msid:{stream_id} {track_id}\r\n"
        out.append(sec)
    line_ending = "\r\n" if "\r\n" in str(sdp or "") else "\n"
    return session.rstrip("\r\n") + line_ending + line_ending.join(out)


def apply_stored_audio_identity(
    session: dict[str, Any], sdp: str, key: str
) -> str:
    ident = session.get(f"{key}:identity")
    if not isinstance(ident, dict) or not ident.get("ssrc"):
        return sdp
    return rewrite_audio_identity(
        sdp,
        int(ident["ssrc"]),
        str(ident["stream_id"]),
        str(ident["track_id"]),
    )


def _consume_audio_remint(session: dict[str, Any], slot: str) -> bool:
    """True only after hangup unbridge — next RING remints SSRC/msid."""
    flags = session.get("remintAudio")
    if not isinstance(flags, dict):
        return False
    return bool(flags.pop(slot, False))


def _tap_slot_for_key(key: str) -> str:
    if key == "localAudioTrack" or str(key).startswith("localAudio"):
        return "pc1SendTap"
    return "pc2SendTap"


async def _ensure_local_audio_on_pc(
    session: dict[str, Any],
    pc: Any,
    *,
    key: str,
    remint: bool = False,
) -> Any:
    """Attach blank audio track. remint=True: Node _ensureAudioSenderOnExistingTransceiver
    — rotate SSRC/msid on the existing mid. After end-call we replaceTrack(null);
    reuse the same Switchable tap (do not mint a second recv loop). Rotate BEFORE
    replaceTrack so the RTP task starts on the new SSRC (Node order).
    """
    tr = _audio_transceiver(pc)
    tap_slot = _tap_slot_for_key(key)
    existing = session.get(key)
    if existing is None:
        existing = session.get(tap_slot)
    if existing is not None and not remint:
        if tr is not None:
            try:
                tr.direction = "sendrecv"
            except Exception:  # noqa: BLE001
                pass
            sender = getattr(tr, "sender", None)
            if sender is not None and getattr(sender, "track", None) is None:
                await _replace_track(sender, existing)
            session[key] = existing
            session[tap_slot] = existing
            return existing
        # Brand-new PC has no transceiver yet. Early-return without addTrack
        # produced a 99-byte BUNDLE-only offer (rtpengine "Error rewriting SDP").
        try:
            pc.addTrack(existing)
        except Exception:  # noqa: BLE001
            existing = _SwitchableAudioTrack()
            pc.addTrack(existing)
        session[key] = existing
        session[tap_slot] = existing
        return existing
    track = existing if existing is not None else _SwitchableAudioTrack()
    session[tap_slot] = track
    session[key] = track
    if tr is not None and getattr(tr, "sender", None) is not None:
        try:
            tr.direction = "sendrecv"
        except Exception:  # noqa: BLE001
            pass
        if remint:
            ident = _rotate_audio_sender_identity(tr.sender, track)
            session[f"{key}:identity"] = ident
            log.info(
                f"PC: rotated {key} session={session.get('sessionId')} "
                f"ssrc {ident.get('old_ssrc')} -> {ident.get('ssrc')} "
                f"msid {ident.get('stream_id')} {ident.get('track_id')}"
            )
        await _replace_track(tr.sender, track)
        try:
            tr.direction = "sendrecv"
        except Exception:  # noqa: BLE001
            pass
    else:
        pc.addTrack(track)
    if remint:
        log.info(
            f"PC: reminted {key} session={session.get('sessionId')} "
            f"(tap id={id(track)} reused={existing is track})"
        )
    return track


async def _wait_pc_connected(
    pc: Any,
    *,
    label: str,
    timeout_s: float = 8.0,
) -> bool:
    """Wait until DTLS is up — ice=completed alone is NOT enough (can still fail)."""
    if pc is None:
        return False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    last = ""
    while loop.time() < deadline:
        conn = str(getattr(pc, "connectionState", "") or "")
        ice = str(getattr(pc, "iceConnectionState", "") or "")
        key = f"{conn}/{ice}"
        if key != last:
            log.info(f"{label}: wait-connected connectionState={conn} ice={ice}")
            last = key
        if conn == "connected":
            return True
        if conn == "failed" or ice == "failed":
            log.warn(f"{label}: connection failed connectionState={conn} ice={ice}")
            return False
        await asyncio.sleep(0.05)
    log.warn(f"{label}: connect timeout connectionState={getattr(pc, 'connectionState', '?')} "
             f"ice={getattr(pc, 'iceConnectionState', '?')}")
    return False


async def _bridge_media(session: dict[str, Any], *, force: bool = False) -> None:
    """Relay decoded audio PC1↔PC2 via MediaRelay (aiortc stand-in for Node RTP bridge).

    Wait until PC2 DTLS is up — replaceTrack during handshake correlates with
    connectionState=failed after ice=completed.

    IMPORTANT: never force-resubscribe an already-bridged leg. A second
    MediaRelay.subscribe() cancels the first consumer and (by default) stops
    the source track → PC2:out stuck at ~1 while PC1:in keeps climbing.
    """
    if session.get("mediaWorker"):
        from webrtc_pc_worker import _bridge_media as _b

        await _b(session, force=force)
        return
    # Inbound SBC→WebRTC: do NOT bridge during PC1 setRemote/createAnswer —
    # early subscribe + later rebridge = PC2.out stuck at ~1 (dead to phone).
    if session.get("routeKind") == "inbound" and not session.get("inboundSipAnswered"):
        log.info(
            f"MEDIA: bridge deferred (inbound SIP not answered) "
            f"session={session.get('sessionId')}"
        )
        return
    if session.get("routeKind") == "inbound":
        if not (session.get("calleeRingAnswered") and session.get("pc2Connected")):
            log.info(
                f"MEDIA: bridge deferred (phone leg not ready) "
                f"session={session.get('sessionId')}"
            )
            return
        if not session.get("pc1Connected"):
            log.info(
                f"MEDIA: bridge deferred (sbc leg not ready) "
                f"session={session.get('sessionId')}"
            )
            return
    pc1 = session.get("pc")
    pc2 = session.get("pc2")
    pc1_remote = session.get("pc1RemoteTrack") or _live_remote_audio(pc1)
    pc2_remote = session.get("pc2RemoteTrack") or _live_remote_audio(pc2)
    if pc1_remote is not None:
        session["pc1RemoteTrack"] = pc1_remote
    if pc2_remote is not None:
        session["pc2RemoteTrack"] = pc2_remote
    same_c2s = (
        pc1_remote is not None
        and session.get("bridgedClientToSbc")
        and session.get("bridgePc1TrackId") == id(pc1_remote)
    )
    same_s2c = (
        pc2_remote is not None
        and session.get("bridgedSbcToClient")
        and session.get("bridgePc2TrackId") == id(pc2_remote)
    )
    if session.get("mediaBridged") and not force and same_c2s and same_s2c:
        return
    if pc1 is None or pc2 is None:
        return
    if not session.get("pc2OfferReady"):
        log.info(
            f"MEDIA: bridge deferred (PC2 offer not ready) session={session.get('sessionId')}"
        )
        return
    if not session.get("pc2Connected"):
        log.info(
            f"MEDIA: bridge deferred (PC2 not connected) session={session.get('sessionId')}"
        )
        return
    if session.get("routeKind") != "inbound" and not session.get("pc1Connected"):
        log.info(
            f"MEDIA: bridge deferred (PC1 not connected) session={session.get('sessionId')}"
        )
        return

    try:
        # Switchable tap is the single consumer of each remote track.
        # MediaRelay.subscribe() on reuse races the hangup consumer and
        # yields zeros while packetsReceived still climbs.
        record = session_should_record(session)
        relay = session.get("mediaRelay")
        if record and relay is None and MediaRelay is not None:
            relay = MediaRelay()
            session["mediaRelay"] = relay

        sid = session.get("sessionId") or "?"
        if pc1_remote is not None:
            session["pc1RemoteTrack"] = pc1_remote
        if pc2_remote is not None:
            session["pc2RemoteTrack"] = pc2_remote
        # force only clears the "complete" latch so missing legs can attach;
        # do NOT clear per-leg flags (that caused double-subscribe track death).
        if force:
            session["mediaBridged"] = False

        if pc1_remote is not None and not same_c2s:
            src = pc1_remote
            via = "tap-direct"
            if record and relay is not None:
                src = _maybe_tee_recording(
                    session, _relay_subscribe(relay, pc1_remote), "sbc"
                )
                via = "tap-relay"
            tap = session.get("pc2SendTap")
            set_src = getattr(tap, "set_source", None)
            if callable(set_src):
                set_src(src)
            else:
                sender = _audio_sender(pc2)
                await _replace_track(sender, src)
                via = "replaceTrack"
            session["bridgedClientToSbc"] = True
            session["bridgePc1TrackId"] = id(pc1_remote)
            ready = getattr(pc1_remote, "readyState", "?")
            log.info(
                f"MEDIA: bridged PC1→PC2 (client→SBC) session={sid} "
                f"src_ready={ready} via={via}"
            )

        if pc2_remote is not None and not same_s2c:
            src = pc2_remote
            via = "tap-direct"
            if record and relay is not None:
                src = _maybe_tee_recording(
                    session, _relay_subscribe(relay, pc2_remote), "phone"
                )
                via = "tap-relay"
            tap = session.get("pc1SendTap")
            set_src = getattr(tap, "set_source", None)
            if callable(set_src):
                set_src(src)
            else:
                sender = _audio_sender(pc1)
                await _replace_track(sender, src)
                session["localAudioTrack"] = src
                via = "replaceTrack"
            session["bridgedSbcToClient"] = True
            session["bridgePc2TrackId"] = id(pc2_remote)
            ready = getattr(pc2_remote, "readyState", "?")
            log.info(
                f"MEDIA: bridged PC2→PC1 (SBC→client) session={sid} "
                f"src_ready={ready} via={via}"
            )

        if session.get("bridgedClientToSbc") and session.get("bridgedSbcToClient"):
            session["mediaBridged"] = True
            note_call_connected(session)
            log.info(f"MEDIA: bridge complete session={sid}")
            if not session.get("mediaStatsScheduled"):
                session["mediaStatsScheduled"] = True
                _schedule(session, _media_stats_probe(session), label="media-stats")
        else:
            log.info(
                f"MEDIA: bridge partial session={sid} "
                f"c2s={bool(session.get('bridgedClientToSbc'))} "
                f"s2c={bool(session.get('bridgedSbcToClient'))} "
                f"pc1_remote={pc1_remote is not None} pc2_remote={pc2_remote is not None}"
            )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"MEDIA: bridge attempt failed session={session.get('sessionId')}: {exc}")


async def _media_stats_probe(session: dict[str, Any], *, seconds: float = 3.0) -> None:
    """Sample RTP stats after bridge — proves whether MediaRelay is moving packets."""
    pc1 = session.get("pc")
    pc2 = session.get("pc2")
    sid = session.get("sessionId") or "?"
    if pc1 is None or pc2 is None:
        return
    await asyncio.sleep(max(0.5, float(seconds)))
    if session.get("closed") or session.get("clientEnded"):
        return

    async def _pkt(pc: Any, label: str) -> str:
        try:
            stats = await pc.getStats()
            inbound = outbound = 0
            for report in (stats.values() if hasattr(stats, "values") else stats or []):
                t = str(getattr(report, "type", "") or "")
                pkts = int(getattr(report, "packetsReceived", 0) or 0)
                pkts_out = int(getattr(report, "packetsSent", 0) or 0)
                if t == "inbound-rtp":
                    inbound += pkts
                elif t == "outbound-rtp":
                    outbound += pkts_out
            return f"{label}:in={inbound}:out={outbound}"
        except Exception as exc:  # noqa: BLE001
            return f"{label}:err={exc}"

    a = await _pkt(pc1, "PC1")
    b = await _pkt(pc2, "PC2")
    t1 = session.get("pc1RemoteTrack") or _live_remote_audio(pc1)
    t2 = session.get("pc2RemoteTrack") or _live_remote_audio(pc2)
    if t1 is not None:
        session["pc1RemoteTrack"] = t1
    if t2 is not None:
        session["pc2RemoteTrack"] = t2

    def _out(s: str) -> int:
        m = re.search(r":out=(\d+)", s)
        return int(m.group(1)) if m else -1

    def _inn(s: str) -> int:
        m = re.search(r":in=(\d+)", s)
        return int(m.group(1)) if m else -1

    cur = {
        "pc1in": _inn(a),
        "pc1out": _out(a),
        "pc2in": _inn(b),
        "pc2out": _out(b),
    }
    prev = session.get("mediaStatsPrev") or {}
    d = {
        k: cur[k] - int(prev.get(k) or 0)
        for k in cur
    }
    session["mediaStatsPrev"] = cur
    log.info(
        f"MEDIA-STATS session={sid} {a} {b} "
        f"dPC1:in={d['pc1in']}:out={d['pc1out']} "
        f"dPC2:in={d['pc2in']}:out={d['pc2out']} "
        f"pc1_src={getattr(t1, 'readyState', None)} "
        f"pc2_src={getattr(t2, 'readyState', None)}"
    )
    # Client→SBC dead: PC1 receiving but PC2 barely sending.
    try:
        if _inn(a) > 20 and _out(b) < 5:
            log.warn(
                f"MEDIA-STATS session={sid} client→SBC stalled "
                f"(PC1.in={_inn(a)} PC2.out={_out(b)})"
            )
        if _inn(b) > 20 and _out(a) < 5:
            log.warn(
                f"MEDIA-STATS session={sid} SBC→client stalled "
                f"(PC2.in={_inn(b)} PC1.out={_out(a)})"
            )
    except Exception:  # noqa: BLE001
        pass


async def rebridge_media(session: dict[str, Any], *, force: bool = False) -> None:
    """Attach any missing bridge legs after PC2 connect / client answer flush.

    Does NOT tear down existing MediaRelay consumers (see _bridge_media).
    """
    await _bridge_media(session, force=force)


def _prefer_g711_codecs(pc: Any, *, label: str = "PC") -> None:
    """Prefer PCMA/PCMU so bridge/SBC stay on G711 (Node mediaCodecPolicy)."""
    try:
        from aiortc import RTCRtpSender

        caps = RTCRtpSender.getCapabilities("audio")
        if caps is None or not getattr(caps, "codecs", None):
            return
        prefer = [
            c
            for c in caps.codecs
            if str(getattr(c, "mimeType", "") or "").lower()
            in ("audio/pcma", "audio/pcmu", "audio/telephone-event")
        ]
        if not prefer:
            return
        tr = _audio_transceiver(pc)
        if tr is not None and hasattr(tr, "setCodecPreferences"):
            tr.setCodecPreferences(prefer)
            log.info(
                f"{label}: codec preferences → "
                + ",".join(str(c.mimeType) for c in prefer[:4])
            )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"{label}: setCodecPreferences failed: {exc}")


def _bind_pc2_state_logs(session: dict[str, Any], pc: Any) -> None:
    sid = session.get("sessionId") or "?"

    @pc.on("icegatheringstatechange")
    def _on_gather() -> None:
        log.info(f"PC2: session={sid} iceGatheringState={pc.iceGatheringState}")

    @pc.on("iceconnectionstatechange")
    def _on_ice() -> None:
        log.info(
            f"PC2: session={sid} iceConnectionState={getattr(pc, 'iceConnectionState', '?')}"
        )

    @pc.on("connectionstatechange")
    def _on_conn() -> None:
        state = str(getattr(pc, "connectionState", "") or "")
        log.info(f"PC2: session={sid} connectionState={state}")
        if state == "connected":
            session["pc2Connected"] = True
            _schedule(session, _bridge_media(session), label="media-bridge-pc2-conn")
        elif state in ("failed", "closed", "disconnected"):
            # Renegotiation briefly hits "connecting" — don't clear there.
            if state in ("failed", "closed"):
                session["pc2Connected"] = False


def _bind_remote_audio_track(
    session: dict[str, Any],
    pc: Any,
    *,
    remote_key: str,
    label: str,
) -> None:
    if session.get("mediaWorker") or getattr(pc, "worker", False) or not hasattr(pc, "on"):
        return
    if session.get(f"{remote_key}Bound"):
        return
    session[f"{remote_key}Bound"] = True
    sid = session.get("sessionId") or "?"

    @pc.on("track")
    def _on_track(track: Any) -> None:
        kind = getattr(track, "kind", "") or ""
        log.info(f"{label}: session={sid} track received kind={kind!r}")
        if kind != "audio":
            return
        session[remote_key] = track
        _schedule(session, _bridge_media(session), label="media-bridge")


async def prepare_ring_answer(
    session: dict[str, Any],
    offer_sdp: str,
    candidates: Optional[list[Any]] = None,
) -> str:
    """Node applyOffer RING path: setRemote + createAnswer, hold SDP (do not send yet)."""
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import prepare_ring_answer as _p

        return await _p(session, offer_sdp, candidates)
    _require_aiortc()
    pc = session.get("pc")
    if pc is None:
        raise RuntimeError("PC1 missing for RING answer")
    session_id = session.get("sessionId") or "?"
    # Pin G711 before setRemote/createAnswer — matches Node mediaCodecPolicy.
    # Opus on PC1 + PCMA on PC2/SBC → silence/noise across the bridge.
    raw_offer = str(offer_sdp or "")
    try:
        from client_ingress import _narrow_telephony_audio_sdp

        offer_sdp = _narrow_telephony_audio_sdp(raw_offer)
    except Exception:  # noqa: BLE001
        offer_sdp = raw_offer
    if offer_sdp != raw_offer:
        log.info(
            f"PC1: narrowed RING offer to G711 "
            f"{len(raw_offer)}→{len(offer_sdp)} bytes"
        )
    session["ringOfferSdp"] = offer_sdp
    _bind_remote_audio_track(session, pc, remote_key="pc1RemoteTrack", label="PC1")

    log.info(
        f"PC1: RING setRemote begin session={session_id} offer_bytes={len(offer_sdp or '')}"
    )
    await pc.setRemoteDescription(
        RTCSessionDescription(sdp=offer_sdp, type="offer")
    )
    _revive_audio_receiver(pc, label="PC1")
    applied = await add_ice_candidates(session, candidates or [])
    log.info(f"PC1: RING applied trickle candidates={applied}")

    remint = False
    await _ensure_local_audio_on_pc(session, pc, key="localAudioTrack", remint=False)
    _prefer_g711_codecs(pc, label="PC1")

    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await _wait_ice_gathering(pc)

    local = pc.localDescription
    answer_sdp = local.sdp if local else (answer.sdp if answer else "")
    try:
        from client_ingress import ensure_telephone_event_sdp

        answer_sdp = ensure_telephone_event_sdp(answer_sdp, offer_sdp)
    except Exception:  # noqa: BLE001
        pass
    if remint:
        answer_sdp = apply_stored_audio_identity(session, answer_sdp, "localAudioTrack")
    ice = candidates_from_sdp(answer_sdp)
    ice_for_client = candidates_for_client(ice)
    answer_sdp = embed_candidates_in_sdp(answer_sdp, ice_for_client)

    session["pendingAnswerSdp"] = answer_sdp
    session["state"] = "ring-answer-held"
    log.info(
        f"PC1: held ring answer session={session_id} bytes={len(answer_sdp)} "
        f"remint={remint} {sdp_media_summary(answer_sdp)} "
        f"(flush on SBC/peer answer)"
    )
    return answer_sdp


def flush_held_ring_answer(session: dict[str, Any]) -> str:
    """Node answer() flush: send held PC1 SDP + ackFor=answer."""
    answer_sdp = str(session.get("pendingAnswerSdp") or "")
    if not answer_sdp.strip():
        raise RuntimeError("no held ring answer to flush")
    send_dc_signaling_answer(session, answer_sdp)
    try:
        send_dc_ack_answer(session)
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC1: ackFor=answer failed session={session.get('sessionId')}: {exc}"
        )
    session["pendingAnswerSdp"] = None
    session["state"] = "answered"
    log.info(
        f"PC1: flushed held ring answer session={session.get('sessionId')} "
        f"bytes={len(answer_sdp)}"
    )
    return answer_sdp


def _bind_callee_dc(session: dict[str, Any], dc: Any) -> None:
    """Outbound DC we create on PC-callee (Node attachOutboundDataChannel)."""
    session_id = session.get("sessionId") or "?"
    session["calleeDataChannel"] = dc
    session["calleeDcOpen"] = False

    @dc.on("open")
    def _on_open() -> None:  # noqa: ANN202
        session["calleeDcOpen"] = True
        log.info(f"PC-callee: session={session_id} datachannel OPEN")
        _resolve_future(session.get("calleeDcOpenFut"), True)

    @dc.on("close")
    def _on_close() -> None:  # noqa: ANN202
        session["calleeDcOpen"] = False
        log.info(f"PC-callee: session={session_id} datachannel CLOSED")

    @dc.on("message")
    def _on_message(message: Any) -> None:  # noqa: ANN401
        try:
            text = message if isinstance(message, str) else bytes(message).decode("utf-8", "replace")
            data = json.loads(text)
        except Exception:  # noqa: BLE001
            return
        if not isinstance(data, dict):
            return
        msg_type = data.get("msgType") or data.get("type")
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        action = data.get("action") or payload.get("type")
        action_l = str(action or "").lower()
        payload_type = str(payload.get("type") or "").lower()
        sdp = str(payload.get("sdp") or "")
        log.info(
            f"PC-callee: session={session_id} DC-IN msgType={msg_type!r} action={action!r} "
            f"sdp_len={len(sdp)}"
        )
        _note_dc_peer_alive(session, str(session.get("to") or ""))
        _note_leg_call_id(session, f"callee:{session.get('to') or ''}", data)

        # RING answer (active call) — only when not an end-call reneg answer.
        if (
            msg_type == "signaling"
            and payload_type == "answer"
            and action_l != "end-call"
            and sdp.strip()
            and not is_inactive_offer(sdp)
        ):
            fut = session.get("calleeRingAnswerFut")
            if fut is not None and not fut.done():
                _resolve_future(fut, sdp)
            return

        if msg_type == "call" and action_l in ("end", "hangup"):
            reason = str(data.get("reason") or action or "hangup")
            end_cb = session.get("on_dc_end")
            if callable(end_cb):
                _schedule(
                    session,
                    end_cb(session, reason, ended_leg="callee"),
                    label="callee_on_dc_end",
                )
            return

        if msg_type == "signaling" and action_l == "end-call":
            if payload_type == "answer" and sdp.strip():
                _schedule(
                    session,
                    apply_end_call_answer(session, payload, leg="callee"),
                    label="apply_end_call_answer_callee",
                )
                return
            if sdp.strip() and (is_inactive_offer(sdp) or not _sdp_has_active_audio(sdp)):
                reason = str(data.get("reason") or "hangup")
                _schedule(
                    session,
                    _client_inactive_end(session, payload, leg="callee", reason=reason),
                    label="client_inactive_end_callee",
                )
                return
            reason = str(data.get("reason") or "hangup")
            end_cb = session.get("on_dc_end")
            if callable(end_cb):
                _schedule(
                    session,
                    end_cb(session, reason, ended_leg="callee"),
                    label="callee_on_dc_end",
                )
            return

        # Inactive offer without end-call action → absorb (Node END_RENEGOTIATION).
        if (
            msg_type == "signaling"
            and payload_type == "offer"
            and sdp.strip()
            and (is_inactive_offer(sdp) or not _sdp_has_active_audio(sdp))
        ):
            reason = str(data.get("reason") or "hangup")
            _schedule(
                session,
                _client_inactive_end(session, payload, leg="callee", reason=reason),
                label="client_inactive_end_callee",
            )
            return

        action_cb = session.get("on_dc_action")
        if callable(action_cb) and (
            session.get("productKind")
            or msg_type in ("dtmf", "digit", "action")
            or payload.get("digit") is not None
            or action_l in ("dtmf", "digit", "transfer", "redirect")
        ):
            data.setdefault("_dcLeg", "callee")
            data.setdefault(
                "_dcIdent",
                str(session.get("multiringWinner") or session.get("to") or ""),
            )
            action_cb(session, data)


async def create_callee_dc_offer(session: dict[str, Any]) -> dict[str, Any]:
    """Node WebRtcOutboundLegFactory dcOnly: PC-callee createDataChannel + createOffer."""
    _require_aiortc()
    session_id = session.get("sessionId") or "?"
    prev = session.pop("pcCallee", None)
    if prev is not None:
        try:
            await prev.close()
        except Exception:  # noqa: BLE001
            pass

    loop = asyncio.get_running_loop()
    session["eventLoop"] = loop
    session["calleeDcOpenFut"] = loop.create_future()
    session["calleeRingAnswerFut"] = None

    pc = RTCPeerConnection(configuration=_pc_config())
    session["pcCallee"] = pc
    session["pc2"] = pc  # MediaRelay bridge helpers key off pc2
    session["pc2OfferReady"] = False
    session["pc2Connected"] = False
    session["calleeDcOpen"] = False
    session["bridgedClientToSbc"] = False
    session["bridgedSbcToClient"] = False
    session["mediaBridged"] = False
    session.pop("pc2RemoteTrack", None)
    session.pop("pc2RemoteTrackBound", None)

    _bind_pc2_state_logs(session, pc)
    dc = pc.createDataChannel("chat")
    _bind_callee_dc(session, dc)

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    await _wait_ice_gathering(pc)
    local = pc.localDescription
    sdp = local.sdp if local else (offer.sdp if offer else "")
    ice = candidates_from_sdp(sdp)
    ice_for_client = prefer_srflx_and_relay(ice)
    sdp = embed_candidates_in_sdp(sdp, ice_for_client)
    # Gate for _bridge_media — same flag create_pc2_offer sets for SBC path.
    session["pc2OfferReady"] = True
    log.info(
        f"PC-callee: DC-only offer session={session_id} bytes={len(sdp)} "
        f"candidates={len(ice_for_client)} types[{candidate_type_counts(ice_for_client)}]"
    )
    return {"sdp": sdp, "candidates": ice_for_client}


async def apply_callee_remote_answer(
    session: dict[str, Any],
    answer_sdp: str,
    candidates: Optional[list[Any]] = None,
) -> None:
    _require_aiortc()
    pc = session.get("pcCallee")
    if pc is None:
        raise RuntimeError("PC-callee missing for answer")
    ans = str(answer_sdp or "")
    await pc.setRemoteDescription(RTCSessionDescription(sdp=ans, type="answer"))
    await add_ice_candidates_to_pc(session, pc, candidates or [], label="PC-callee")
    log.info(
        f"PC-callee: setRemote answer session={session.get('sessionId')} bytes={len(ans)}"
    )


async def apply_callee_ring_answer(
    session: dict[str, Any],
    pc: Any,
    answer_sdp: str,
    candidates: Optional[list[Any]] = None,
    *,
    label: str = "PC-callee",
) -> str:
    """Apply RING answer as-is. Munging m=audio 9 + stripping ICE kills our
    send dest (PC2:out climbs, callee hears silence). Working calls used the
    real answer port (TURN). RING *offer* still uses port 9 so iOS sends on
    the HTTP bundle (PC2:in).
    """
    raw = str(answer_sdp or "")
    merged = merge_ice_array_and_sdp(raw, candidates)
    to_add = prefer_srflx_and_relay(merged)
    log.info(
        f"{label}: RING answer ICE types[{candidate_type_counts(merged)}] "
        f"apply={len(to_add)} {sdp_media_summary(raw)}"
    )
    await pc.setRemoteDescription(RTCSessionDescription(sdp=raw, type="answer"))
    _revive_audio_receiver(pc, label=label)
    applied = 0
    if to_add:
        applied = await add_ice_candidates_to_pc(session, pc, to_add, label=label)
    log.info(f"{label}: RING answer applied trickle candidates={applied}")
    return raw


async def add_ice_candidates_to_pc(
    session: dict[str, Any],
    pc: Any,
    candidates: list[Any],
    *,
    label: str = "PC",
) -> int:
    if getattr(pc, "worker", False) or session.get("mediaWorker"):
        from webrtc_pc_worker import add_ice_candidates_to_pc as _add

        return await _add(session, pc, candidates, label=label)
    if pc is None or candidate_from_sdp is None:
        return 0
    added = 0
    for c in candidates or []:
        if not c:
            continue
        if isinstance(c, dict):
            cand = c.get("candidate")
            mid = c.get("sdpMid")
            mline = c.get("sdpMLineIndex")
        else:
            cand = getattr(c, "candidate", None)
            mid = getattr(c, "sdpMid", None)
            mline = getattr(c, "sdpMLineIndex", None)
        if not cand:
            continue
        raw = str(cand)
        if raw.startswith("candidate:"):
            raw = raw[len("candidate:") :]
        try:
            ice = candidate_from_sdp(raw)
            ice.sdpMid = str(mid) if mid is not None else "0"
            if mline is not None:
                ice.sdpMLineIndex = int(mline)
            await pc.addIceCandidate(ice)
            added += 1
        except Exception as exc:  # noqa: BLE001
            log.warn(f"{label}: addIceCandidate failed: {exc}")
    for leg in (session.get("ringLegs") or {}).values():
        if getattr(leg, "pc", None) is pc:
            add_remote = getattr(leg, "add_remote_ice", None)
            if callable(add_remote):
                add_remote(candidates)
    return added


async def wait_callee_dc_open(session: dict[str, Any], timeout: float = 30.0) -> None:
    if session.get("calleeDcOpen"):
        return
    fut = session.get("calleeDcOpenFut")
    if fut is None:
        raise RuntimeError("callee DC open future missing")
    await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)


def send_callee_dc_json(session: dict[str, Any], message: dict[str, Any]) -> None:
    if session.get("mediaWorker"):
        from webrtc_pc_worker import send_dc_json as _send

        pc = session.get("pcCallee") or session.get("pc2")
        _send(session, message, leg=getattr(pc, "leg", "pc2"))
        return
    dc = session.get("calleeDataChannel")
    session_id = session.get("sessionId") or "?"
    state = str(getattr(dc, "readyState", "") or "").lower() if dc else ""
    if dc is None or state != "open":
        raise RuntimeError(f"[{session_id}] no open callee data channel")
    raw = json.dumps(message)
    action = message.get("action") or (message.get("payload") or {}).get("type") or "unknown"
    log.info(
        f"PC-callee: session={session_id} DC-OUT msgType={message.get('msgType')!r} "
        f"action={action!r}"
    )
    _dc_send_bytes(session, dc, raw)


def _allocate_leg_call_id(session: dict[str, Any], ident: str = "") -> int:
    """Per-seat RING callId. Parallel hunt must not share session activeCallId."""
    ident = str(ident or "")
    stamp = int(time.time() * 1000) % 1_000_000_000
    salt = (abs(hash(ident)) % 997) if ident else (os.getpid() % 1000)
    call_id = max(1, stamp + salt)
    if ident:
        session[f"ringCallId:{ident}"] = call_id
        session.setdefault(f"legCallId:{ident}", call_id)
    return call_id


def _leg_call_id(session: dict[str, Any], ident: str = "") -> int:
    ident = str(ident or "")
    if ident:
        existing = session.get(f"ringCallId:{ident}")
        if isinstance(existing, int) and existing > 0:
            return existing
    return _ensure_session_call_id(session)


def _allocate_call_id(session: dict[str, Any]) -> int:
    """Node WebRtcNegotiation._allocateCallId — client correlates RING ack/answer."""
    existing = session.get("activeCallId")
    if isinstance(existing, int) and existing > 0:
        return existing
    call_id = max(1, (int(time.time() * 1000) % 1_000_000_000) + (os.getpid() % 1000))
    session["activeCallId"] = call_id
    return call_id


# Android WebRtcClient.handleRemoteOffer: lower localId yields
# (localId.compareTo(remoteId) < 0). Higher identity keeps its offer.
_GLARE_COLLECT_SECS = 0.05
# One side notes its offer, then blocks in wait_until_callee_rungable (1s)
# before glare_keep. The other offer often lands ~1s later. Keep the parked
# offer fresh well past that wait or both sides keep.
_GLARE_FRESH_SECS = 8.5
# iOS loser answers the glare end-call offer; Android ignores it (no wait).
_GLARE_LOSER_ANSWER_SECS = 1.5


def note_glare_offer(
    session: dict[str, Any],
    sender: str,
    sdp: str,
    *,
    leg: str,
    call_id: Optional[int] = None,
) -> None:
    sender = str(sender or "").strip()
    if not sender:
        return
    offers = session.setdefault("glareOffers", {})
    if not isinstance(offers, dict):
        offers = {}
        session["glareOffers"] = offers
    offers[sender] = {
        "callEnd": bool(is_inactive_offer(sdp) or not _sdp_has_active_audio(sdp)),
        "leg": leg,
        "callId": call_id if isinstance(call_id, int) and call_id > 0 else None,
        "at": time.monotonic(),
    }


def _glare_fresh(session: dict[str, Any]) -> dict[str, Any]:
    offers = session.get("glareOffers") or {}
    if not isinstance(offers, dict) or not offers:
        return {}
    newest = max(float(info.get("at") or 0) for info in offers.values())
    return {
        sender: info
        for sender, info in offers.items()
        if newest - float(info.get("at") or 0) <= _GLARE_FRESH_SECS
    }


def clear_glare_offers(session: dict[str, Any]) -> None:
    """Drop parked offers once the call is up or the previous call ended.

    Otherwise a fast redial pairs with the last call's offer and hangs it up.
    """
    offers = session.get("glareOffers")
    if isinstance(offers, dict):
        offers.clear()


def note_call_connected(session: dict[str, Any]) -> None:
    """Bridge is up: drop parked glare offers and retire the pair's other attempt."""
    clear_glare_offers(session)
    try:
        from client_ingress import retire_glare_siblings

        retire_glare_siblings(session)
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"DIALOG-GLARE: retire siblings failed session={session.get('sessionId')}: {exc}"
        )


def glare_offer_winner(session: dict[str, Any]) -> str | None:
    """Higher identity keeps the offer. A real call beats a call-end offer."""
    fresh = _glare_fresh(session)
    if not fresh:
        return None
    real = [sender for sender, info in fresh.items() if not info.get("callEnd")]
    pool = real or list(fresh)
    return max(pool)


def _glare_both_live(session: dict[str, Any]) -> bool:
    return bool(session.get("dcOpen") and session.get("calleeDcOpen"))


async def glare_keep(session: dict[str, Any], sender: str) -> bool:
    """True when this sender's offer is the one to setRemote and connect."""
    sender = str(sender or "").strip()
    if not sender:
        return True
    await asyncio.sleep(0)
    if _glare_both_live(session) and len(_glare_fresh(session)) < 2:
        await asyncio.sleep(_GLARE_COLLECT_SECS)
    fresh = _glare_fresh(session)
    if len(fresh) < 2:
        return True
    winner = glare_offer_winner(session)
    session_id = session.get("sessionId")
    if winner == sender:
        log.info(
            f"GLARE: keep offer sender={sender} winner={winner} "
            f"session={session_id}"
        )
        return True
    log.info(
        f"GLARE: yield offer sender={sender} winner={winner} "
        f"session={session_id} (higher id keeps offer)"
    )
    return False


def glare_loser(session: dict[str, Any], winner: str) -> Optional[tuple[str, Optional[int]]]:
    """The other live offer in this glare, as (leg, callId)."""
    fresh = _glare_fresh(session)
    real = {
        sender: info
        for sender, info in fresh.items()
        if not info.get("callEnd")
    }
    if len(real) < 2:
        return None
    winner = str(winner or "").strip()
    for sender, info in real.items():
        if sender == winner:
            continue
        leg = str(info.get("leg") or "")
        if leg not in ("pc1", "callee"):
            continue
        call_id = info.get("callId")
        return leg, call_id if isinstance(call_id, int) and call_id > 0 else None
    return None


async def hangup_glare_loser(
    session: dict[str, Any], leg: str, call_id: Optional[int]
) -> None:
    """call/end, then inactive end-call. The new dial must not share this call."""
    if leg not in ("pc1", "callee"):
        return
    if isinstance(call_id, int) and call_id > 0:
        session["activeCallId"] = call_id
    send_leg_ui_hangup(session, leg=leg, reason="glare")
    offered = False
    try:
        offered = bool(await initiate_end_call_offer(session, leg=leg, reason="glare"))
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"GLARE: loser end-call failed session={session.get('sessionId')} "
            f"leg={leg}: {exc}"
        )
    if offered and call_id is None:
        # No callId on the losing RING = iOS (Android always sends one). iOS
        # rolls back and answers the inactive offer. Let that answer land
        # before our new offer, or it is applied as the answer to the new RING.
        deadline = time.monotonic() + _GLARE_LOSER_ANSWER_SECS
        while session.get(_leg_ending_key(leg)) and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        log.info(
            f"GLARE: loser end-call answer wait done leg={leg} "
            f"session={session.get('sessionId')} "
            f"answered={not session.get(_leg_ending_key(leg))}"
        )
    # Android drops this answer. Do not hold the redial for it.
    session[_leg_ending_key(leg)] = False
    session["endCallRenegotiating"] = False
    clear_glare_offers(session)
    log.info(
        f"GLARE: hung up loser leg={leg} session={session.get('sessionId')} "
        f"callId={call_id}"
    )


async def handle_callee_originated_ring(
    session: dict[str, Any], payload: dict[str, Any], offered_epoch: int = 0
) -> None:
    """Callee RING after hangup. WebRTC A-leg → PC1 DC RING. SIP A-leg → new SBC INVITE."""
    session_id = session.get("sessionId") or "?"
    offer = str(payload.get("sdp") or "")
    sender = str(session.get("to") or "")
    log.info(
        f"NOTIFY: DC RING from callee session={session_id} sdp_len={len(offer)}"
    )
    from client_ingress import callee_dialog_still_ours, prepare_callee_dialog

    if int(session.get("dialogEpoch") or 0) != int(offered_epoch):
        session["dcRingStarted"] = False
        log.info(f"DIALOG-GLARE: callee RING dropped before start session={session_id}")
        return
    if not await prepare_callee_dialog(session):
        session["dcRingStarted"] = False
        return
    epoch = session.get("dialogEpoch")
    # This offer is the callee abandoning our unanswered end-call. iOS answers
    # the other leg's end-call in a few hundred ms; Android never does. Wait
    # the 1s cap so an iOS answer is not applied to this RING, then dial.
    # A missing answer does not cancel the redial.
    if session.get("endingAwaitAnswerCallee"):
        session["endingAwaitAnswerCallee"] = False
        log.info(
            f"PC-callee: new RING replaces unanswered end-call session={session_id}"
        )
    try:
        await wait_until_callee_rungable(session, 1.0)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY: callee RING ENDING wait failed session={session_id}: {exc}")
    if _callee_ending(session):
        log.info(
            f"PC-callee: callback RING dials, end-call unanswered "
            f"session={session_id}"
        )
    if not callee_dialog_still_ours(session, epoch):
        session["dcRingStarted"] = False
        log.info(f"DIALOG-GLARE: callee RING dropped session={session_id}")
        return
    if not await glare_keep(session, sender):
        session["dcRingStarted"] = False
        return
    loser = glare_loser(session, sender)
    if loser is not None:
        await hangup_glare_loser(session, loser[0], loser[1])
    session["softEnded"] = False
    session["clientEnded"] = False
    session["softEndInProgress"] = False
    session["failureNotified"] = False
    session["failureCleanupDone"] = False
    session["endCallSent"] = False
    session["endingAwaitAnswerPc1"] = False
    session["endingAwaitAnswerCallee"] = False
    session["endCallRenegotiating"] = False
    session["localAudioTrack"] = None
    session["pc2LocalTrack"] = None
    ring_token = int(session.get("callbackRingToken") or 0)
    try:
        await answer_callee_ring_offer(session, payload)
        if not callee_dialog_still_ours(session, epoch):
            session["pendingCalleeAnswerSdp"] = None
            session["dcRingStarted"] = False
            log.info(f"DIALOG-GLARE: callee RING dropped session={session_id}")
            return
        from client_ingress import _ring_timeout_secs

        session["ringStartedAt"] = time.monotonic()
        ring_timeout = _ring_timeout_secs(session)
        log.info(
            f"NOTIFY: callback RING wait session={session_id} timeout={ring_timeout:.0f}s"
        )
        if _a_leg_is_sip(session):
            from client_ingress import dial_sbc_for_callee_callback

            await dial_sbc_for_callee_callback(
                session, offer, timeout_s=ring_timeout
            )
        else:
            await pc1_audio_ring_and_answer(session, timeout=ring_timeout)
        if not callee_dialog_still_ours(session, epoch):
            session["pendingCalleeAnswerSdp"] = None
            session["dcRingStarted"] = False
            log.info(f"DIALOG-GLARE: callee RING dropped session={session_id}")
            return
        if int(session.get("callbackRingToken") or 0) != ring_token:
            session["pendingCalleeAnswerSdp"] = None
            session["dcRingStarted"] = False
            log.info(
                f"NOTIFY: drop held callee answer, newer ring session={session_id}"
            )
            return
        flush_held_callee_ring_answer(session)
        try:
            await asyncio.sleep(0.15)
            await _bridge_media(session)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY: callee RING rebridge failed session={session_id}: {exc}")
        log.info(f"NOTIFY: callee-originated RING complete session={session_id}")
    except Exception as exc:  # noqa: BLE001
        session["dcRingStarted"] = False
        session["pendingCalleeAnswerSdp"] = None
        session["pendingCalleeAnswerIce"] = None
        if not callee_dialog_still_ours(session, epoch):
            log.info(f"DIALOG-GLARE: callee RING lost session={session_id}: {exc}")
            return
        if int(session.get("callbackRingToken") or 0) != ring_token:
            log.info(
                f"NOTIFY: callback RING timeout dropped, newer ring session={session_id}"
            )
            return
        timed_out = isinstance(exc, TimeoutError) or "timeout" in str(exc).lower()
        if timed_out:
            fut = session.get("pc1RingAnswerFut")
            if fut is not None and not fut.done():
                fut.cancel()
            log.info(
                f"NOTIFY: callback RING timeout session={session_id} "
                f"error={exc}"
            )
            from client_ingress import _cancel_pending_sbc, _soft_end_call

            try:
                await _cancel_pending_sbc(session)
            except Exception as cancel_exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY: callback RING timeout cancel SBC failed "
                    f"session={session_id}: {cancel_exc}"
                )
            try:
                await _soft_end_call(
                    session,
                    "ring-timeout",
                    client_ended=False,
                    ended_leg="callee",
                    send_ui_end=True,
                    offer_legs=("pc1", "callee"),
                )
            except Exception as end_exc:  # noqa: BLE001
                log.warn(
                    f"NOTIFY: callback RING timeout soft-end failed "
                    f"session={session_id}: {end_exc}"
                )
            return
        log.warn(f"NOTIFY: callee-originated RING failed session={session_id}: {exc}")
        raise


def _a_leg_is_sip(session: dict[str, Any]) -> bool:
    """PSTN/SIP A-leg has no DC. After inbound BYE, pc1 is deliberately gone."""
    if str(session.get("routeKind") or "") == "inbound":
        return True
    if not isinstance(session.get("inboundCall"), dict):
        return False
    if session.get("pc") is None:
        return True
    return not _dc_is_open(session)


async def answer_callee_ring_offer(
    session: dict[str, Any], payload: dict[str, Any]
) -> None:
    """Node applyOffer on callee PC: ACK ring, hold answer until PC1 picks up."""
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import answer_callee_ring_offer as _a

        await _a(session, payload)
        return
    _require_aiortc()
    pc = session.get("pcCallee") or session.get("pc2")
    if pc is None:
        raise RuntimeError("PC-callee missing for RING offer")
    session_id = session.get("sessionId") or "?"
    raw_offer = str(payload.get("sdp") or "")
    try:
        from client_ingress import _narrow_telephony_audio_sdp

        offer_sdp = _narrow_telephony_audio_sdp(raw_offer)
    except Exception:  # noqa: BLE001
        offer_sdp = raw_offer
    call_id = _normalize_call_id(payload.get("callId")) or _call_id_for_leg(
        session, "callee"
    )
    if call_id is None:
        call_id = _allocate_leg_call_id(session, str(session.get("to") or ""))
    send_callee_dc_json(
        session,
        {
            "msgType": "call",
            "action": "ack",
            "ackFor": "ring",
            "callId": call_id,
        },
    )
    _bind_remote_audio_track(session, pc, remote_key="pc2RemoteTrack", label="PC-callee")
    await pc.setRemoteDescription(RTCSessionDescription(sdp=offer_sdp, type="offer"))
    await add_ice_candidates_to_pc(
        session, pc, payload.get("candidates") or [], label="PC-callee"
    )
    await _ensure_local_audio_on_pc(session, pc, key="pc2LocalTrack")
    _prefer_g711_codecs(pc, label="PC-callee")
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await _wait_ice_gathering(pc)
    local = pc.localDescription
    answer_sdp = local.sdp if local else (answer.sdp if answer else "")
    try:
        from client_ingress import ensure_telephone_event_sdp

        answer_sdp = ensure_telephone_event_sdp(answer_sdp, offer_sdp)
    except Exception:  # noqa: BLE001
        pass
    ice = prefer_srflx_and_relay(candidates_from_sdp(answer_sdp))
    answer_sdp = embed_candidates_in_sdp(answer_sdp, ice)
    session["pendingCalleeAnswerSdp"] = answer_sdp
    session["pendingCalleeAnswerIce"] = ice
    log.info(
        f"PC-callee: held RING answer session={session_id} bytes={len(answer_sdp)} "
        f"(flush after PC1 pickup — Node applyOffer hold)"
    )


def flush_held_callee_ring_answer(session: dict[str, Any]) -> None:
    """Node answer() on callee PC: flush held SDP after the other leg is IN_CALL."""
    answer_sdp = str(session.get("pendingCalleeAnswerSdp") or "")
    if not answer_sdp.strip():
        raise RuntimeError("no held callee RING answer to flush")
    call_id = session.get("activeCallId")
    ice = session.get("pendingCalleeAnswerIce") or prefer_srflx_and_relay(
        candidates_from_sdp(answer_sdp)
    )
    send_callee_dc_json(
        session,
        {
            "msgType": "signaling",
            "callId": call_id,
            "payload": {
                "type": "answer",
                "from": session.get("from"),
                "to": session.get("to"),
                "sessionId": session.get("sessionId"),
                "sdp": answer_sdp,
                "candidates": ice,
                "callId": call_id,
                "isCall": True,
            },
        },
    )
    send_callee_dc_json(
        session,
        {
            "msgType": "call",
            "action": "ack",
            "ackFor": "answer",
            "callId": call_id,
        },
    )
    session["pendingCalleeAnswerSdp"] = None
    session["pendingCalleeAnswerIce"] = None
    session["calleeRingAnswered"] = True
    session["pc2OfferReady"] = True
    log.info(
        f"PC-callee: flushed RING answer session={session.get('sessionId')} "
        f"bytes={len(answer_sdp)}"
    )


async def pc1_audio_ring_and_answer(
    session: dict[str, Any], *, timeout: float = 60.0
) -> None:
    """RING the original caller (PC1) after callee originated audio RING."""
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import pc1_audio_ring_and_answer as _r

        await _r(session, timeout=timeout)
        return
    _require_aiortc()
    await wait_until_callee_rungable(session, min(1.0, timeout))
    if _callee_ending(session):
        raise RuntimeError("PC1 RING answer timeout")
    pc = session.get("pc")
    if pc is None:
        raise RuntimeError("PC1 missing for callback RING")
    session_id = session.get("sessionId") or "?"
    loop = asyncio.get_running_loop()
    session["pc1RingAnswerFut"] = loop.create_future()
    session["pc1Connected"] = False
    _bind_remote_audio_track(session, pc, remote_key="pc1RemoteTrack", label="PC1")
    await _ensure_local_audio_on_pc(session, pc, key="localAudioTrack")
    _prefer_g711_codecs(pc, label="PC1")
    offer = await pc.createOffer()
    raw_sdp = (offer.sdp if offer else "") or ""
    try:
        from client_ingress import _narrow_telephony_audio_sdp

        narrowed = _narrow_telephony_audio_sdp(raw_sdp)
        if narrowed != raw_sdp:
            offer = RTCSessionDescription(sdp=narrowed, type="offer")
    except Exception:  # noqa: BLE001
        pass
    await pc.setLocalDescription(offer)
    await _wait_ice_gathering(pc)
    local = pc.localDescription
    sdp = local.sdp if local else (getattr(offer, "sdp", None) or raw_sdp)
    ice = prefer_srflx_and_relay(candidates_from_sdp(sdp))
    sdp = embed_candidates_in_sdp(sdp, ice)
    call_id = _call_id_for_leg(session, "pc1")
    if call_id is None:
        # This offer is what the caller adopts. It must not be a callee RING id.
        call_id = _allocate_leg_call_id(session, "pc1")
        session["legCallId:pc1"] = call_id
    from_label = str(session.get("to") or "")
    send_dc_json(
        session,
        {
            "msgType": "signaling",
            "callId": call_id,
            "payload": {
                "type": "offer",
                "from": from_label,
                "to": session.get("from"),
                "sessionId": session.get("sessionId"),
                "sdp": sdp,
                "candidates": ice,
                "callId": call_id,
                "label": from_label,
                "isCall": True,
            },
        },
    )
    log.info(f"PC1: callback RING offer sent session={session_id} bytes={len(sdp)}")
    _note_dc_ring_sent(
        session,
        str(session.get("from") or ""),
        sdp,
        ice,
        invert_caller=True,
    )
    try:
        answer_sdp = await asyncio.wait_for(
            asyncio.shield(session["pc1RingAnswerFut"]), timeout=timeout
        )
    except asyncio.TimeoutError as exc:
        raise RuntimeError("PC1 RING answer timeout") from exc
    if not answer_sdp:
        raise RuntimeError("PC1 RING answer empty")
    await pc.setRemoteDescription(
        RTCSessionDescription(sdp=str(answer_sdp), type="answer")
    )
    log.info(f"PC1: callback RING answer applied session={session_id} bytes={len(answer_sdp)}")
    connected = await _wait_pc_connected(pc, label="PC1", timeout_s=8.0)
    session["pc1Connected"] = bool(connected)


async def callee_audio_ring_and_answer(
    session: dict[str, Any],
    *,
    timeout: float = 60.0,
) -> None:
    """After callee DC is up: add audio, RING over DC, apply answer (Node poly ring)."""
    _require_aiortc()
    pc = session.get("pcCallee")
    if pc is None:
        raise RuntimeError("PC-callee missing for audio RING")
    session_id = session.get("sessionId") or "?"
    loop = asyncio.get_running_loop()
    session["calleeRingAnswerFut"] = loop.create_future()
    pending = ""
    for leg in (session.get("ringLegs") or {}).values():
        pending = str(getattr(leg, "pending_pickup_sdp", None) or "")
        if pending:
            try:
                leg.pending_pickup_sdp = None
            except Exception:  # noqa: BLE001
                pass
            break
    if pending:
        session["calleeRingAnswerFut"].set_result(pending)
    # Renegotiation briefly drops connectionState — clear latch so wait below is real.
    session["pc2Connected"] = False
    # Inbound: hold MediaRelay until SIP 200 (see _bridge_media gate).
    if session.get("routeKind") == "inbound":
        session["inboundSipAnswered"] = False

    _bind_remote_audio_track(session, pc, remote_key="pc2RemoteTrack", label="PC-callee")
    remint = False
    # Keep call-1 SSRC/msid. Remint+replaceTrack is a new MediaStream; iOS reuse
    # keeps the first-call transceiver and drops the new SSRC (silent 2nd call).
    await _ensure_local_audio_on_pc(session, pc, key="pc2LocalTrack", remint=False)
    _prefer_g711_codecs(pc, label="PC-callee")

    prev_sdp = str(getattr(pc.localDescription, "sdp", "") or "")
    prev_ufrag, prev_pwd = _sdp_ice_ufrag_pwd(prev_sdp)
    prev_ice = prefer_srflx_and_relay(candidates_from_sdp(prev_sdp))
    offer = await pc.createOffer()
    raw_sdp = (offer.sdp if offer else "") or ""
    try:
        from client_ingress import _narrow_telephony_audio_sdp

        narrowed = _narrow_telephony_audio_sdp(raw_sdp)
        if narrowed != raw_sdp:
            raw_sdp = narrowed
            log.info(
                f"PC-callee: narrowed RING offer to G711 "
                f"{len(offer.sdp or '')}→{len(raw_sdp)} bytes"
            )
    except Exception:  # noqa: BLE001
        pass
    if prev_ufrag and prev_pwd:
        raw_sdp = _set_sdp_ice_ufrag_pwd(raw_sdp, prev_ufrag, prev_pwd)
    raw_sdp = force_bundle_ports(ensure_bundle_all_mids(raw_sdp))
    if remint:
        raw_sdp = apply_stored_audio_identity(session, raw_sdp, "pc2LocalTrack")
    try:
        await pc.setLocalDescription(RTCSessionDescription(sdp=raw_sdp, type="offer"))
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PC-callee: RING setLocal reused-ICE failed: {exc}")
        await pc.setLocalDescription(offer)
        await _wait_ice_gathering(pc)
    if str(getattr(pc, "iceGatheringState", "") or "") != "complete":
        await _wait_ice_gathering(pc)
    local = pc.localDescription
    sdp = local.sdp if local else raw_sdp
    sdp = force_bundle_ports(ensure_bundle_all_mids(sdp))
    if prev_ufrag and prev_pwd:
        sdp = _set_sdp_ice_ufrag_pwd(sdp, prev_ufrag, prev_pwd)
    ice = prev_ice or prefer_srflx_and_relay(candidates_from_sdp(sdp))
    sdp = embed_candidates_in_sdp(sdp, ice)
    if remint:
        sdp = apply_stored_audio_identity(session, sdp, "pc2LocalTrack")
    log.info(f"PC-callee: RING offer SDP {sdp_media_summary(sdp)} remint={remint}")
    call_id = _allocate_leg_call_id(session, str(session.get("to") or ""))
    from_label = str(session.get("from") or "")
    # identity_label without importing client identity cycle — bare digits/label only
    if "." in from_label:
        from_label = from_label.split(".", 1)[0]
    if "@" in from_label:
        from_label = from_label.split("@", 1)[0]

    send_callee_dc_json(
        session,
        {
            "msgType": "signaling",
            "callId": call_id,
            "payload": {
                "type": "offer",
                "from": from_label,
                "to": session.get("to"),
                "sessionId": session.get("sessionId"),
                "sdp": sdp,
                "candidates": ice,
                "callId": call_id,
                "label": from_label,
                "isCall": True,
            },
        },
    )
    log.info(
        f"PC-callee: RING offer sent session={session_id} callId={call_id} bytes={len(sdp)}"
    )
    _note_dc_ring_sent(
        session,
        str(session.get("to") or ""),
        sdp,
        ice,
    )
    try:
        answer_sdp = await asyncio.wait_for(
            asyncio.shield(session["calleeRingAnswerFut"]), timeout=timeout
        )
    except asyncio.CancelledError:
        raise RuntimeError("callee RING answer cancelled (teardown)") from None
    except asyncio.TimeoutError as exc:
        raise RuntimeError("callee RING answer timeout") from exc
    if not answer_sdp:
        raise RuntimeError("callee RING answer empty")
    cands: list[Any] = []
    for leg in (session.get("ringLegs") or {}).values():
        extra = getattr(leg, "pickup_candidates", None)
        if extra:
            cands = extra
            break
    await apply_callee_ring_answer(
        session, pc, str(answer_sdp), cands, label="PC-callee"
    )
    session["calleeRingAnswered"] = True
    remote = _live_remote_audio(pc)
    if remote is not None:
        session["pc2RemoteTrack"] = remote
    log.info(
        f"PC-callee: RING answer applied session={session_id} bytes={len(answer_sdp)}"
    )
    session["pc2OfferReady"] = True
    connected = await _wait_pc_connected(pc, label="PC-callee", timeout_s=8.0)
    session["pc2Connected"] = bool(connected)
    await _bridge_media(session)
    log.info(
        f"PC-callee: post-RING bridge "
        f"connected={session.get('pc2Connected')} "
        f"bridged={session.get('mediaBridged')} "
        f"c2s={session.get('bridgedClientToSbc')} "
        f"s2c={session.get('bridgedSbcToClient')}"
    )


async def accept_sbc_rtpengine_offer(session: dict[str, Any], offer_sdp: str) -> str:
    """PC1 answers rtpengine sbc_to_webrtc offer (SBC→WebRTC inbound media leg).

    Phone leg is PC-callee (pc2). This PC is audio-only toward rtpengine — same
    role as create_pc2_offer but as answerer. Does NOT bridge — caller arms
    inboundSipAnswered then rebridge_media after SIP 200 + DTLS.
    """
    if use_media_worker():
        from webrtc_pc_worker import accept_sbc_rtpengine_offer as _a

        return await _a(session, offer_sdp)
    _require_aiortc()
    session_id = session.get("sessionId") or "?"
    prev = session.pop("pc", None)
    if prev is not None:
        try:
            await prev.close()
        except Exception:  # noqa: BLE001
            pass

    # Same host as rtpengine (network_mode=host) — STUN/TURN adds bad paths.
    pc = RTCPeerConnection(configuration=RTCConfiguration(iceServers=[]))
    session["pc"] = pc
    session["inboundSipAnswered"] = False
    session["bridgedClientToSbc"] = False
    session["bridgedSbcToClient"] = False
    session["mediaBridged"] = False
    session.pop("pc1RemoteTrack", None)
    session.pop("pc1RemoteTrackBound", None)
    # Drop any prior MediaRelay consumers — flag reset alone double-subscribes.
    session.pop("mediaRelay", None)

    _bind_pc_events(session, pc)
    _bind_remote_audio_track(session, pc, remote_key="pc1RemoteTrack", label="PC1")
    await _ensure_local_audio_on_pc(session, pc, key="localAudioTrack")
    # Prefer G711 via transceiver prefs only — do NOT rewrite the rtpengine
    # offer SDP. Old sip.js answered the Kamailio/rtpengine INVITE body
    # verbatim; mutating m-line/rtcp-mux before setRemote made our answer
    # disagree with rtpengine's offer → PC1.in=0 one-way.
    _prefer_g711_codecs(pc, label="PC1")

    raw = str(offer_sdp or "")
    log.info(
        f"PC1: inbound setRemote begin session={session_id} offer_bytes={len(raw)} "
        f"(verbatim rtpengine offer — no narrow/mux patch)"
    )
    await pc.setRemoteDescription(RTCSessionDescription(sdp=raw, type="offer"))
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await _wait_ice_gathering(pc)
    local = pc.localDescription
    answer_sdp = local.sdp if local else (answer.sdp if answer else "")
    log.info(
        f"PC1: inbound createAnswer done session={session_id} "
        f"answer_bytes={len(answer_sdp)} gather={pc.iceGatheringState}"
    )
    return answer_sdp


async def wait_pc1_connected(session: dict[str, Any], *, timeout_s: float = 8.0) -> bool:
    if session.get("mediaWorker"):
        from webrtc_pc_worker import wait_pc1_connected as _w

        return await _w(session, timeout_s=timeout_s)
    pc = session.get("pc")
    ok = await _wait_pc_connected(pc, label="PC1", timeout_s=timeout_s)
    return bool(ok)


async def create_pc1_offer(session: dict[str, Any]) -> str:
    from webrtc_pc_worker import create_pc1_offer as _c

    return await _c(session)


async def apply_pc1_remote_answer(session: dict[str, Any], answer_sdp: str) -> None:
    from webrtc_pc_worker import apply_pc1_remote_answer as _a

    await _a(session, answer_sdp)


async def create_pc2_offer(session: dict[str, Any]) -> str:
    """Node PC2/sip.js: audio-only PeerConnection offer toward rtpengine/SBC."""
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import create_pc2_offer as _c

        return await _c(session)
    _require_aiortc()
    session_id = session.get("sessionId") or "?"
    prev = session.pop("pc2", None)
    # Never close PC-callee when it was aliased as pc2 (WebRTC↔WebRTC bridge).
    # `None is None` used to hit the intact branch on the first outbound dial.
    pc_callee = session.get("pcCallee")
    if prev is not None and prev is pc_callee:
        log.info(
            f"PC2: createOffer leaving pcCallee intact session={session_id}"
        )
    elif prev is not None:
        try:
            await prev.close()
        except Exception:  # noqa: BLE001
            pass

    # PC2↔rtpengine is on-host (network_mode=host). STUN/TURN just adds bad paths.
    pc2 = RTCPeerConnection(configuration=RTCConfiguration(iceServers=[]))
    session["pc2"] = pc2
    session["pc2OfferReady"] = False
    session["bridgedClientToSbc"] = False
    session["bridgedSbcToClient"] = False
    session["mediaBridged"] = False
    session.pop("pc2RemoteTrack", None)
    session.pop("pc2RemoteTrackBound", None)
    # Fresh PC2 needs a fresh blank track (soft end / prior bridge may have nulled).
    # Also drop the tap slot — otherwise _ensure_local_audio finds pc2SendTap,
    # remint=False, no transceiver, and skips addTrack.
    session["pc2LocalTrack"] = None
    session.pop("pc2SendTap", None)

    _bind_pc2_state_logs(session, pc2)
    _bind_remote_audio_track(session, pc2, remote_key="pc2RemoteTrack", label="PC2")
    await _ensure_local_audio_on_pc(session, pc2, key="pc2LocalTrack")
    _prefer_g711_codecs(pc2, label="PC2")

    offer = await pc2.createOffer()
    await pc2.setLocalDescription(offer)
    await _wait_ice_gathering(pc2)
    local = pc2.localDescription
    sdp = local.sdp if local else (offer.sdp if offer else "")
    session["pc2OfferReady"] = True
    session["pc2Connected"] = False
    log.info(f"PC2: createOffer done session={session_id} offer_bytes={len(sdp)}")
    # Do NOT bridge yet — wait for DTLS (apply_pc2_remote_answer).
    return sdp


async def apply_pc2_remote_answer(session: dict[str, Any], answer_sdp: str) -> None:
    """Apply NG/SBC WebRTC answer onto PC2, wait DTLS, then bridge."""
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import apply_pc2_remote_answer as _a

        await _a(session, answer_sdp)
        return
    _require_aiortc()
    pc2 = session.get("pc2")
    if pc2 is None:
        raise RuntimeError("PC2 missing for remote answer")
    # aiortc is happier with explicit end-of-candidates on non-trickle answers.
    ans = str(answer_sdp or "")
    # Defense in depth if caller skipped localize_pc2_answer_sdp.
    try:
        from client_ingress import ensure_pc2_answer_rtcp_mux

        ans = ensure_pc2_answer_rtcp_mux(ans)
    except Exception:  # noqa: BLE001
        if ans.strip() and "a=rtcp-mux" not in ans:
            ending = "\r\n" if "\r\n" in ans else "\n"
            if re.search(r"^a=rtcp:", ans.replace("\r\n", "\n"), re.M):
                ans = re.sub(
                    r"(a=rtcp:[^\r\n]*)",
                    r"\1" + ending + "a=rtcp-mux",
                    ans,
                    count=1,
                )
            else:
                ans = ans.rstrip() + ending + "a=rtcp-mux" + ending
    if ans.strip() and "a=end-of-candidates" not in ans:
        ending = "\r\n" if "\r\n" in ans else "\n"
        ans = ans.rstrip() + ending + "a=end-of-candidates" + ending
    setup_m = re.search(r"^a=setup:(\S+)", ans.replace("\r\n", "\n"), re.M)
    setup = setup_m.group(1) if setup_m else "?"
    log.info(
        f"PC2: applying answer session={session.get('sessionId')} "
        f"setup={setup!r} bytes={len(ans)}"
    )
    await pc2.setRemoteDescription(
        RTCSessionDescription(sdp=ans, type="answer")
    )
    log.info(
        f"PC2: setRemote answer session={session.get('sessionId')} "
        f"bytes={len(ans)}"
    )
    # DTLS transport diagnostics (connectionState=failed with ice=completed).
    try:
        for i, tr in enumerate(pc2.getTransceivers() or []):
            receiver = getattr(tr, "receiver", None)
            transport = getattr(receiver, "transport", None) if receiver else None
            dtls = getattr(transport, "transport", None) or transport
            state = getattr(dtls, "state", None) if dtls is not None else None
            if state is not None:
                log.info(f"PC2: dtls[{i}] state={state}")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PC2: dtls state probe failed: {exc}")
    ok = await _wait_pc_connected(pc2, label="PC2", timeout_s=8.0)
    session["pc2Connected"] = bool(ok)
    if not ok:
        log.warn(
            f"PC2: not connected after NG answer session={session.get('sessionId')} "
            "— media likely silent"
        )
        return
    # Do NOT bridge here — client RTP starts only after held PC1 answer flush.
    # Bridging then force-rebridging on flush killed MediaRelay (PC2:out≈1).


async def apply_remote_offer_local_answer(
    session: dict[str, Any],
    offer_sdp: str,
    answer_sdp: str,
) -> None:
    """Legacy helper — prefer prepare_ring_answer + flush_held_ring_answer."""
    _require_aiortc()
    pc = session.get("pc")
    if pc is None:
        return
    try:
        await pc.setRemoteDescription(RTCSessionDescription(sdp=str(offer_sdp), type="offer"))
        await pc.setLocalDescription(RTCSessionDescription(sdp=str(answer_sdp), type="answer"))
        log.info(f"PC1: applied audio renegotiation session={session.get('sessionId')}")
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC1: could not apply renegotiation on PC1 (DC answer still sent): {exc}"
        )


async def close_pcs(
    session: Optional[dict[str, Any]],
    *,
    pc1: bool = True,
    callee: bool = True,
) -> None:
    """Close selected PeerConnections. handshake replaces PC1 only (keep callee DC)."""
    if not session:
        return
    if callee:
        for fut_key in ("calleeRingAnswerFut", "calleeDcOpenFut"):
            fut = session.get(fut_key)
            if fut is not None and not fut.done():
                try:
                    fut.cancel()
                except Exception:  # noqa: BLE001
                    pass
            session[fut_key] = None
        for leg in list((session.get("ringLegs") or {}).values()):
            try:
                if not getattr(leg, "promoted", False):
                    await leg.close()
            except Exception:  # noqa: BLE001
                pass
        session["ringLegs"] = {}
        pc_callee = session.pop("pcCallee", None)
        pc2 = session.pop("pc2", None)
        closed_ids: set[int] = set()
        for label, peer in (("PC-callee", pc_callee), ("PC2", pc2)):
            if peer is None or id(peer) in closed_ids:
                continue
            closed_ids.add(id(peer))
            try:
                await peer.close()
                log.info(f"{label}: closed session={session.get('sessionId')}")
            except Exception as exc:  # noqa: BLE001
                log.warn(f"{label}: close failed: {exc}")
        session["calleeDataChannel"] = None
        session["calleeDcOpen"] = False
        session["pc2LocalTrack"] = None
    if not pc1:
        return
    session["pendingAnswerSdp"] = None
    session["localAudioTrack"] = None
    pc = session.pop("pc", None)
    session["dataChannel"] = None
    session["dcOpen"] = False
    if pc is None:
        return
    try:
        await pc.close()
        log.info(f"PC1: closed session={session.get('sessionId')}")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PC1: close failed: {exc}")


async def close_inbound_sip_pc(session: Optional[dict[str, Any]]) -> None:
    """Inbound hangup: drop rtpengine pc1 sockets. Do not touch the phone DC."""
    if not session:
        return
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import close_inbound_sip_pc as _w

        await _w(session)
        return
    await close_pcs(session, pc1=True, callee=False)


async def abandon(session: Optional[dict[str, Any]]) -> None:
    """Replace path: drop the old call without close() under the new handshake."""
    if not session:
        return
    finalize_recording(session)
    pickup = session.get("pickupEvent")
    if pickup is not None:
        try:
            pickup.set()
        except Exception:  # noqa: BLE001
            pass
    event = session.get("answerEvent")
    if event is not None:
        try:
            event.set()
        except Exception:  # noqa: BLE001
            pass
    session["on_dc_ring"] = None
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import abandon as _wabandon

        await _wabandon(session)
        return
    await close_pcs(session, pc1=True, callee=True)


async def close(session: Optional[dict[str, Any]]) -> None:
    if not session:
        return
    finalize_recording(session)
    pickup = session.get("pickupEvent")
    if pickup is not None:
        try:
            pickup.set()
        except Exception:  # noqa: BLE001
            pass
    event = session.get("answerEvent")
    if event is not None:
        try:
            event.set()
        except Exception:  # noqa: BLE001
            pass
    session["on_dc_ring"] = None
    if session.get("mediaWorker") or use_media_worker():
        from webrtc_pc_worker import close as _wclose

        await _wclose(session)
        return
    await close_pcs(session, pc1=True, callee=True)
