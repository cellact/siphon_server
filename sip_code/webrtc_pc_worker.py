"""Peer orchestrator. The WebRTC agent is siphon.peer, not a side process."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import struct
import threading
import time
from typing import Any, Optional

from siphon import log

import media_worker
import webrtc_pc as wpc

_session_legs: dict[str, dict[str, Any]] = {}
_local_sdp: dict[tuple[str, str], str] = {}


_poller_started = False


def _native_peer():
    try:
        from siphon import peer

        if peer.available():
            return peer
    except Exception:  # noqa: BLE001
        return None
    return None


_KNOWN_RTPMAP = {
    "0": "PCMU/8000",
    "8": "PCMA/8000",
    "9": "G722/8000",
    "13": "CN/8000",
    "101": "telephone-event/8000",
    "110": "telephone-event/48000",
    "111": "opus/48000/2",
    "126": "telephone-event/8000",
}


def _repair_missing_rtpmap(sdp: str) -> str:
    """str0m rejects an m-line PT that has no a=rtpmap. Android's RING
    answer lists 111 and omits the map. Insert the known one."""
    text = str(sdp or "")
    if "m=audio" not in text:
        return text
    ending = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(ending)
    have: set[str] = set()
    for line in lines:
        if line.startswith("a=rtpmap:"):
            have.add(line[len("a=rtpmap:") :].split()[0].split("/")[0])
    # str0m accepts c=/b= only while they are the first lines under m=.
    # Inserting a=rtpmap above c= makes it stop the section and report
    # "Media is missing a=mid" even though a=mid is further down.
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        out.append(line)
        index += 1
        if not line.startswith("m=audio "):
            continue
        while index < len(lines) and (
            lines[index].startswith("c=") or lines[index].startswith("b=")
        ):
            out.append(lines[index])
            index += 1
        for pt in line.split()[3:]:
            if pt in have or pt not in _KNOWN_RTPMAP:
                continue
            out.append(f"a=rtpmap:{pt} {_KNOWN_RTPMAP[pt]}")
            have.add(pt)
            if pt == "111":
                out.append("a=fmtp:111 minptime=10;useinbandfec=1")
            elif _KNOWN_RTPMAP[pt].startswith("telephone-event"):
                out.append(f"a=fmtp:{pt} 0-16")
    joined = ending.join(out)
    if text.endswith("\r\n") and not joined.endswith("\r\n"):
        joined += "\r\n"
    elif text.endswith("\n") and not joined.endswith("\n"):
        joined += "\n"
    return joined


def _order_sdp_for_str0m(sdp: str) -> str:
    """Put c= and b= directly under each m=.

    str0m's media parser takes one optional c= and one optional b=, then
    only a= lines. A later c= ends the section, so a=mid below it is ignored.
    """
    text = str(sdp or "")
    if "m=" not in text:
        return text
    ending = "\r\n" if "\r\n" in text else "\n"
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    parts = re.split(r"(?=^m=)", normalized, flags=re.M)
    out: list[str] = []
    for part in parts:
        keep_nl = part.endswith("\n")
        lines = part.split("\n")
        if keep_nl and lines and lines[-1] == "":
            lines = lines[:-1]
        if not lines or not lines[0].startswith("m="):
            out.append(part)
            continue
        connection = ""
        bandwidth = ""
        rest: list[str] = []
        for line in lines[1:]:
            if line == "":
                continue
            if not connection and line.startswith("c="):
                connection = line
                continue
            if not bandwidth and line.startswith("b=") and ":" in line:
                bandwidth = line
                continue
            rest.append(line)
        ordered = [lines[0]]
        if connection:
            ordered.append(connection)
        if bandwidth:
            ordered.append(bandwidth)
        ordered.extend(rest)
        chunk = "\n".join(ordered)
        if keep_nl:
            chunk += "\n"
        out.append(chunk)
    joined = "".join(out)
    if ending == "\r\n":
        joined = joined.replace("\n", "\r\n")
    return joined


def _cand_lines(candidates: list[Any]) -> list[str]:
    lines: list[str] = []
    for item in candidates or []:
        if isinstance(item, str):
            lines.append(item)
        elif isinstance(item, dict):
            lines.append(str(item.get("candidate") or ""))
    return [line for line in lines if line.strip()]


def _cand_dicts(candidates: list[Any]) -> list[dict[str, Any]]:
    """siphon.peer returns SDP lines. candidates_for_client wants dicts.

    Do not invent sdpMid "0". str0m mints the offer mid (`sfQ`). Android
    strips a=candidate from the SDP and addIceCandidate drops a mid that
    does not match, so the phone never STUNs us and the DC never opens.
    """
    out: list[dict[str, Any]] = []
    for item in candidates or []:
        if isinstance(item, dict):
            out.append(item)
            continue
        raw = str(item or "").strip()
        if raw.startswith("a="):
            raw = raw[2:].strip()
        if not raw or raw.lower() == "end-of-candidates":
            continue
        out.append({"sdpMLineIndex": 0, "candidate": raw})
    return out


def _with_sdp_mids(sdp: str, raw: Any) -> list[dict[str, Any]]:
    """Prefer mids parsed off the SDP. Stamp that mid onto later trickle lines."""
    parsed = wpc.candidates_from_sdp(str(sdp or ""))
    extra = _cand_dicts(raw if isinstance(raw, list) else [])
    if not parsed:
        return extra
    mid = str(parsed[0].get("sdpMid") or "")
    index = parsed[0].get("sdpMLineIndex") if parsed[0].get("sdpMLineIndex") is not None else 0
    seen = {
        str(c.get("candidate") or "").split(" ufrag ", 1)[0].strip()
        for c in parsed
    }
    out = list(parsed)
    for cand in extra:
        key = str(cand.get("candidate") or "").split(" ufrag ", 1)[0].strip()
        if not key or key in seen:
            continue
        stamped = dict(cand)
        if mid:
            stamped["sdpMid"] = mid
            stamped["sdpMLineIndex"] = index
        out.append(stamped)
        seen.add(key)
    return out


async def _peer_json(awaitable: Any) -> dict[str, Any]:
    raw = await awaitable
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}


async def peer_call(method: str, params: Optional[dict[str, Any]] = None, timeout: Any = None) -> dict[str, Any]:
    """WorkerPc's old JSON-RPC names, on siphon.peer."""
    params = params or {}
    peer = _native_peer()
    if peer is None:
        raise RuntimeError(
            "siphon.peer is not available. Build siphon-edge; there is no aiortc fallback."
        )
    sid = str(params.get("sessionId") or "")
    leg = str(params.get("leg") or "")
    if method == "ping":
        return {"ok": True}
    if method == "pc.create":
        return await _peer_json(peer.create(
            sid,
            leg or "pc1",
            bool(params.get("reserveAudio")),
            json.dumps(params.get("iceServers") or []),
        ))
    if method == "pc.setRemote":
        sdp = _repair_missing_rtpmap(str(params.get("sdp") or ""))
        ordered = _order_sdp_for_str0m(sdp)
        if ordered != sdp:
            log.info(
                f"pc.setRemote: lifted c= under m= session={sid} leg={leg or 'pc1'}"
            )
            sdp = ordered
        kind = str(params.get("type") or "offer")
        if kind == "answer":
            offer = _local_sdp.get((sid, leg or "pc1")) or ""
            stamped = wpc.stamp_answer_mids(sdp, offer)
            log.info(
                f"pc.setRemote answer session={sid} leg={leg or 'pc1'} "
                f"offer_bytes={len(offer)} changed={stamped != sdp} "
                f"{wpc.sdp_media_summary(stamped)}"
            )
            sdp = stamped
        return await _peer_json(peer.set_remote(
            sid,
            leg or "pc1",
            kind,
            sdp,
            bool(params.get("refreshAudio")),
        ))
    if method == "pc.addIce":
        return await _peer_json(peer.add_ice(sid, leg or "pc1", json.dumps(_cand_lines(params.get("candidates") or []))))
    if method == "pc.createOffer":
        if params.get("rotateAudio"):
            try:
                await _peer_json(peer.rotate(sid, leg or "pc1"))
            except Exception:  # noqa: BLE001
                pass
        # withAudio adds or reopens m=audio (sendrecv). rotateAudio is only
        # the extra SSRC reset. A redial must reopen audio without rotating,
        # or the offer stays inactive from the hangup and the phone ignores it.
        with_audio = params.get("withAudio")
        if with_audio is None:
            with_audio = bool(params.get("rotateAudio"))
        out = await _peer_json(peer.create_offer(
            sid, leg or "pc1", bool(with_audio),
        ))
        if params.get("narrowG711") and out.get("sdp"):
            try:
                from client_ingress import _narrow_telephony_audio_sdp

                out["sdp"] = _narrow_telephony_audio_sdp(str(out["sdp"]))
            except Exception:  # noqa: BLE001
                pass
        if out.get("sdp"):
            _local_sdp[(sid, leg or "pc1")] = str(out["sdp"])
        return out
    if method == "pc.createAnswer":
        out = await _peer_json(peer.create_answer(sid, leg or "pc1"))
        if out.get("sdp"):
            _local_sdp[(sid, leg or "pc1")] = str(out["sdp"])
        return out
    if method == "pc.localIce":
        deadline = time.monotonic() + (float(params.get("timeoutMs") or 0) / 1000.0)
        while True:
            out = await _peer_json(peer.local_ice(sid, leg or "pc1"))
            lines = list(out.get("candidates") or [])
            relay = any("typ relay" in line for line in lines)
            if not params.get("waitRelay") or relay or time.monotonic() >= deadline:
                remembered = _local_sdp.get((sid, leg or "pc1"), "")
                return {"candidates": _with_sdp_mids(remembered, lines)}
            await asyncio.sleep(0.05)
    if method == "pc.waitConnected":
        return await _peer_json(peer.wait_connected(
            sid, leg or "pc1", int(params.get("timeoutMs") or (timeout or 8) * 1000),
        ))
    if method == "pc.close":
        if not leg:
            return await _peer_json(peer.abandon(sid))
        return await _peer_json(peer.close(sid, leg))
    if method == "dc.send":
        body = params.get("json")
        text = body if isinstance(body, str) else json.dumps(body)
        return await _peer_json(peer.send(sid, leg or "pc1", text))
    if method == "audio.rotate":
        try:
            return await _peer_json(peer.rotate(sid, leg or "pc1"))
        except Exception as exc:  # noqa: BLE001
            if "no audio mid" not in str(exc):
                raise
            log.info(f"audio.rotate skipped session={sid} leg={leg or 'pc1'} (no audio yet)")
            return {"ok": True, "skipped": True}
    if method == "bridge.start":
        return await _peer_json(peer.bridge(sid, str(params.get("a") or "pc1"), str(params.get("b") or "pc2")))
    if method == "bridge.stop":
        return await _peer_json(peer.unbridge(sid))
    if method == "bridge.injectDtmf":
        return await _peer_json(peer.dtmf(
            sid,
            str(params.get("towardLeg") or leg or "pc1"),
            str(params.get("digit") or ""),
            bool(params.get("rfc4733")),
        ))
    if method == "session.abandon":
        return await _peer_json(peer.abandon(sid))
    if method == "session.softEnd":
        legs = params.get("legs") or [leg or "pc1"]
        for one in legs:
            await _peer_json(peer.soft_end(sid, str(one)))
        return {"ok": True}
    if method == "bridge.across":
        return await _peer_json(peer.bridge_across(
            sid,
            str(params.get("a") or "pc1"),
            str(params.get("peerSessionId") or sid),
            str(params.get("b") or "pc2"),
        ))
    raise RuntimeError(f"siphon.peer has no {method}")


def _start_peer_poller() -> None:
    global _poller_started
    peer = _native_peer()
    if peer is None or _poller_started:
        return
    _poller_started = True

    def _loop() -> None:
        while True:
            try:
                msg = peer.poll_event(500)
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
                continue
            if msg:
                _on_worker_event(msg)

    threading.Thread(target=_loop, name="siphon-peer-events", daemon=True).start()


class WorkerPc:
    def __init__(self, session_id: str, leg: str, epoch: int = 0) -> None:
        self.session_id = session_id
        self.leg = leg
        self.epoch = int(epoch or 0)
        self.worker = True
        self.connectionState = "new"
        self.iceConnectionState = "new"
        self.iceGatheringState = "complete"
        self.localDescription = None

    async def setRemoteDescription(self, desc: Any) -> None:
        sdp = getattr(desc, "sdp", None)
        typ = getattr(desc, "type", None)
        if isinstance(desc, dict):
            sdp = desc.get("sdp")
            typ = desc.get("type")
        await peer_call(
            "pc.setRemote",
            {
                "sessionId": self.session_id,
                "leg": self.leg,
                "type": str(typ or "answer"),
                "sdp": str(sdp or ""),
            },
        )


    async def close(self) -> None:
        await peer_call(
            "pc.close", {"sessionId": self.session_id, "leg": self.leg}
        )


class WorkerDc:
    def __init__(self, session_id: str, leg: str) -> None:
        self.session_id = session_id
        self.leg = leg
        self.worker = True
        self.readyState = "connecting"
        self.label = "chat"

    def send(self, data: Any) -> None:
        session = _lookup_session(self.session_id)
        if session is None:
            raise RuntimeError("WorkerDc.send: session gone")
        raw = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
        message = json.loads(raw) if isinstance(raw, str) else raw
        send_dc_json(session, message, leg=self.leg)


def _lookup_session(session_id: str) -> Optional[dict[str, Any]]:
    try:
        from client_ingress import _session_for_worker

        return _session_for_worker(session_id)
    except Exception:  # noqa: BLE001
        return None


def _phone_worker_leg(session: dict[str, Any]) -> str:
    """Phone PC. After a callback, pc2 is the SBC and must not win this lookup."""
    phone = session.get("pcCallee")
    sbc = session.get("pc2")
    if phone is not None and sbc is not None and sbc is not phone:
        leg = str(getattr(phone, "leg", "") or "")
        if leg and leg != "pc2":
            return leg
    pc = sbc or phone
    if pc is None:
        return ""
    return str(getattr(pc, "leg", "") or "")


def _on_worker_event(msg: dict[str, Any]) -> None:
    event = str(msg.get("event") or "")
    sid = str(msg.get("sessionId") or "")
    leg = str(msg.get("leg") or "")
    session = _lookup_session(sid)
    if session is None:
        return
    loop = session.get("eventLoop")
    if event == "dc.open":
        _on_dc_open(session, leg)
    elif event == "dc.close":
        _on_dc_close(session, leg)
    elif event == "dc.message":
        raw = str(msg.get("data") or "")
        _on_dc_message(session, leg, raw)
    elif event == "connection":
        if _stale_worker_event(session, leg, msg):
            return
        state = str(msg.get("state") or "")
        pc = _pc_for_leg(session, leg)
        if pc is not None:
            pc.connectionState = state
        phone_leg = _phone_worker_leg(session)
        b_caller_leg = str(session.get("bLegCallerLeg") or "")
        ended = bool(session.get("softEnded") or session.get("clientEnded"))
        if state == "connected":
            _note_leg_up(session, leg)
        elif state in ("failed", "closed"):
            drop = False
            if leg == "pc1":
                session["pc1Connected"] = False
                if not b_caller_leg:
                    drop = True
            elif b_caller_leg and leg == b_caller_leg:
                session["bLegCallerConnected"] = False
                drop = True
            elif leg == "pc2" and session.get("voicemailActive"):
                session["pc2Connected"] = False
                session["sbcPc2Connected"] = False
                drop = True
            elif leg == "pc2" and phone_leg and phone_leg != "pc2":
                session["sbcPc2Connected"] = False
                drop = True
            elif phone_leg and leg == phone_leg:
                session["pc2Connected"] = False
                drop = True
            if drop and session.get("mediaBridged") and not ended:
                wpc._schedule(
                    session, unbridge_media(session), label="media-unbridge-leg-down"
                )
    elif event == "iceConnection":
        if _stale_worker_event(session, leg, msg):
            return
        pc = _pc_for_leg(session, leg)
        ice = str(msg.get("state") or "")
        dtls = str(msg.get("dtls") or "")
        if pc is not None:
            pc.iceConnectionState = ice
            if dtls:
                pc.dtlsState = dtls
        if dtls == "connected" or ice in ("connected", "completed"):
            if dtls == "connected" or str(getattr(pc, "dtlsState", "") or "") == "connected":
                _note_leg_up(session, leg)
    elif event == "dtls":
        if _stale_worker_event(session, leg, msg):
            return
        pc = _pc_for_leg(session, leg)
        dtls = str(msg.get("dtls") or msg.get("state") or "")
        if pc is not None and dtls:
            pc.dtlsState = dtls
        if dtls == "connected":
            _note_leg_up(session, leg)
    elif event == "dtmf":
        digit = str(msg.get("digit") or "")
        log.info(
            f"DTMF/RTP hit session={session.get('sessionId')} worker={sid} "
            f"digit={digit!r} pt={msg.get('pt')} dir={msg.get('direction')} "
            f"leg={leg or '-'}"
        )
        if digit:
            cb = session.get("on_dc_action")
            if callable(cb):
                dc_leg = "callee" if str(leg or "").startswith("callee") else str(leg or "pc1")
                cb(
                    session,
                    {
                        "msgType": "dtmf",
                        "action": "dtmf",
                        "digit": digit,
                        "source": "rtp",
                        "pt": msg.get("pt"),
                        "_dcLeg": dc_leg,
                        "originLeg": str(leg or ""),
                    },
                )
            else:
                log.warn(f"DTMF/RTP: no on_dc_action session={session.get('sessionId')}")
    elif event == "stats":
        health = msg.get("health") or {}
        log.info(
            f"MEDIA-STATS session={sid} worker "
            f"a_to_b={health.get('aToB')} b_to_a={health.get('bToA')} "
            f"a_in={(health.get('a') or {}).get('inboundPackets')} "
            f"b_in={(health.get('b') or {}).get('inboundPackets')}"
        )
    if loop is None:
        return


def _stale_worker_event(session: dict[str, Any], leg: str, msg: dict[str, Any]) -> bool:
    """Ignore abandonPc / replaced-PC emits (Node !transportBinding)."""
    pc = _pc_for_leg(session, leg)
    if pc is None:
        return True
    epoch = msg.get("epoch")
    if epoch is None:
        return False
    return int(getattr(pc, "epoch", 0) or 0) != int(epoch)


def _pc_for_leg(session: dict[str, Any], leg: str) -> Any:
    if leg == "pc1":
        return session.get("pc")
    if leg == "pc2":
        return session.get("pc2")
    if (
        session.get("bLegCallerPc") is not None
        and getattr(session.get("bLegCallerPc"), "leg", "") == leg
    ):
        return session.get("bLegCallerPc")
    if session.get("pcCallee") is not None and getattr(session.get("pcCallee"), "leg", "") == leg:
        return session.get("pcCallee")
    for ring in (session.get("ringLegs") or {}).values():
        pc = getattr(ring, "pc", None)
        if getattr(pc, "leg", None) == leg:
            return pc
    return session.get("pc2")


def _note_leg_up(session: dict[str, Any], leg: str) -> None:
    """DTLS is up. str0m emits that on event=dtls field=dtls, not state."""
    ended = bool(session.get("softEnded") or session.get("clientEnded"))
    phone_leg = _phone_worker_leg(session)
    b_caller_leg = str(session.get("bLegCallerLeg") or "")
    pc = _pc_for_leg(session, leg)
    if pc is not None:
        pc.connectionState = "connected"
        pc.dtlsState = "connected"
    if leg == "pc1":
        session["pc1Connected"] = True
        if not ended:
            wpc._schedule(session, wpc._bridge_media(session), label="media-bridge-pc1-conn")
    elif b_caller_leg and leg == b_caller_leg:
        session["bLegCallerConnected"] = True
        if not ended:
            wpc._schedule(
                session, wpc._bridge_media(session), label="media-bridge-bcaller-conn"
            )
    elif leg == "pc2" and session.get("voicemailActive"):
        session["pc2Connected"] = True
        session["sbcPc2Connected"] = True
        if not ended:
            wpc._schedule(
                session, wpc._bridge_media(session), label="media-bridge-vm-pc2-conn"
            )
    elif leg == "pc2" and phone_leg and phone_leg != "pc2":
        session["sbcPc2Connected"] = True
        if not ended:
            wpc._schedule(
                session, wpc._bridge_media(session), label="media-bridge-sbc-pc2-conn"
            )
    elif phone_leg and leg == phone_leg:
        session["pc2Connected"] = True
        if not ended and (
            session.get("calleeRingAnswered") or session.get("pc2OfferReady")
        ):
            wpc._schedule(session, wpc._bridge_media(session), label="media-bridge-pc2-conn")
    elif leg == "pc2":
        session["pc2Connected"] = True
        session["sbcPc2Connected"] = True
        if not ended:
            wpc._schedule(session, wpc._bridge_media(session), label="media-bridge-pc2-conn")
    log.info(
        f"MEDIA: leg up session={session.get('sessionId')} leg={leg} "
        f"phone={phone_leg or '-'}"
    )


def _on_dc_open(session: dict[str, Any], leg: str) -> None:
    dc = WorkerDc(_sid(session), leg)
    dc.readyState = "open"
    if leg == "pc1":
        session["dataChannel"] = dc
        session["dcOpen"] = True
        log.info(f"PC1: session={session.get('sessionId')} datachannel OPEN (worker)")
        _note_leg_up(session, "pc1")
        return
    session.setdefault("dcByIdentity", {})
    ident = leg.split(":", 1)[1] if leg.startswith("callee:") else leg
    session["dcByIdentity"][ident] = dc
    ring = (session.get("ringLegs") or {}).get(ident)
    if ring is not None:
        ring.dc = dc
        wpc._resolve_future(getattr(ring, "dc_open_fut", None), True)
        if ring.promoted:
            session["calleeDataChannel"] = dc
            session["calleeDcOpen"] = True
            wpc._resolve_future(session.get("calleeDcOpenFut"), True)
    log.info(f"PC-callee[{ident}]: session={session.get('sessionId')} datachannel OPEN (worker)")
    winner = str(session.get("multiringWinner") or "")
    loser = bool(winner and ident != winner)
    if session.get("clientEnded") or session.get("callerCancelForwarded") or loser:
        ring_obj = (session.get("ringLegs") or {}).get(ident)
        if ring_obj is not None:
            ring_obj.cancelled = True
        task = getattr(ring_obj, "drive_task", None) if ring_obj is not None else None
        if task is not None and not task.done():
            return
        reason = "answered-elsewhere" if loser else "cancelled"
        wpc._schedule(
            session,
            wpc.send_dc_cancel_for_identity(session, ident, reason),
            label="caller-cancel-on-dc-open",
        )


def _on_dc_close(session: dict[str, Any], leg: str) -> None:
    if leg == "pc1":
        session["dcOpen"] = False
        dc = session.get("dataChannel")
        if isinstance(dc, WorkerDc):
            dc.readyState = "closed"
        return
    ident = leg.split(":", 1)[1] if leg.startswith("callee:") else leg
    by_id = session.get("dcByIdentity")
    if isinstance(by_id, dict):
        dc = by_id.get(ident)
        if isinstance(dc, WorkerDc):
            dc.readyState = "closed"
        by_id.pop(ident, None)
    ring = (session.get("ringLegs") or {}).get(ident)
    if ring is not None:
        dc = ring.dc
        if isinstance(dc, WorkerDc):
            dc.readyState = "closed"
        ring.dc = None
        if ring.promoted:
            session["calleeDcOpen"] = False


def _on_dc_message(session: dict[str, Any], leg: str, raw: str) -> None:
    if leg == "pc1":
        wpc._handle_dc_message(session, raw)
        return
    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001
        return
    if not isinstance(data, dict):
        return
    ident = leg.split(":", 1)[1] if leg.startswith("callee:") else ""
    ring = (session.get("ringLegs") or {}).get(ident)
    if ring is not None:
        ring._on_dc_payload(data)
        return
    if leg == str(session.get("bLegCallerLeg") or ""):
        data["_dcLeg"] = "pc1"
        data["_dcIdent"] = str(session.get("bLegCallerIdent") or ident or session.get("from") or "")
        wpc._note_leg_call_id(session, "pc1", data)
        msg_type = data.get("msgType")
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        action = data.get("action") or payload.get("type")
        action_l = str(action or "").lower()
        if msg_type == "call" and action_l in ("end", "hangup"):
            reason = str(data.get("reason") or action or "hangup")
            end_cb = session.get("on_dc_end")
            if callable(end_cb):
                wpc._schedule(
                    session,
                    end_cb(session, reason, ended_leg="pc1"),
                    label="bcaller_on_dc_end",
                )
            return
        if msg_type == "signaling" and action_l == "end-call":
            reason = str(data.get("reason") or "hangup")
            end_cb = session.get("on_dc_end")
            if callable(end_cb):
                wpc._schedule(
                    session,
                    end_cb(session, reason, ended_leg="pc1"),
                    label="bcaller_on_dc_end",
                )
            return
        action_cb = session.get("on_dc_action")
        if callable(action_cb) and (
            session.get("productKind")
            or msg_type in ("dtmf", "digit", "action")
            or payload.get("digit") is not None
            or action_l in ("dtmf", "digit", "transfer", "redirect")
        ):
            action_cb(session, data)
            return
        return
    wpc._handle_callee_dc_payload(session, data)


def _handle() -> None:
    _start_peer_poller()


_handle()


def _sid(session: dict[str, Any]) -> str:
    return str(session.get("workerSessionId") or session.get("sessionId") or "")


def _ice_pc1() -> list[dict[str, Any]]:
    return media_worker.ice_servers()


async def handshake(
    session: dict[str, Any],
    offer_sdp: str,
    candidates: Optional[list[Any]] = None,
    *,
    on_dc_ring: Any = None,
    reuse_pc: bool = False,
) -> dict[str, Any]:
    session_id = _sid(session)
    on_dc_end = session.get("on_dc_end")
    on_dc_action = session.get("on_dc_action")
    session["on_dc_ring"] = on_dc_ring
    session["on_dc_end"] = on_dc_end
    session["on_dc_action"] = on_dc_action
    session["eventLoop"] = asyncio.get_running_loop()
    session["iceCandidates"] = []
    session["dcRingStarted"] = False
    session["mediaWorker"] = True
    session["mediaBridged"] = False
    keep = bool(reuse_pc and session.get("pc") is not None)
    if keep:
        log.info(
            f"PC1: handshake reuse live PC session={session_id} "
            f"offer_bytes={len(offer_sdp or '')} via=worker"
        )
    else:
        session["dcOpen"] = False
        session["pc1Connected"] = False
        session.pop("pc1Str0mOffer", None)
        created = await peer_call(
            "pc.create",
            {
                "sessionId": session_id,
                "leg": "pc1",
                "iceServers": _ice_pc1(),
                "replace": True,
            },
        )
        session["pc"] = WorkerPc(
            session_id, "pc1", epoch=int((created or {}).get("epoch") or 0)
        )
        log.info(
            f"PC1: handshake begin session={session_id} "
            f"offer_bytes={len(offer_sdp or '')} via=worker"
        )
    ufrag, _pwd = wpc._sdp_ice_ufrag_pwd(str(offer_sdp or ""))
    session["pc1RemoteUfrag"] = str(ufrag or "")
    await peer_call(
        "pc.setRemote",
        {"sessionId": session_id, "leg": "pc1", "type": "offer", "sdp": str(offer_sdp or "")},
    )
    applied = await add_ice_candidates(session, candidates or [])
    log.info(f"PC1: applied offer trickle candidates={applied}")
    result = await peer_call(
        "pc.createAnswer",
        {"sessionId": session_id, "leg": "pc1"},
    )
    answer_sdp = str(result.get("sdp") or "")
    try:
        from client_ingress import ensure_telephone_event_sdp

        answer_sdp = ensure_telephone_event_sdp(answer_sdp, str(offer_sdp or ""))
    except Exception:  # noqa: BLE001
        pass
    ice = _with_sdp_mids(answer_sdp, result.get("candidates"))
    ice_for_client = wpc.candidates_for_client(ice)
    answer_sdp = wpc.embed_candidates_in_sdp(answer_sdp, ice_for_client)
    session["state"] = "pc1-answered"
    log.info(
        f"PC1: createAnswer done session={session_id} answer_bytes={len(answer_sdp)} "
        f"candidates={len(ice_for_client)} types[{wpc.candidate_type_counts(ice_for_client)}] "
        f"via=worker"
    )
    return {"sdp": answer_sdp, "candidates": ice_for_client}


async def add_ice_candidates(session: dict[str, Any], candidates: list[Any]) -> int:
    return await add_ice_candidates_to_pc(session, session.get("pc"), candidates, label="PC1")


async def add_ice_candidates_to_pc(
    session: dict[str, Any],
    pc: Any,
    candidates: list[Any],
    *,
    label: str = "PC",
) -> int:
    if pc is None or not getattr(pc, "worker", False):
        return 0
    result = await peer_call(
        "pc.addIce",
        {
            "sessionId": getattr(pc, "session_id", _sid(session)),
            "leg": getattr(pc, "leg", "pc1"),
            "candidates": candidates or [],
        },
    )
    return int(result.get("added") or 0)


async def send_dc_json_async(session: dict[str, Any], message: dict[str, Any], *, leg: str = "pc1") -> None:
    try:
        await peer_call(
            "dc.send",
            {"sessionId": _sid(session), "leg": leg, "json": message},
        )
    except Exception as exc:  # noqa: BLE001
        if "no dc" in str(exc).lower():
            log.warn(
                f"{leg}: session={session.get('sessionId')} dc.send skipped (no dc)"
            )
            return
        raise


async def hangup_loser_leg(
    session: dict[str, Any],
    *,
    ident: str,
    worker_leg: str,
    call_id: int,
    reason: str,
) -> bool:
    """Same hangup as a real end: call/end then inactive SDP, loser's RING callId."""
    await send_dc_json_async(
        session,
        {
            "msgType": "call",
            "action": "end",
            "callId": call_id,
            "reason": reason,
        },
        leg=worker_leg,
    )
    offer_sdp = ""
    try:
        await peer_call(
            "session.softEnd",
            {
                "sessionId": _sid(session),
                "legs": [worker_leg],
                "keepBridge": True,
            },
        )
        result = await peer_call(
            "pc.createOffer",
            {"sessionId": _sid(session), "leg": worker_leg},
        )
        offer_sdp = wpc.normalize_end_call_offer_sdp(str(result.get("sdp") or ""))
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC: loser end-call offer failed ident={ident!r} "
            f"session={session.get('sessionId')}: {exc}"
        )
    if offer_sdp.strip():
        await send_dc_json_async(
            session,
            {
                "msgType": "signaling",
                "action": "end-call",
                "callId": call_id,
                "reason": reason,
                "payload": {
                    "type": "offer",
                    "from": session.get("from"),
                    "to": ident,
                    "sessionId": session.get("sessionId"),
                    "sdp": offer_sdp,
                    "callId": call_id,
                },
            },
            leg=worker_leg,
        )
    else:
        await send_dc_json_async(
            session,
            {
                "msgType": "signaling",
                "action": "end-call",
                "callId": call_id,
                "reason": reason,
                "payload": {"callId": call_id, "type": "end-call", "reason": reason},
            },
            leg=worker_leg,
        )
    log.info(
        f"PC: loser hangup ident={ident!r} session={session.get('sessionId')} "
        f"callId={call_id} sdp={len(offer_sdp)} reason={reason}"
    )
    return True


def _drop_stale_callback_ring(session: dict[str, Any]) -> None:
    """A new caller RING owns the PC. Do not flush the previous held answer."""
    session["callbackRingToken"] = int(session.get("callbackRingToken") or 0) + 1
    session["pendingCalleeAnswerSdp"] = None
    session["pendingCalleeAnswerIce"] = None
    fut = session.get("pc1RingAnswerFut")
    if fut is not None and not fut.done():
        fut.cancel()


def send_dc_json(session: dict[str, Any], message: dict[str, Any], *, leg: str = "pc1") -> None:
    wpc._schedule(
        session,
        send_dc_json_async(session, message, leg=leg),
        label="dc-send-worker",
    )
    action = message.get("action") or (message.get("payload") or {}).get("type") or "unknown"
    log.info(
        f"{leg}: session={session.get('sessionId')} DC-OUT msgType={message.get('msgType')!r} "
        f"action={action!r} via=worker"
    )


def dc_is_open(session: dict[str, Any], *, leg: str = "pc1") -> bool:
    if leg == "pc1":
        return bool(session.get("dcOpen"))
    return wpc._callee_transport_open(session, leg)


async def prepare_ring_answer(
    session: dict[str, Any],
    offer_sdp: str,
    candidates: Optional[list[Any]] = None,
) -> str:
    session["endCallRenegotiating"] = False
    session_id = _sid(session)
    raw_offer = str(offer_sdp or "")
    try:
        from client_ingress import _narrow_telephony_audio_sdp

        offer_sdp = _narrow_telephony_audio_sdp(raw_offer)
    except Exception:  # noqa: BLE001
        offer_sdp = raw_offer
    session["ringOfferSdp"] = offer_sdp
    fed = wpc.pin_established_mlines(offer_sdp, str(session.get("pc1Str0mOffer") or ""))
    if fed != offer_sdp:
        log.info(
            f"PC1: keep established m-lines session={session_id} "
            f"offer_bytes={len(offer_sdp)} fed_bytes={len(fed)}"
        )
    log.info(f"PC1: RING setRemote begin session={session_id} offer_bytes={len(fed)} via=worker")
    try:
        from client_ingress import _log_sdp

        _log_sdp(f"PC1 RING offer SDP in session={session_id}", fed)
    except Exception:  # noqa: BLE001
        log.info(f"PC1: RING offer SDP in session={session_id}\n{fed}")
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": session_id,
            "leg": "pc1",
            "type": "offer",
            "sdp": fed,
            # First RING has no transmit stream yet, so this no-ops.
            # A redial must mint a new SSRC or iOS treats the answer as the
            # previous one and leaves the transceiver inactive.
            "refreshAudio": True,
        },
    )
    await add_ice_candidates(session, candidates or [])
    result = await peer_call(
        "pc.createAnswer",
        {"sessionId": session_id, "leg": "pc1"},
    )
    answer_sdp = str(result.get("sdp") or "")
    try:
        from client_ingress import ensure_telephone_event_sdp

        answer_sdp = ensure_telephone_event_sdp(answer_sdp, offer_sdp)
    except Exception:  # noqa: BLE001
        pass
    answer_sdp = wpc.answer_for_client_mids(answer_sdp, offer_sdp)
    session["pc1Str0mOffer"] = fed
    ice = _with_sdp_mids(answer_sdp, result.get("candidates"))
    ice_for_client = wpc.candidates_for_client(ice)
    answer_sdp = wpc.embed_candidates_in_sdp(answer_sdp, ice_for_client)
    session["pendingAnswerSdp"] = answer_sdp
    session["state"] = "ring-answer-held"
    log.info(
        f"PC1: held ring answer session={session_id} bytes={len(answer_sdp)} "
        f"via=worker remint=True {wpc.sdp_media_summary(answer_sdp)}"
    )
    try:
        from client_ingress import _log_sdp

        _log_sdp(f"PC1 RING answer SDP out session={session_id}", answer_sdp)
    except Exception:  # noqa: BLE001
        log.info(f"PC1: RING answer SDP out session={session_id}\n{answer_sdp}")
    return answer_sdp


def _bridge_record(session: dict[str, Any]) -> bool:
    return bool(wpc.session_should_record(session))


def _concat_pcm_wav(first: bytes, second: bytes) -> bytes:
    """Append two MediaBridge PCM wavs (same fmt). Keep `second` on mismatch."""
    if not first:
        return second
    if not second:
        return first

    def _split(wav: bytes) -> tuple[bytes, bytes] | None:
        if len(wav) < 44 or wav[0:4] != b"RIFF" or wav[8:12] != b"WAVE":
            return None
        return wav[:44], wav[44:]

    a = _split(first)
    b = _split(second)
    if not a or not b or a[0][20:36] != b[0][20:36]:
        return second
    data = a[1] + b[1]
    hdr = bytearray(a[0])
    struct.pack_into("<I", hdr, 4, 36 + len(data))
    struct.pack_into("<I", hdr, 40, len(data))
    return bytes(hdr) + data


def _epoch_seconds(value: Any) -> Optional[float]:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n > 1e11:
        n /= 1000.0
    return n


def _take_bridge_wav(session: dict[str, Any], result: Any) -> None:
    wav = b""
    path = str((result or {}).get("wavPath") or "")
    if path:
        try:
            with open(path, "rb") as fh:
                wav = fh.read()
        except Exception as exc:  # noqa: BLE001
            log.warn(f"RECORD: read wavPath failed path={path!r}: {exc}")
            wav = b""
        try:
            os.unlink(path)
        except Exception:  # noqa: BLE001
            pass
    if not wav:
        raw = str((result or {}).get("wavBase64") or "")
        if raw:
            try:
                wav = base64.b64decode(raw)
            except Exception:  # noqa: BLE001
                wav = b""
    if wav:
        prev = session.get("recordingWav") or b""
        if prev:
            wav = _concat_pcm_wav(prev, wav)
        session["recordingWav"] = wav
        started = _epoch_seconds((result or {}).get("startedAt"))
        ended = _epoch_seconds((result or {}).get("endedAt"))
        if started and not session.get("recordingStartedAt"):
            session["recordingStartedAt"] = started
        if ended:
            session["recordingEndedAt"] = ended
        log.info(
            f"RECORD: worker wav session={session.get('sessionId')} bytes={len(wav)}"
        )


def _callee_calling_out(session: dict[str, Any]) -> bool:
    """This call is the extension dialing the PSTN.

    A session the SBC opened stays routeKind=inbound forever. That label is
    the first call. Here sipCall is gone and pc2 is the new SBC leg, so the
    inbound "wait until we 200 them" check does not apply.
    """
    if session.get("voicemailActive") or session.get("bLegCallerLeg"):
        return False
    if session.get("sipCall") is not None:
        return False
    if not (session.get("sbcAnswered") or session.get("sbcHairpinAnswered")):
        return False
    phone = session.get("pcCallee")
    sbc = session.get("pc2")
    if phone is None or sbc is None or sbc is phone:
        return False
    return str(getattr(sbc, "leg", "") or "") == "pc2"


def _phone_ready(session: dict[str, Any]) -> bool:
    """Client/phone PC is actually up (DTLS), not just RING-answered."""
    if session.get("bLegCallerLeg"):
        return bool(session.get("bLegCallerConnected", True))
    if session.get("voicemailActive"):
        return bool(session.get("pc1Connected"))
    if _callee_calling_out(session):
        phone = session.get("pcCallee")
        conn = str(getattr(phone, "connectionState", "") or "").lower()
        return conn == "connected" or bool(session.get("calleeDcOpen"))
    kind = str(session.get("routeKind") or "")
    if kind == "inbound":
        return bool(session.get("calleeRingAnswered") and session.get("pc2Connected"))
    phone = session.get("pcCallee")
    sbc = session.get("pc2")
    if phone is not None and sbc is not None and sbc is not phone:
        conn = str(getattr(phone, "connectionState", "") or "").lower()
        return conn == "connected" or bool(
            session.get("calleeRingAnswered") and session.get("pc2Connected")
        )
    return bool(session.get("pc1Connected"))


def _sbc_ready(session: dict[str, Any]) -> bool:
    """rtpengine/SBC PC DTLS up — not SIP 200, not ICE-only."""
    if session.get("voicemailActive"):
        return bool(session.get("pc2Connected") or session.get("sbcPc2Connected"))
    if session.get("bLegCallerLeg"):
        return bool(session.get("pc2Connected") or session.get("sbcPc2Connected"))
    if _callee_calling_out(session):
        sbc = session.get("pc2")
        conn = str(getattr(sbc, "connectionState", "") or "").lower()
        return conn == "connected" or bool(session.get("sbcPc2Connected"))
    kind = str(session.get("routeKind") or "")
    if kind == "inbound":
        return bool(session.get("pc1Connected"))
    phone = session.get("pcCallee")
    sbc = session.get("pc2")
    if (
        phone is not None
        and sbc is not None
        and sbc is not phone
        and str(getattr(sbc, "leg", "") or "") == "pc2"
    ):
        conn = str(getattr(sbc, "connectionState", "") or "").lower()
        return conn == "connected" or bool(session.get("sbcPc2Connected"))
    if session.get("pc2Connected"):
        return True
    # Hangup unbridge clears the flag and leaves the callee PC up. A redial
    # does not get a second "connected" event for that leg.
    phone = session.get("pcCallee") or session.get("pc2")
    if phone is not None and str(getattr(phone, "leg", "") or "").startswith("callee:"):
        if str(getattr(phone, "connectionState", "") or "").lower() == "connected":
            session["pc2Connected"] = True
            return True
    return False


async def rebridge_media(session: dict[str, Any], *, force: bool = False) -> None:
    await _bridge_media(session, force=force)


async def _bridge_media(session: dict[str, Any], force: bool = False) -> None:
    if (
        session.get("endCallRenegotiating")
        or session.get("softEndInProgress")
        or session.get("softEnded")
        or session.get("clientEnded")
    ):
        log.info(
            f"MEDIA: bridge deferred (end-call) session={session.get('sessionId')}"
        )
        return
    if (
        session.get("routeKind") == "inbound"
        and not session.get("inboundSipAnswered")
        and not _callee_calling_out(session)
    ):
        log.info(
            f"MEDIA: bridge deferred (inbound SIP not answered) session={session.get('sessionId')}"
        )
        return
    if not _phone_ready(session):
        log.info(
            f"MEDIA: bridge deferred (phone leg not ready) session={session.get('sessionId')} "
            f"ring={bool(session.get('calleeRingAnswered'))} "
            f"pc2={bool(session.get('pc2Connected'))} pc1={bool(session.get('pc1Connected'))}"
        )
        return
    if not _sbc_ready(session):
        log.info(
            f"MEDIA: bridge deferred (sbc leg not ready) session={session.get('sessionId')} "
            f"pc1={bool(session.get('pc1Connected'))} "
            f"sbcPc2={bool(session.get('sbcPc2Connected'))}"
        )
        return
    b_caller_leg = str(session.get("bLegCallerLeg") or "")
    caller_pc = session.get("bLegCallerPc") if b_caller_leg else session.get("pc")
    caller_leg = b_caller_leg if b_caller_leg else "pc1"
    if session.get("voicemailActive"):
        if caller_pc is None or session.get("pc2") is None:
            log.info(
                f"MEDIA: bridge deferred (missing voicemail pc) session={session.get('sessionId')} "
                f"caller={caller_pc is not None} pc2={session.get('pc2') is not None}"
            )
            return
        if session.get("mediaBridged") and not force:
            return
        if not session.get("pc2OfferReady"):
            log.info(
                f"MEDIA: bridge deferred (PC2 offer not ready) session={session.get('sessionId')}"
            )
            return
        await peer_call(
            "bridge.start",
            {
                "sessionId": _sid(session),
                "a": caller_leg,
                "b": "pc2",
                "mode": "sbc",
                "record": _bridge_record(session),
            },
        )
        session["mediaBridged"] = True
        session["bridgedClientToSbc"] = True
        session["bridgedSbcToClient"] = True
        wpc.note_call_connected(session)
        if _bridge_record(session):
            log.info(f"RECORD: tee armed session={session.get('sessionId')} via=worker")
        log.info(
            f"MEDIA: bridge complete session={session.get('sessionId')} via=worker "
            f"a={caller_leg} b=pc2 (voicemail)"
        )
        return
    phone = session.get("pcCallee")
    sbc = session.get("pc2")
    callee_to_sbc = (
        not b_caller_leg
        and phone is not None
        and sbc is not None
        and sbc is not phone
        and str(getattr(sbc, "leg", "") or "") == "pc2"
    )
    if callee_to_sbc:
        if session.get("mediaBridged") and not force:
            return
        if not session.get("pc2OfferReady"):
            log.info(
                f"MEDIA: bridge deferred (PC2 offer not ready) session={session.get('sessionId')}"
            )
            return
        phone_leg = getattr(phone, "leg", "pc2")
        await peer_call(
            "bridge.start",
            {
                "sessionId": _sid(session),
                "a": phone_leg,
                "b": "pc2",
                "mode": "sbc",
                "record": _bridge_record(session),
            },
        )
        session["mediaBridged"] = True
        session["bridgedClientToSbc"] = True
        session["bridgedSbcToClient"] = True
        wpc.note_call_connected(session)
        if _bridge_record(session):
            log.info(f"RECORD: tee armed session={session.get('sessionId')} via=worker")
        log.info(
            f"MEDIA: bridge complete session={session.get('sessionId')} via=worker "
            f"a={phone_leg} b=pc2"
        )
        return
    pc2 = session.get("pc2") or session.get("pcCallee")
    if caller_pc is None or pc2 is None:
        log.info(
            f"MEDIA: bridge deferred (missing pc) session={session.get('sessionId')} "
            f"caller={caller_pc is not None} phone={pc2 is not None}"
        )
        return
    if session.get("mediaBridged") and not force:
        return
    if not session.get("pc2OfferReady"):
        log.info(f"MEDIA: bridge deferred (PC2 offer not ready) session={session.get('sessionId')}")
        return
    phone_leg = getattr(pc2, "leg", "pc2")
    if session.get("routeKind") == "inbound" and not b_caller_leg:
        await peer_call(
            "bridge.start",
            {
                "sessionId": _sid(session),
                "a": phone_leg,
                "b": "pc1",
                "mode": "sbc",
                "record": _bridge_record(session),
            },
        )
    else:
        mode = "sbc" if phone_leg == "pc2" and session.get("routeKind") != "webrtc" else "webrtc"
        if session.get("sbcHairpinId") or session.get("routeKind") == "sbc":
            if phone_leg == "pc2":
                mode = "sbc"
        if phone_leg == "pc2" and str((session.get("route") or {}).get("route") or "") == "sbc":
            mode = "sbc"
        await peer_call(
            "bridge.start",
            {
                "sessionId": _sid(session),
                "a": caller_leg,
                "b": phone_leg,
                "mode": mode,
                "record": _bridge_record(session),
            },
        )
    session["mediaBridged"] = True
    session["bridgedClientToSbc"] = True
    session["bridgedSbcToClient"] = True
    wpc.note_call_connected(session)
    if _bridge_record(session):
        log.info(f"RECORD: tee armed session={session.get('sessionId')} via=worker")
    log.info(
        f"MEDIA: bridge complete session={session.get('sessionId')} via=worker "
        f"a={phone_leg if (session.get('routeKind') == 'inbound' and not b_caller_leg) else caller_leg} "
        f"b={'pc1' if (session.get('routeKind') == 'inbound' and not b_caller_leg) else phone_leg}"
    )
    await _stitch_hairpin_clients(session)


async def _stitch_hairpin_clients(session: dict[str, Any]) -> None:
    """SBC hairpin sends no RTP. Bridge the two WebRTC peers directly."""
    if session.get("hairpinClientsStitched"):
        return
    if not (session.get("peerHairpinId") or session.get("hairpinReturnWorker")):
        return
    import client_ingress as ci

    if session.get("peerHairpinId"):
        inbound = session
        outbound = ci._get_session(str(session.get("hairpinCallerKey") or ""))
    else:
        outbound = session
        inbound = ci._get_session(str(session.get("hairpinReturnKey") or ""))
    if not inbound or not outbound:
        return
    if not inbound.get("mediaBridged") or not outbound.get("mediaBridged"):
        return
    caller = outbound.get("pc")
    callee = inbound.get("pcCallee")
    caller_leg = str(getattr(caller, "leg", "") or "")
    callee_leg = str(getattr(callee, "leg", "") or "")
    caller_worker = str(outbound.get("workerSessionId") or "")
    callee_worker = str(inbound.get("workerSessionId") or "")
    if not caller_leg or not callee_leg or not caller_worker or not callee_worker:
        return
    try:
        await peer_call(
            "bridge.across",
            {
                "sessionId": caller_worker,
                "a": caller_leg,
                "peerSessionId": callee_worker,
                "b": callee_leg,
            },
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"MEDIA: hairpin client stitch failed "
            f"caller={outbound.get('sessionId')} callee={inbound.get('sessionId')}: {exc}"
        )
        return
    outbound["hairpinClientsStitched"] = True
    inbound["hairpinClientsStitched"] = True
    log.info(
        f"MEDIA: hairpin clients stitched "
        f"caller={caller_worker}:{caller_leg} callee={callee_worker}:{callee_leg}"
    )


async def unbridge_media(session: dict[str, Any], *, keep_pc1_audio: bool = False) -> None:
    try:
        stopped = await peer_call("bridge.stop", {"sessionId": _sid(session)})
        _take_bridge_wav(session, stopped)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"MEDIA: bridge.stop failed session={session.get('sessionId')}: {exc}")
    wpc.finalize_recording(session)
    session["bridgedClientToSbc"] = False
    session["bridgedSbcToClient"] = False
    session["mediaBridged"] = False
    session["calleeRingAnswered"] = False
    session.pop("activeCallId", None)
    pc2 = session.get("pc2")
    pc_callee = session.get("pcCallee")
    # SBC/rtpengine PC2 is dead after BYE. Leave it up and late DTLS
    # "connected" restarts the bridge on a hung-up call.
    if pc2 is not None and pc2 is not pc_callee and getattr(pc2, "worker", False):
        try:
            await peer_call(
                "pc.close",
                {"sessionId": getattr(pc2, "session_id", _sid(session)), "leg": "pc2"},
                timeout=2.0,
            )
        except Exception:  # noqa: BLE001
            pass
        session["pc2"] = None
    session["pc2OfferReady"] = False
    session["pc2Connected"] = False
    log.info(f"MEDIA: unbridged session={session.get('sessionId')} via=worker")


async def inject_dtmf(
    session: dict[str, Any],
    digit: Any,
    duration_ms: Any = 200,
    volume: Any = 10,
    *,
    source_leg: str = "",
    rfc4733: bool = False,
) -> None:
    """Write RFC4733 from the origin leg toward the opposite leg."""
    code = str(digit if digit is not None else "").strip()
    if not code:
        raise RuntimeError("inject DTMF needs digit")
    src = str(source_leg or session.get("lastDtmfDcLeg") or "").strip()
    b_caller_leg = str(session.get("bLegCallerLeg") or "").strip()
    phone = session.get("pcCallee")
    sbc = session.get("pc2")
    phone_leg = str(getattr(phone, "leg", "") or "").strip()
    if src in ("pc2", "openai-dtmf"):
        if b_caller_leg:
            toward = b_caller_leg
        elif str(session.get("routeKind") or "") == "inbound" and phone_leg and phone_leg != "pc2":
            toward = phone_leg
        else:
            toward = "pc1"
    elif src == "callee" or src.startswith("callee:"):
        if session.get("voicemailActive"):
            toward = "pc2"
        elif str(session.get("routeKind") or "") == "inbound" and not b_caller_leg:
            toward = "pc1"
        elif b_caller_leg and src != b_caller_leg:
            toward = b_caller_leg
        elif sbc is not None and sbc is not phone and str(getattr(sbc, "leg", "") or "") == "pc2":
            toward = "pc2"
        else:
            toward = b_caller_leg or "pc1"
    else:
        if session.get("voicemailActive"):
            toward = "pc2"
        elif sbc is not None and str(getattr(sbc, "leg", "") or "") == "pc2":
            toward = "pc2"
        elif phone_leg:
            toward = phone_leg
        else:
            pc2 = sbc or phone
            toward = str(getattr(pc2, "leg", "") or "pc2")
    try:
        dur = int(duration_ms or 200)
    except (TypeError, ValueError):
        dur = 200
    try:
        vol = int(volume or 10)
    except (TypeError, ValueError):
        vol = 10
    await peer_call(
        "bridge.injectDtmf",
        {
            "sessionId": _sid(session),
            "towardLeg": toward,
            "digit": code[0],
            "durationMs": max(50, min(dur, 1000)),
            "volume": max(0, min(vol, 36)),
            "rfc4733": bool(rfc4733),
        },
        timeout=4.0,
    )


async def close_pcs(session: dict[str, Any], *, pc1: bool = True, callee: bool = True) -> None:
    if session.get("mediaBridged"):
        await unbridge_media(session)
    sid = _sid(session)
    if pc1:
        try:
            await peer_call("pc.close", {"sessionId": sid, "leg": "pc1"}, timeout=2.0)
        except Exception:  # noqa: BLE001
            pass
        session["pc"] = None
        session["dcOpen"] = False
        session["pc1Connected"] = False
    if callee:
        try:
            await peer_call("pc.close", {"sessionId": sid}, timeout=2.0)
        except Exception:  # noqa: BLE001
            pass
        session["pc2"] = None
        session["pcCallee"] = None


async def close_inbound_sip_pc(session: dict[str, Any]) -> None:
    """Drop the rtpengine WebRTC PC only. Leave the phone DC for end-call SDP."""
    await close_pcs(session, pc1=True, callee=False)


async def abandon(session: dict[str, Any]) -> None:
    """Unmap this worker session now. close() waits so it does not race the next PC."""
    sid = _sid(session)
    try:
        await peer_call("session.abandon", {"sessionId": sid}, timeout=2.0)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PC: session.abandon failed session={session.get('sessionId')}: {exc}")
    session["pc"] = None
    session["dcOpen"] = False
    session["pc1Connected"] = False
    session["pc2"] = None
    session["pcCallee"] = None
    session["calleeDcOpen"] = False


async def close(session: dict[str, Any]) -> None:
    if session.get("mediaBridged"):
        try:
            await unbridge_media(session)
        except Exception:  # noqa: BLE001
            pass
    await close_pcs(session, pc1=True, callee=True)


async def create_pc2_offer(session: dict[str, Any]) -> str:
    session_id = _sid(session)
    pc_callee = session.get("pcCallee")
    prev = session.get("pc2")
    # WebRTC hunt aliases pc2=pcCallee. SBC/OpenAI needs a real PC2 SDP —
    # empty offer → INVITE with no body → rtpengine "message has no SDP body".
    if prev is not None and pc_callee is not None and prev is pc_callee:
        log.info(f"PC2: unalias pcCallee before SBC createOffer session={session_id}")
        session["pc2"] = None
    created = await peer_call(
        "pc.create",
        {
            "sessionId": session_id,
            "leg": "pc2",
            "iceServers": [],
            "replace": True,
            "reserveAudio": True,
        },
    )
    pc = WorkerPc(session_id, "pc2", epoch=int((created or {}).get("epoch") or 0))
    session["pc2"] = pc
    session["pc2OfferReady"] = False
    session["mediaBridged"] = False
    result = await peer_call(
        "pc.createOffer",
        {"sessionId": session_id, "leg": "pc2", "rotateAudio": True},
    )
    sdp = str(result.get("sdp") or "")
    session["pc2OfferSdp"] = sdp
    session["pc2OfferReady"] = True
    session["pc2Connected"] = False
    log.info(f"PC2: createOffer done session={session_id} offer_bytes={len(sdp)} via=worker")
    return sdp


async def create_pc1_offer(session: dict[str, Any]) -> str:
    """Inbound SBC: siphon is WebRTC offerer (same polarity as working hairpin pc2)."""
    session_id = _sid(session)
    created = await peer_call(
        "pc.create",
        {
            "sessionId": session_id,
            "leg": "pc1",
            "iceServers": [],
            "replace": True,
            "reserveAudio": True,
        },
    )
    session["pc"] = WorkerPc(
        session_id, "pc1", epoch=int((created or {}).get("epoch") or 0)
    )
    session["inboundSipAnswered"] = False
    session["mediaBridged"] = False
    session["eventLoop"] = asyncio.get_running_loop()
    session["mediaWorker"] = True
    session["pc1Connected"] = False
    result = await peer_call(
        "pc.createOffer",
        {"sessionId": session_id, "leg": "pc1", "rotateAudio": True},
    )
    sdp = str(result.get("sdp") or "")
    session["pc1OfferSdp"] = sdp
    log.info(
        f"PC1: inbound createOffer session={session_id} bytes={len(sdp)} "
        f"{wpc.sdp_media_summary(sdp)}"
    )
    return sdp


async def apply_pc1_remote_answer(session: dict[str, Any], answer_sdp: str) -> None:
    ans = str(answer_sdp or "")
    try:
        from client_ingress import (
            align_pc2_answer_to_offer,
            ensure_pc2_answer_ice_lite,
            ensure_pc2_answer_rtcp_mux,
        )

        ans = ensure_pc2_answer_ice_lite(ensure_pc2_answer_rtcp_mux(ans))
        ans = align_pc2_answer_to_offer(str(session.get("pc1OfferSdp") or ""), ans)
    except Exception:  # noqa: BLE001
        pass
    await peer_call(
        "pc.setRemote",
        {"sessionId": _sid(session), "leg": "pc1", "type": "answer", "sdp": ans},
    )


async def apply_pc2_remote_answer(session: dict[str, Any], answer_sdp: str) -> None:
    ans = str(answer_sdp or "")
    try:
        from client_ingress import align_pc2_answer_to_offer, ensure_pc2_answer_rtcp_mux

        ans = ensure_pc2_answer_rtcp_mux(ans)
        ans = align_pc2_answer_to_offer(str(session.get("pc2OfferSdp") or ""), ans)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PC2: align answer to offer failed: {exc}")
    # Cellact answers PCMA plus telephone-event/8000. The relay cannot
    # play_dtmf, so the digit has to go out as RFC4733 on this PT.
    session["pc2AnswerHasTe"] = "telephone-event/8000" in ans.lower()
    await peer_call(
        "pc.setRemote",
        {"sessionId": _sid(session), "leg": "pc2", "type": "answer", "sdp": ans},
    )
    session["pc2OfferReady"] = True
    if session.get("dcOpen"):
        session["pc1Connected"] = True
    wpc._schedule(session, _arm_pc2_bridge(session), label="pc2-wait-bridge")
    await _bridge_media(session)


async def _arm_pc2_bridge(session: dict[str, Any]) -> None:
    try:
        wait = await peer_call(
            "pc.waitConnected",
            {
                "sessionId": _sid(session),
                "leg": "pc2",
                "timeoutMs": 8000,
                "requireDtls": True,
            },
            timeout=12.0,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PC2: waitConnected failed: {exc}")
        return
    log.info(
        f"PC2: waitConnected session={session.get('sessionId')} ok={wait.get('ok')} "
        f"state={wait.get('state')} ice={wait.get('ice')} dtls={wait.get('dtls')}"
    )
    if wait.get("ok") and str(wait.get("dtls") or "") == "connected":
        _note_leg_up(session, "pc2")


async def accept_sbc_rtpengine_offer(session: dict[str, Any], offer_sdp: str) -> str:
    session_id = _sid(session)
    raw = str(offer_sdp or "")
    try:
        from client_ingress import ensure_pc2_answer_ice_lite, ensure_pc2_answer_rtcp_mux

        raw = ensure_pc2_answer_rtcp_mux(raw)
        raw = ensure_pc2_answer_ice_lite(raw)
    except Exception:  # noqa: BLE001
        pass
    log.info(
        f"PC1: inbound setRemote begin session={session_id} offer_bytes={len(raw)} "
        f"(rtpengine offer: ice-lite + rtcp-mux, same as working hairpin pc2)"
    )
    created = await peer_call(
        "pc.create",
        {
            "sessionId": session_id,
            "leg": "pc1",
            "iceServers": [],
            "replace": True,
        },
    )
    session["pc"] = WorkerPc(
        session_id, "pc1", epoch=int((created or {}).get("epoch") or 0)
    )
    session["inboundSipAnswered"] = False
    session["mediaBridged"] = False
    session["eventLoop"] = asyncio.get_running_loop()
    session["mediaWorker"] = True
    await peer_call(
        "audio.rotate",
        {"sessionId": session_id, "leg": "pc1"},
    )
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": session_id,
            "leg": "pc1",
            "type": "offer",
            "sdp": raw,
            "skipPin": True,
        },
    )
    result = await peer_call(
        "pc.createAnswer",
        {"sessionId": session_id, "leg": "pc1"},
    )
    answer_sdp = str(result.get("sdp") or "")
    try:
        from client_ingress import ensure_telephone_event_sdp

        answer_sdp = ensure_telephone_event_sdp(answer_sdp, raw)
    except Exception:  # noqa: BLE001
        pass
    log.info(
        f"PC1: inbound createAnswer session={session_id} "
        f"bytes={len(answer_sdp)} {wpc.sdp_media_summary(answer_sdp)}"
    )
    return answer_sdp


async def wait_pc1_connected(session: dict[str, Any], *, timeout_s: float = 8.0) -> bool:
    wait = await peer_call(
        "pc.waitConnected",
        {
            "sessionId": _sid(session),
            "leg": "pc1",
            "timeoutMs": int(timeout_s * 1000),
            "requireDtls": True,
        },
        timeout=float(timeout_s) + 5.0,
    )
    ok = bool(wait.get("ok"))
    if ok:
        session["pc1Connected"] = True
    elif not session.get("pc1Connected"):
        session["pc1Connected"] = False
    log.info(
        f"PC1: waitConnected session={session.get('sessionId')} ok={ok} "
        f"state={wait.get('state')} ice={wait.get('ice')} dtls={wait.get('dtls')}"
    )
    return ok


async def initiate_end_call_offer(
    session: dict[str, Any],
    *,
    leg: str = "pc1",
    reason: str = "hangup",
) -> bool:
    pc = wpc._leg_pc(session, leg)
    worker_leg = getattr(pc, "leg", "pc1" if leg == "pc1" else None)
    if worker_leg is None:
        worker_leg = "pc1" if leg == "pc1" else getattr(session.get("pcCallee"), "leg", "pc2")
    if not dc_is_open(session, leg="pc1" if leg == "pc1" else worker_leg):
        if leg == "callee" and not dc_is_open(session, leg=worker_leg):
            log.info(
                f"PC: END-CALL OFFER skip session={session.get('sessionId')} leg={leg} (no open DC)"
            )
            return False
        if leg == "pc1" and not session.get("dcOpen"):
            return False
    offer_leg = worker_leg if leg != "pc1" else "pc1"
    await peer_call(
        "session.softEnd",
        {"sessionId": _sid(session), "legs": [offer_leg]},
    )
    result = await peer_call(
        "pc.createOffer",
        {"sessionId": _sid(session), "leg": offer_leg},
    )
    offer_sdp = wpc.normalize_end_call_offer_sdp(str(result.get("sdp") or ""))
    call_id = wpc._call_id_for_leg(session, offer_leg if offer_leg != "pc1" else "pc1")
    # PC1 hears the DID it dialed. promote() has already set `to` to the extension.
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
    msg = wpc._with_call_id(
        {
            "msgType": "signaling",
            "action": "end-call",
            "reason": reason,
            "payload": payload,
        },
        call_id,
    )
    send_leg = "pc1" if leg == "pc1" else worker_leg
    send_dc_json(session, msg, leg=send_leg)
    session[wpc._leg_ending_key(leg)] = True
    log.info(
        f"PC: END-CALL OFFER sent session={session.get('sessionId')} "
        f"leg={leg} bytes={len(offer_sdp)} via=worker"
    )
    return True


async def apply_end_call_answer(
    session: dict[str, Any],
    payload: dict[str, Any],
    *,
    leg: str = "pc1",
) -> None:
    pc = wpc._leg_pc(session, leg)
    worker_leg = getattr(pc, "leg", "pc1" if leg == "pc1" else None)
    if worker_leg is None:
        worker_leg = getattr(session.get("pcCallee"), "leg", "pc2")
    answer_sdp = str(payload.get("sdp") or "")
    session["endCallRenegotiating"] = True
    try:
        if answer_sdp.strip():
            await peer_call(
                "pc.setRemote",
                {
                    "sessionId": _sid(session),
                    "leg": worker_leg,
                    "type": "answer",
                    "sdp": answer_sdp,
                },
            )
    finally:
        session[wpc._leg_ending_key(leg)] = False
        session["endCallRenegotiating"] = False
    call_id = wpc._normalize_call_id(payload.get("callId")) or wpc._call_id_for_leg(
        session, "pc1" if leg == "pc1" else worker_leg
    )
    send_leg = "pc1" if leg == "pc1" else worker_leg
    try:
        send_dc_json(
            session,
            wpc._with_call_id(
                {"msgType": "signaling", "action": "end-call"},
                call_id,
            ),
            leg=send_leg,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"PC: bare end-call after answer failed session={session.get('sessionId')} "
            f"leg={leg}: {exc}"
        )
    log.info(
        f"PC: END-CALL answer applied session={session.get('sessionId')} "
        f"leg={leg} bytes={len(answer_sdp)} via=worker"
    )


async def apply_loser_end_call_answer(leg: Any, payload: dict[str, Any]) -> None:
    session = leg.session
    worker_leg = getattr(leg.pc, "leg", f"callee:{leg.ident}")
    answer_sdp = str(payload.get("sdp") or "")
    if answer_sdp.strip():
        try:
            await peer_call(
                "pc.setRemote",
                {
                    "sessionId": _sid(session),
                    "leg": worker_leg,
                    "type": "answer",
                    "sdp": answer_sdp,
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.warn(
                f"{leg._label()}: loser end-call setRemote failed "
                f"session={session.get('sessionId')}: {exc}"
            )
    call_id = (
        wpc._normalize_call_id(payload.get("callId"))
        or wpc._leg_call_id(session, str(leg.ident or ""))
    )
    try:
        send_dc_json(
            session,
            {"msgType": "signaling", "action": "end-call", "callId": call_id},
            leg=worker_leg,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn(
            f"{leg._label()}: bare end-call after answer failed "
            f"session={session.get('sessionId')}: {exc}"
        )
    log.info(
        f"{leg._label()}: loser END-CALL answer applied session={session.get('sessionId')} "
        f"bytes={len(answer_sdp)} via=worker"
    )


async def answer_end_call_offer(
    session: dict[str, Any],
    payload: dict[str, Any],
    *,
    leg: str = "pc1",
) -> None:
    # Answer the offer the phone set as its local description. Narrowing or
    # restamping mids here makes the answer a different SDP, and the phone
    # rejects it ("wrong state" / m-line order). The next call on that PC dies.
    offer_sdp = str(payload.get("sdp") or "")
    pc = wpc._leg_pc(session, leg)
    worker_leg = getattr(pc, "leg", "pc1")
    session["endCallRenegotiating"] = True
    session[wpc._leg_ending_key(leg)] = True
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": _sid(session),
            "leg": worker_leg,
            "type": "offer",
            "sdp": offer_sdp,
            "skipPin": True,
        },
    )
    result = await peer_call(
        "pc.createAnswer", {"sessionId": _sid(session), "leg": worker_leg}
    )
    answer_sdp = str(result.get("sdp") or "")
    call_id = wpc._normalize_call_id(payload.get("callId")) or wpc._call_id_for_leg(
        session, worker_leg
    )
    answer_payload = {
        "type": "answer",
        "from": payload.get("to") or session.get("to"),
        "to": payload.get("from") or session.get("from"),
        "sessionId": session.get("sessionId"),
        "sdp": answer_sdp,
    }
    if call_id is not None:
        answer_payload["callId"] = call_id
    send_dc_json(
        session,
        wpc._with_call_id(
            {
                "msgType": "signaling",
                "action": "end-call",
                "payload": answer_payload,
            },
            call_id,
        ),
        leg=worker_leg,
    )
    log.info(
        f"PC: END-CALL ANSWER sent session={session.get('sessionId')} "
        f"leg={leg} bytes={len(answer_sdp)} via=worker"
    )
    session["endCallRenegotiating"] = False
    session[wpc._leg_ending_key(leg)] = False


async def answer_callee_http_offer(
    leg: Any, sdp: str, candidates: Optional[list[Any]] = None
) -> dict[str, Any]:
    """Android POSTed a new offer instead of answering the DC invite.

    Replace the peer on ``callee:<ident>``. A local aiortc PC is not a leg
    ``bridge.start`` can see, so the bridge looks up ``pc2`` and misses.
    ``set_remote`` of the offer is the answer; str0m negotiates the phone's
    m=audio there. Do not create a local data channel first.
    """
    session = leg.session
    session_id = _sid(session)
    worker_leg = f"callee:{leg.ident}"
    old_leg = str(getattr(leg.pc, "leg", "") or "")
    if old_leg.startswith("callee:"):
        worker_leg = old_leg
    loop = asyncio.get_running_loop()
    session["eventLoop"] = loop
    session["mediaWorker"] = True
    old_dc_fut = getattr(leg, "dc_open_fut", None)
    leg.dc_open_fut = loop.create_future()
    if old_dc_fut is not None and not old_dc_fut.done():
        wpc._resolve_future(old_dc_fut, False)
    created = await peer_call(
        "pc.create",
        {
            "sessionId": session_id,
            "leg": worker_leg,
            "iceServers": _ice_pc1(),
            "replace": True,
        },
    )
    pc = WorkerPc(
        session_id, worker_leg, epoch=int((created or {}).get("epoch") or 0)
    )
    old = leg.pc
    leg.pc = pc
    leg.dc = None
    if session.get("pcCallee") is old:
        session["pcCallee"] = pc
    if session.get("pc2") is old:
        session["pc2"] = pc
    offer_sdp = str(sdp or "")
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": session_id,
            "leg": worker_leg,
            "type": "offer",
            "sdp": offer_sdp,
        },
    )
    applied = await add_ice_candidates_to_pc(
        session, pc, candidates or [], label=f"PC-callee[{leg.ident}]"
    )
    result = await peer_call(
        "pc.createAnswer",
        {"sessionId": session_id, "leg": worker_leg},
    )
    answer_sdp = str(result.get("sdp") or "")
    try:
        from client_ingress import _narrow_telephony_audio_sdp, ensure_telephone_event_sdp

        answer_sdp = _narrow_telephony_audio_sdp(answer_sdp)
        answer_sdp = ensure_telephone_event_sdp(answer_sdp, offer_sdp)
    except Exception:  # noqa: BLE001
        pass
    answer_sdp = wpc.ensure_bundle_all_mids(answer_sdp)
    try:
        ice_out = await peer_call(
            "pc.localIce",
            {
                "sessionId": session_id,
                "leg": worker_leg,
                "waitRelay": True,
                "timeoutMs": 3500,
            },
            timeout=8.0,
        )
        ice = list((ice_out or {}).get("candidates") or [])
    except Exception:  # noqa: BLE001
        ice = []
    if not ice:
        ice = _with_sdp_mids(answer_sdp, result.get("candidates"))
    ice = wpc.prefer_srflx_and_relay(ice)
    answer_sdp = wpc.embed_candidates_in_sdp(answer_sdp, ice)
    log.info(
        f"PC-callee[{leg.ident}]: reminted worker PC for HTTP offer "
        f"session={session.get('sessionId')} leg={worker_leg} "
        f"bytes={len(answer_sdp)} applied={applied}"
    )
    return {"sdp": answer_sdp, "candidates": ice, "applied": applied}


async def ringleg_create_offer(leg: Any) -> dict[str, Any]:
    session = leg.session
    session_id = _sid(session)
    worker_leg = f"callee:{leg.ident}"
    loop = asyncio.get_running_loop()
    session["eventLoop"] = loop
    session["mediaWorker"] = True
    leg.dc_open_fut = loop.create_future()
    created = await peer_call(
        "pc.create",
        {
            "sessionId": session_id,
            "leg": worker_leg,
            "iceServers": _ice_pc1(),
            "createDataChannel": True,
            "replace": True,
        },
    )
    pc = WorkerPc(
        session_id, worker_leg, epoch=int((created or {}).get("epoch") or 0)
    )
    leg.pc = pc
    result = await peer_call(
        "pc.createOffer", {"sessionId": session_id, "leg": worker_leg}
    )
    sdp = str(result.get("sdp") or "")
    ice = _with_sdp_mids(sdp, result.get("candidates"))
    sdp = wpc.embed_candidates_in_sdp(sdp, ice)
    try:
        from client_ingress import _narrow_telephony_audio_sdp

        sdp = _narrow_telephony_audio_sdp(sdp)
    except Exception:  # noqa: BLE001
        pass
    sdp = wpc.ensure_bundle_all_mids(sdp)
    leg.invite = {"sdp": sdp, "candidates": ice}
    mids = ",".join(sorted({str(c.get("sdpMid") or "-") for c in ice})) or "-"
    log.info(
        f"{leg._label()}: invite session={session_id} bytes={len(sdp)} "
        f"candidates={len(ice)} sdpMid={mids} via=worker {wpc.sdp_media_summary(sdp)}"
    )
    return leg.invite


async def ringleg_apply_http_answer(
    leg: Any, sdp: str, candidates: Optional[list[Any]] = None
) -> None:
    ans = str(sdp or "")
    merged = wpc.merge_ice_array_and_sdp(ans, candidates)
    leg.add_remote_ice(merged)
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": _sid(leg.session),
            "leg": getattr(leg.pc, "leg", f"callee:{leg.ident}"),
            "type": "answer",
            "sdp": ans,
        },
    )
    applied = await add_ice_candidates_to_pc(
        leg.session, leg.pc, wpc.prefer_srflx_and_relay(merged), label=leg._label()
    )
    log.info(
        f"{leg._label()}: setRemote HTTP answer session={leg.session.get('sessionId')} "
        f"bytes={len(ans)} applied={applied} via=worker"
    )


async def ringleg_send_ring(leg: Any, timeout: float) -> str:
    session = leg.session
    await wpc.wait_until_callee_rungable(session, timeout)
    worker_leg = getattr(leg.pc, "leg", f"callee:{leg.ident}")
    result = await peer_call(
        "pc.createOffer",
        {
            "sessionId": _sid(session),
            "leg": worker_leg,
            "withAudio": True,
            "rotateAudio": False,
            "narrowG711": True,
        },
    )
    _drop_stale_callback_ring(session)
    sdp = str(result.get("sdp") or "")
    if "m=audio" not in sdp:
        raise RuntimeError(
            f"{leg._label()}: RING offer has no m=audio bytes={len(sdp)}"
        )
    ice = _with_sdp_mids(sdp, result.get("candidates"))
    sdp = wpc.embed_candidates_in_sdp(sdp, ice)
    call_id = wpc._allocate_leg_call_id(session, str(leg.ident or ""))
    import identity

    route = session.get("route") or {}
    cli = identity.callkit_handle(
        route.get("callerId") or session.get("callerId") or ""
    )
    from_label = cli or identity.callkit_handle(session.get("from"))
    payload = {
        "msgType": "signaling",
        "callId": call_id,
        "payload": {
            "type": "offer",
            "from": from_label,
            "to": leg.ident,
            "sessionId": leg.signaling_session_id,
            "sdp": sdp,
            "candidates": ice,
            "callId": call_id,
            "label": from_label,
            "isCall": True,
        },
    }
    send_dc_json(session, payload, leg=worker_leg)
    leg.ring_sent = True
    try:
        import time as _time

        leg.ring_sent_at = _time.monotonic()
    except Exception:  # noqa: BLE001
        pass
    log.info(
        f"{leg._label()}: RING offer sent session={session.get('sessionId')} "
        f"callId={call_id} bytes={len(sdp)} via=worker"
    )
    wpc._note_dc_ring_sent(
        session, str(leg.ident or ""), sdp, ice, wallet=getattr(leg, "wallet", None)
    )
    try:
        answer_sdp = await asyncio.wait_for(asyncio.shield(leg.pickup_fut), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise RuntimeError(f"{leg._label()}: RING answer timeout") from exc
    return str(answer_sdp or "")


async def ringleg_complete_pickup(leg: Any, answer_sdp: str) -> None:
    session = leg.session
    worker_leg = getattr(leg.pc, "leg", f"callee:{leg.ident}")
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": _sid(session),
            "leg": worker_leg,
            "type": "answer",
            "sdp": str(answer_sdp),
        },
    )
    if leg.pickup_candidates:
        await add_ice_candidates_to_pc(
            session, leg.pc, leg.pickup_candidates, label=leg._label()
        )
    session["calleeRingAnswered"] = True
    session["pc2OfferReady"] = True
    wait = await peer_call(
        "pc.waitConnected",
        {"sessionId": _sid(session), "leg": worker_leg, "timeoutMs": 8000},
    )
    session["pc2Connected"] = bool(wait.get("ok"))
    await _bridge_media(session)


async def answer_callee_ring_offer(
    session: dict[str, Any], payload: dict[str, Any]
) -> None:
    """Apply callee callback RING offer; hold answer until PC1 picks up."""
    pc = session.get("pcCallee") or session.get("pc2")
    if pc is None:
        raise RuntimeError("PC-callee missing for RING offer")
    worker_leg = getattr(pc, "leg", "pc2")
    session_id = _sid(session)
    # Same bytes iOS set as its local offer. A narrowed copy produces an
    # answer iOS rejects on setRemote.
    offer_sdp = str(payload.get("sdp") or "")
    ident = worker_leg.split(":", 1)[1] if str(worker_leg).startswith("callee:") else str(session.get("to") or "")
    wpc._note_leg_call_id(session, f"callee:{ident}", payload)
    call_id = wpc._normalize_call_id(payload.get("callId")) or wpc._call_id_for_leg(
        session, f"callee:{ident}"
    )
    if call_id is None:
        call_id = wpc._allocate_leg_call_id(session, ident)
    send_dc_json(
        session,
        wpc._with_call_id(
            {
                "msgType": "call",
                "action": "ack",
                "ackFor": "ring",
            },
            call_id,
        ),
        leg=worker_leg,
    )
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": session_id,
            "leg": worker_leg,
            "type": "offer",
            "sdp": offer_sdp,
        },
    )
    await add_ice_candidates_to_pc(
        session, pc, payload.get("candidates") or [], label="PC-callee"
    )
    result = await peer_call(
        "pc.createAnswer",
        {"sessionId": session_id, "leg": worker_leg},
    )
    answer_sdp = str(result.get("sdp") or "")
    ice = _with_sdp_mids(answer_sdp, result.get("candidates"))
    answer_sdp = wpc.embed_candidates_in_sdp(answer_sdp, ice)
    session["pendingCalleeAnswerSdp"] = answer_sdp
    session["pendingCalleeAnswerIce"] = ice
    session["pc2OfferReady"] = True
    if str(getattr(pc, "connectionState", "") or "").lower() == "connected":
        session["pc2Connected"] = True
    log.info(
        f"PC-callee: held RING answer session={session.get('sessionId')} "
        f"bytes={len(answer_sdp)} via=worker (flush after PC1 pickup)"
    )


async def pc1_audio_ring_and_answer(
    session: dict[str, Any], *, timeout: float = 60.0
) -> None:
    """RING original caller on PC1 after callee-originated audio RING."""
    await wpc.wait_until_callee_rungable(session, timeout)
    if wpc._callee_ending(session):
        raise RuntimeError("PC1 RING answer timeout")
    session_id = _sid(session)
    loop = asyncio.get_running_loop()
    session["eventLoop"] = loop
    session["pc1RingAnswerFut"] = loop.create_future()
    session["pc1Connected"] = False
    result = await peer_call(
        "pc.createOffer",
        {
            "sessionId": session_id,
            "leg": "pc1",
            # Reopen the inactive hangup m-line. rotateAudio is a separate
            # SSRC reset and mints an RTX ssrc Android rejects.
            "withAudio": True,
            "rotateAudio": False,
            "narrowG711": True,
        },
    )
    sdp = str(result.get("sdp") or "")
    if "a=sendrecv" not in sdp and "a=sendonly" not in sdp:
        raise RuntimeError(
            f"PC1: callback offer is not an incoming call "
            f"session={session.get('sessionId')} {wpc.sdp_media_summary(sdp)}"
        )
    ice = _with_sdp_mids(sdp, result.get("candidates"))
    sdp = wpc.embed_candidates_in_sdp(sdp, ice)
    call_id = wpc._call_id_for_leg(session, "pc1")
    if call_id is None:
        # This offer is what the caller adopts. It must not be a callee RING id.
        call_id = wpc._allocate_leg_call_id(session, "pc1")
        session["legCallId:pc1"] = call_id
    import identity

    from_label = identity.callkit_handle(session.get("to"))
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
        leg="pc1",
    )
    log.info(
        f"PC1: callback RING offer sent session={session.get('sessionId')} "
        f"bytes={len(sdp)} via=worker {wpc.sdp_media_summary(sdp)}"
    )
    wpc._note_dc_ring_sent(
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
    await peer_call(
        "pc.setRemote",
        {
            "sessionId": session_id,
            "leg": "pc1",
            "type": "answer",
            "sdp": str(answer_sdp),
        },
    )
    log.info(
        f"PC1: callback RING answer applied session={session.get('sessionId')} "
        f"bytes={len(answer_sdp)} via=worker"
    )
    wait = await peer_call(
        "pc.waitConnected",
        {"sessionId": session_id, "leg": "pc1", "timeoutMs": 8000},
    )
    session["pc1Connected"] = bool(wait.get("ok"))
    session["pc2Connected"] = True
    session["pc2OfferReady"] = True


async def ringleg_close(leg: Any, *, force: bool = False) -> None:
    if leg.promoted and not force:
        return
    session = getattr(leg, "session", None) or {}
    ident = str(getattr(leg, "ident", "") or "")
    dc = leg.dc
    if isinstance(dc, WorkerDc):
        dc.readyState = "closed"
    by_id = session.get("dcByIdentity") if isinstance(session, dict) else None
    if isinstance(by_id, dict) and ident:
        stored = by_id.get(ident)
        if isinstance(stored, WorkerDc):
            stored.readyState = "closed"
        by_id.pop(ident, None)
    pc = leg.pc
    leg.pc = None
    leg.dc = None
    if pc is None:
        return
    try:
        await pc.close()
    except Exception as exc:  # noqa: BLE001
        log.warn(f"{leg._label()}: close failed: {exc}")
