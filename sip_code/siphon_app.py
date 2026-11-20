"""Arnacon SIPhon edge — Kamailio behavioral parity for webrtc-service + SBC."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import socket
import sys
import threading
import time
import uuid


def _pin_stdlib_http() -> None:
    """Force stdlib http.* into sys.modules.

    siphon-http registers its addon as sys.modules['http'] (and may re-bind it on
    `from siphon import http`). That shadows the stdlib package and breaks
    requests/urllib3 (`http.client`). Load stdlib by file path so finders cannot
    hand us the siphon shim again.
    """
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

# Ensure policy.py resolves next to this script when mounted in the container.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from siphon import b2bua, log, proxy, registrar, rtpengine

_pin_stdlib_http()
import policy

# Register secnum HTTPS /notify (siphon-http). Keep import side-effects only.
import client_ingress  # noqa: F401
import webrtc_pc_worker  # noqa: F401 — siphon.peer event pump
_pin_stdlib_http()


def _uri_user(uri) -> str:
    if uri is None:
        return ""
    user = getattr(uri, "user", None)
    if user:
        return str(user)
    text = str(uri)
    if text.startswith("sip:") or text.startswith("sips:"):
        text = text.split(":", 1)[1]
    if "@" in text:
        return text.split("@", 1)[0]
    return text


def _uri_host(uri) -> str:
    if uri is None:
        return ""
    host = getattr(uri, "host", None)
    if host:
        return str(host)
    text = str(uri)
    if "@" in text:
        return text.split("@", 1)[1].split(";", 1)[0].split(">", 1)[0]
    return ""


def _call_id(call) -> str:
    return str(getattr(call, "call_id", None) or getattr(call, "id", "") or "")


def _call_header(call, name: str) -> str:
    try:
        if hasattr(call, "get_header"):
            return str(call.get_header(name) or "")
        if hasattr(call, "header"):
            return str(call.header(name) or "")
    except Exception:  # noqa: BLE001
        return ""
    return ""


_INVITE_DUMP_HEADERS = (
    "Via",
    "From",
    "To",
    "Call-ID",
    "CSeq",
    "Contact",
    "Max-Forwards",
    "Route",
    "Record-Route",
    "Diversion",
    "History-Info",
    "P-Asserted-Identity",
    "P-Preferred-Identity",
    "Remote-Party-ID",
    "Privacy",
    "Reason",
    "Referred-By",
    "User-Agent",
    "Supported",
    "Allow",
    "Content-Type",
    "Content-Length",
)


def _log_invite_headers(call, ruri: str) -> None:
    """First value of each header. Siphon Call has no header iterator."""
    lines = [f"INVITE {ruri} SIP/2.0"]
    for name in _INVITE_DUMP_HEADERS:
        value = _call_header(call, name).replace("\r", " ").replace("\n", " ")
        if value:
            lines.append(f"{name}: {value}")
    log.info("INVITE HEADERS\n" + "\n".join(lines))


def _reply_body(reply) -> str:
    body = getattr(reply, "body", None) or b""
    if isinstance(body, bytes):
        return body.decode(errors="replace")
    return str(body)


def _call_body_text(call) -> str:
    try:
        raw = call.body if hasattr(call, "body") else None
        if callable(raw):
            raw = raw()
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).decode(errors="replace")
        if isinstance(raw, str):
            return raw
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _call_user_agent(call) -> str:
    return (
        _call_header(call, "User-Agent") or _call_header(call, "User-agent") or ""
    ).strip()


def _sdp_audio_mline(sdp: str) -> str:
    return next(
        (ln.strip() for ln in str(sdp or "").splitlines() if ln.startswith("m=audio")),
        "",
    )


def _sdp_media_kind(sdp: str) -> str:
    """webrtc = ICE/DTLS. sip-rtp = plain RTP/AVP (Android/SBC/PSTN)."""
    text = str(sdp or "")
    if not text.strip():
        return "none"
    if (
        "a=ice-ufrag:" in text
        or "a=fingerprint:" in text
        or "UDP/TLS/RTP/SAVPF" in text
    ):
        return "webrtc"
    return "sip-rtp"


def _log_full_sdp(label: str, sdp: str, *, extra: str = "") -> None:
    del extra
    client_ingress._log_sdp(label, sdp)


def _invite_client_hint(call_id: str, ua: str) -> str:
    cid = str(call_id or "")
    ual = str(ua or "").lower()
    if "android" in ual or "@ARNACON" in cid:
        return "android-sip"
    return "-"


# Headers we always try to dump for SBC-bound INVITE previews.
_SBC_DUMP_HEADERS = (
    "Via",
    "From",
    "To",
    "Call-ID",
    "CSeq",
    "Contact",
    "Max-Forwards",
    "Route",
    "Record-Route",
    "Content-Type",
    "Content-Length",
    "Allow",
    "Supported",
    "Require",
    "User-Agent",
    "Privacy",
    "Remote-Party-ID",
)


def _log_sbc_invite_preview(call, dial: policy.SbcDialPlan) -> None:
    """Dump Request-Line + headers + SDP as seen on the call before dial().

    B2BUA may still rewrite Via/Contact/CSeq on the wire B-leg; this is the
    closest script-level view of what we are about to send toward the SBC.
    """
    lines = [
        f"INVITE {dial.target_uri} SIP/2.0",
        f"# next_hop={dial.next_hop_uri}",
        f"# shim={dial.via_shim} wire_transport={dial.wire_transport}",
        f"# signaling_transport={dial.signaling_transport} provider={dial.provider}",
        "# header_policy=sip-trunk-edge@2026 (strips X-* / P-* from B-leg)",
    ]
    for name in _SBC_DUMP_HEADERS:
        try:
            value = call.get_header(name) if hasattr(call, "get_header") else None
        except Exception:  # noqa: BLE001
            value = None
        if value:
            lines.append(f"{name}: {value}")

    # Fallbacks when get_header misses identity fields.
    if not any(line.startswith("From:") for line in lines):
        lines.append(f"From: <{getattr(call, 'from_uri', '')}>")
    if not any(line.startswith("To:") for line in lines):
        lines.append(f"To: <{dial.to_header_uri()}>")
    if not any(line.startswith("Call-ID:") for line in lines):
        lines.append(f"Call-ID: {_call_id(call)}")

    body = b""
    try:
        raw_body = call.body if hasattr(call, "body") else None
        if callable(raw_body):
            raw_body = raw_body()
        if isinstance(raw_body, (bytes, bytearray)):
            body = bytes(raw_body)
        elif isinstance(raw_body, str):
            body = raw_body.encode()
    except Exception:  # noqa: BLE001
        body = b""

    if body:
        if not any(line.lower().startswith("content-type:") for line in lines):
            lines.append("Content-Type: application/sdp")
        lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append(body.decode(errors="replace"))
    else:
        lines.append("Content-Length: 0")
        lines.append("")
        lines.append("# (no body on call object after rtpengine.offer)")

    log.info("SBC_TO INVITE preview (pre-dial):\n" + "\n".join(lines))


def _header_user(call, name: str) -> str:
    raw = _call_header(call, name)
    if not raw:
        return ""
    parsed = policy.parse_sip_uri(str(raw))
    if parsed:
        return parsed[0]
    return ""


def _clean_pstn_user(user: str) -> str:
    return policy.strip_plus_and_domain_suffix(user) or str(user or "")


def _apply_openai_leg_identities(call, to_user: str, openai_uri: str) -> None:
    """B-leg To = dialed DID. R-URI (dial) stays the OpenAI project.

    OpenAI copies To-user into dialedNumber. Pinning To to proj_ made
    the webhook show the project id. Do not rewrite the From user.

    TLS Contact/From are otherwise the VPC bind address (advertised_address).
    OpenAI sends in-dialog requests to Contact, so this leg pins the public IP.
    Other trunks stay on the bind address.
    """
    del openai_uri  # routing is call.dial(project uri), not To
    did = _clean_pstn_user(to_user)
    if not did:
        log.warn("OPENAI: empty DID; leaving To unchanged")
    else:
        host = policy.local_domain() or policy.local_bind_ip()
        try:
            if hasattr(call, "set_to_user"):
                call.set_to_user(did)
            if host and hasattr(call, "set_to_host"):
                call.set_to_host(host)
            log.info(f"OPENAI: B-leg To={did}@{host}")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"OPENAI: set To failed: {exc}")
    public = policy.local_public_ip()
    if not public:
        log.warn("OPENAI: no public IP; Contact stays the bind address")
        return
    try:
        if hasattr(call, "set_from_host"):
            call.set_from_host(public)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"OPENAI: set From host failed: {exc}")
    contact = f"sip:{public}:5061;transport=tls"
    try:
        if hasattr(call, "set_contact_uri"):
            call.set_contact_uri(contact)
            log.info(f"OPENAI: B-leg Contact={contact} From-host={public}")
        else:
            log.warn("OPENAI: set_contact_uri missing; Contact stays the bind address")
    except Exception as exc:  # noqa: BLE001
        log.warn(f"OPENAI: set Contact failed: {exc}")


def _openai_ipv4_next_hop(uri: str) -> str:
    """A record only. Siphon shuffles A and AAAA and this host has no IPv6 route."""
    host = _uri_host(uri).split(":", 1)[0].strip("[]")
    if not host:
        raise OSError(f"openai dial has no host: {uri}")
    infos = socket.getaddrinfo(host, 5061, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"no IPv4 for {host}")
    ip = infos[0][4][0]
    return f"sip:{ip}:5061;transport=tls"


def _dial_openai_uri(call, uri: str) -> None:
    try:
        hop = _openai_ipv4_next_hop(uri)
    except OSError as exc:
        log.error(f"OPENAI: no IPv4 for {uri}: {exc}")
        call.reject(503, "OpenAI Unreachable")
        return
    log.info(f"OPENAI: dial {uri} via {hop}")
    call.dial(uri, timeout=60, next_hop=hop)


def _lookup_contact_for_user(user: str):
    domain = policy.local_domain()
    candidates = []
    clean = policy.strip_plus_and_domain_suffix(user)
    if clean:
        candidates.append(f"sip:{clean}@{domain}")
    if user and user != clean:
        candidates.append(f"sip:{user}@{domain}")
    for aor in candidates:
        contacts = registrar.lookup(aor)
        if contacts:
            return contacts[0]
    return None


@proxy.on_request("OPTIONS")
def on_options(request):
    request.reply(200, "OK")


@proxy.on_request("REGISTER")
def on_register(request):
    to_user = _uri_user(request.to_uri) or _uri_user(request.from_uri)
    log.info(
        f"REGISTER: user={to_user} from={request.source_ip} "
        f"transport={getattr(request, 'transport', '')}"
    )
    registrar.save(request)


@b2bua.on_invite
async def on_invite(call):
    _pin_script_loop()
    await _ensure_park_uas()
    from_user = _uri_user(call.from_uri)
    to_user = _uri_user(call.to_uri)
    ruri_user = _uri_user(call.ruri) or to_user
    from_host = _uri_host(call.from_uri)
    to_host = _uri_host(call.to_uri)
    source_ip = str(getattr(call, "source_ip", "") or "")
    call_id = _call_id(call)
    invite_sdp = _call_body_text(call)
    invite_ua = _call_user_agent(call)
    invite_media = _sdp_media_kind(invite_sdp)
    invite_mline = _sdp_audio_mline(invite_sdp)
    invite_hint = _invite_client_hint(call_id, invite_ua)

    log.info(
        f"INVITE: {from_user}@{from_host} -> {ruri_user}@{to_host} "
        f"src={source_ip} call_id={call_id} ua={invite_ua or '-'} "
        f"client={invite_hint} media={invite_media} {invite_mline or 'm=audio?'} "
        f"cl={_call_header(call, 'Content-Length') or '-'}"
    )
    _log_invite_headers(call, str(getattr(call, "ruri", "") or f"sip:{ruri_user}@{to_host}"))
    _log_full_sdp("INVITE SDP (from peer)", invite_sdp)

    # --- /notify hairpin: HTTP ingress → local B2BUA → SBC ---
    ingress_id = _call_header(call, client_ingress.SBC_HAIRPIN_HEADER).strip()
    if ingress_id or ruri_user == client_ingress.SBC_HAIRPIN_USER:
        number = _call_header(call, client_ingress.SBC_HAIRPIN_NUMBER_HEADER).strip() or to_user
        sbc = _call_header(call, client_ingress.SBC_HAIRPIN_ADDRESS_HEADER).strip()
        log.info(
            f"SBC_HAIRPIN: ingress={ingress_id} number={number} sbc={sbc} call_id={call_id}"
        )
        # Preserve ingress id / NG flag for on_answer / on_failure correlation.
        try:
            call.set_header(client_ingress.SBC_HAIRPIN_HEADER, ingress_id)
            ng_flag = _call_header(call, client_ingress.SBC_HAIRPIN_NG_HEADER).strip()
            if ng_flag:
                call.set_header(client_ingress.SBC_HAIRPIN_NG_HEADER, ng_flag)
        except Exception:  # noqa: BLE001
            pass
        await _handle_outbound_to_sbc(
            call,
            number,
            from_user,
            from_host,
            sbc,
            number_only=True,
            hairpin_ingress_id=ingress_id,
        )
        return

    dest_guess = _clean_pstn_user(ruri_user or to_user)
    pending_xfer = client_ingress.peek_pending_xfer(dest_guess)
    if pending_xfer and not policy.is_from_sbc(source_ip):
        # Fallback if a park INVITE ever re-enters this process. The live
        # path is the Python UAS on 5070, not @b2bua.on_invite.
        client_ingress.take_pending_xfer(dest_guess)
        body = _call_body_text(call) or pending_xfer.get("sdp") or ""
        log.info(
            f"INVITE/XFER: park B-leg to={pending_xfer.get('to')} "
            f"from={pending_xfer.get('from')} a_leg={pending_xfer.get('a_leg')} "
            f"call_id={call_id} src={source_ip or '-'} sdp_bytes={len(body)}"
        )
        await _handle_inbound_from_sbc(
            call,
            pending_xfer.get("from") or _clean_pstn_user(from_user),
            pending_xfer.get("to") or dest_guess,
            pending_xfer.get("to") or dest_guess,
            call_id,
            route=pending_xfer.get("route"),
            refer_transfer=False,
            sbc_sdp=body,
            from_tag=str(pending_xfer.get("from_tag") or ""),
            b2bua_call_id=str(pending_xfer.get("a_leg") or ""),
            xfer_park=True,
        )
        return

    # --- inbound from PSTN gateway ---
    # Trunks still force 972….cellactm.global / cellactl.global on the user.
    # Strip to the DID. Do not pin Secnum from that leftover label.
    if policy.is_from_sbc(source_ip):
        raw_to = ruri_user or to_user
        dest = _clean_pstn_user(raw_to)
        src = _clean_pstn_user(from_user)
        to_domain = policy.extract_domain_from_identity(raw_to)
        diversion = policy.strip_plus_and_domain_suffix(_header_user(call, "Diversion"))
        parsed_to = client_ingress.logic_client.parse_address(dest)
        parsed_from = client_ingress.logic_client.parse_address(src)
        owners = policy.providers_for_ingress_ip(source_ip)
        pin = owners[0] if len(owners) == 1 else ""
        inbound_route = await client_ingress.logic_client.resolve_destination(
            parsed_to,
            parsed_from,
            origin="sbc",
            to=dest,
            from_id=src,
            session_id=str(call_id or ""),
            kind="inbound",
            diversion=diversion,
            to_domain=to_domain,
            pin_sp=pin,
        )
        rk = str(inbound_route.get("route") or "")
        log.info(
            f"INVITE/INBOUND: {rk} to={dest} raw={ruri_user or to_user} "
            f"sp={inbound_route.get('logicSp') or '-'} pin={pin or '-'} "
            f"media={_sdp_media_kind(_call_body_text(call))} "
            f"ua={_call_user_agent(call) or '-'}"
        )
        if rk == "reject":
            call.reject(
                int(inbound_route.get("statusCode") or 404),
                str(inbound_route.get("reason") or "Not Found")[:64],
            )
            return
        if rk in ("openai-sip", "openai", "ivr"):
            await _handle_openai(call, route=inbound_route)
            return
        if rk == "external-sip":
            await _hairpin_external_sip(call, inbound_route, src, dest)
            return
        if rk == "sbc":
            # Nobody claimed this DID. Already on the trunk, so do not send
            # the INVITE back out the SBC.
            log.info(f"INVITE/INBOUND: 403 Forbidden to={dest}")
            call.reject(403, "Forbidden")
            return
        await _handle_inbound_from_sbc(
            call, src, dest, dest, call_id, route=inbound_route
        )
        return

    dest = _clean_pstn_user(ruri_user)
    src = _clean_pstn_user(from_user)
    # Not a trunk. PSTN outbound is only for locally registered UAs — never
    # "from=1001" / SQL-in-From scanners. No From allowlist.
    if not (
        _lookup_contact_for_user(from_user) or _lookup_contact_for_user(src)
    ):
        log.warn(
            f"INVITE/ROUTE: reject unregistered origin src={source_ip or '-'} "
            f"from={from_user!r} to={ruri_user!r} ua={invite_ua or '-'}"
        )
        call.reject(403, "Forbidden")
        return
    parsed_to = client_ingress.logic_client.parse_address(dest)
    parsed_from = client_ingress.logic_client.parse_address(src)
    route = await client_ingress.logic_client.resolve_destination(
        parsed_to,
        parsed_from,
        origin="sip",
        to=dest,
        from_id=src,
        session_id=str(call_id or ""),
        kind="outbound",
    )
    rk = str(route.get("route") or "")
    log.info(
        f"INVITE/ROUTE: {rk} to={dest} raw={ruri_user} host={route.get('host') or '-'} "
        f"targets={len(route.get('targets') or [])} "
        f"media={_sdp_media_kind(_call_body_text(call))} "
        f"ua={_call_user_agent(call) or '-'}"
    )
    if rk == "reject":
        call.reject(
            int(route.get("statusCode") or 403),
            str(route.get("reason") or "Forbidden")[:64],
        )
        return
    if rk in ("openai-sip", "openai", "ivr"):
        await _handle_openai(call, route=route)
        return
    if rk == "external-sip":
        await _hairpin_external_sip(call, route, src, dest)
        return
    if rk == "sbc":
        number = str(route.get("number") or dest)
        sbc = str(route.get("host") or route.get("sbcAddress") or "").strip()
        if not sbc:
            sbc = policy.determine_sbc_for_number(number, from_user, from_host) or ""
        if not sbc:
            log.error(f"SBC_TO: route missing host for {number}")
            call.reject(500, "Server Error - Failed to determine SBC for number")
            return
        from_cli = str(route.get("callerId") or "").strip() or from_user
        await _handle_outbound_to_sbc(
            call,
            number,
            from_cli,
            from_host,
            sbc,
            number_only=True,
            privacy=str(route.get("privacy") or ""),
        )
        return
    if rk in ("webrtc", "webrtc-multiring"):
        await _handle_inbound_from_sbc(
            call, src, dest, dest, call_id, route=route
        )
        return

    # --- local registered UA ---
    contact = _lookup_contact_for_user(ruri_user)
    if not contact:
        log.error(f"No local registration for {ruri_user}")
        call.reject(404, "Not Found")
        return
    log.info(f"Local lookup hit for {ruri_user} -> {contact.uri}")
    call.remove_header("P-Asserted-Identity")
    flow = getattr(contact, "flow", None)
    if flow is not None:
        call.dial(str(contact.uri), flow=flow, timeout=60)
    else:
        call.dial(str(contact.uri), timeout=60)


def _session_for_hairpin(ingress_id: str):
    if not str(ingress_id or "").strip():
        return None
    keys = client_ingress._peek_hairpin_ng_keys(ingress_id)
    sid = str((keys or {}).get("session_id") or "").strip()
    if not sid:
        return None
    return client_ingress._get_session(sid)


def _notify_external_sip_uri(session) -> str:
    if not isinstance(session, dict):
        return ""
    route = session.get("route") or {}
    uri = str(route.get("sipUri") or route.get("uri") or "").strip()
    if not uri:
        return ""
    kind = str(
        session.get("productKind") or route.get("productKind") or route.get("route") or ""
    ).strip().lower()
    if kind in client_ingress.logic_client.PRODUCT_ROUTE_KINDS:
        return uri
    if "sip.api.openai.com" in uri.lower():
        return uri
    return ""


async def _dial_notify_external_sip(call, session, uri: str, hairpin_ingress_id: str) -> None:
    """WebRTC /notify -> OpenAI/external-sip. Same B-leg as inbound PSTN IVR.

    Do not use Cellact dial-plan (shim, To=proj_@local, pc2_to_sbc). OpenAI 404s
    that INVITE; inbound succeeds with webrtc/pstn_to_openai and To=proj_@openai.
    """
    route = (session or {}).get("route") or {}
    did = _clean_pstn_user(
        route.get("number")
        or (session or {}).get("recordingDid")
        or (session or {}).get("to")
        or ""
    )
    try:
        if hairpin_ingress_id:
            call.set_header(client_ingress.SBC_HAIRPIN_HEADER, hairpin_ingress_id)
    except Exception:  # noqa: BLE001
        pass
    vm_headers = (session or {}).get("voicemailHeaders")
    if isinstance(vm_headers, dict):
        for hdr_key, hdr_val in vm_headers.items():
            val_s = str(hdr_val or "").strip()
            if not val_s:
                continue
            try:
                call.set_header(str(hdr_key), val_s)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"SBC_TO: set {hdr_key} failed: {exc}")
    # Not webrtc_to_openai: that answer is dtls:passive and PC2/aiortc fails DTLS
    # (ice=completed, connectionState=failed). pc2_to_openai = OpenAI codecs +
    # rtpengine DTLS-active like pc2_to_sbc.
    profile = "pc2_to_openai"
    log.info(
        f"SBC_TO: notify external-sip profile={profile} uri={uri} did={did} "
        f"ingress={hairpin_ingress_id or '-'}"
    )
    try:
        await rtpengine.offer(call, profile=profile)
    except Exception as exc:  # noqa: BLE001
        log.error(f"SBC_TO: external-sip rtpengine.offer failed: {exc}")
        if hairpin_ingress_id:
            client_ingress.fail_notify_call_sync(
                f"rtpengine offer failed: {exc}",
                ingress_id=hairpin_ingress_id,
                cancel_sip=False,
            )
        call.reject(500, "Media Relay Error")
        return
    offered = _call_body_text(call)
    mline = next((ln for ln in offered.splitlines() if ln.startswith("m=audio")), "")
    log.info(
        f"SBC_TO: external-sip offered {mline!r} "
        f"telephone-event={'telephone-event' in offered}"
    )
    _apply_openai_leg_identities(call, did, uri)
    _dial_openai_uri(call, uri)


async def _handle_outbound_to_sbc(
    call,
    number,
    from_user,
    from_host,
    sbc_address,
    number_only,
    hairpin_ingress_id: str = "",
    privacy: str = "",
):
    hairpin_session = _session_for_hairpin(hairpin_ingress_id)
    ext_uri = _notify_external_sip_uri(hairpin_session)
    if ext_uri:
        await _dial_notify_external_sip(
            call, hairpin_session, ext_uri, hairpin_ingress_id
        )
        return
    clean_from = policy.clean_from_user_for_sbc(from_user)
    clean_domain = str(from_host or policy.local_domain()).split(";", 1)[0]
    try:
        dial = policy.build_sbc_dial_plan(
            number,
            sbc_address=sbc_address,
            from_user=from_user,
            from_domain=from_host,
        )
    except ValueError as exc:
        log.error(f"SBC_TO: dial plan failed: {exc}")
        if hairpin_ingress_id:
            client_ingress.fail_notify_call_sync(
                exc, ingress_id=hairpin_ingress_id, cancel_sip=False
            )
        call.reject(500, "Server Error - Failed to determine SBC dial plan")
        return

    call.set_from_user(clean_from)
    call.set_from_host(clean_domain)
    priv = str(privacy or "").strip().lower()
    if priv != "id" and hairpin_session:
        priv = str(((hairpin_session.get("route") or {}).get("privacy") or "")).strip().lower()
    if priv == "id":
        try:
            call.set_header("Privacy", "id")
            log.info(f"SBC_TO: Privacy: id call_id={_call_id(call)}")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"SBC_TO: Privacy header failed: {exc}")
    # Kamailio keeps To user/host as dialed identity (*9225@local); only R-URI
    # points at the SBC. Pin both so B2BUA doesn't rewrite To → sbc IP.
    call.set_to_user(dial.number)
    call.set_to_host(clean_domain)
    # Default B-leg Contact is userless; put CLI in userpart (prod has a user@…).
    if hasattr(call, "set_contact_user") and clean_from:
        try:
            call.set_contact_user(clean_from)
        except Exception:  # noqa: BLE001
            pass
    # Same Call-ID on B-leg so CANCEL / b2bua.terminate can find the dialog.
    if hairpin_ingress_id and hasattr(call, "keep_call_id"):
        try:
            call.keep_call_id()
        except Exception:  # noqa: BLE001
            pass

    # Keep X-Arnacon-* on the A-leg for on_answer/on_failure hairpin correlation.
    # SBC B-leg uses sip-trunk-edge so those never leave the box.
    log.info(
        f"SBC_TO: dial {dial.target_uri} via {dial.next_hop_uri} "
        f"from={clean_from}@{clean_domain} shim={dial.via_shim} "
        f"hairpin={bool(hairpin_ingress_id)}"
    )

    body_text = _call_body_text(call)
    # /notify hairpin may already carry NG-rewritten RTP/AVP (sanitized).
    # Call has no set_body — so we must not run a second rtpengine.offer that
    # re-injects extmap/msid/ssrc the SBC 603s on.
    ng_owned = _call_header(call, client_ingress.SBC_HAIRPIN_NG_HEADER).strip() == "1"
    pre_rewritten = bool(hairpin_ingress_id) and ng_owned
    if pre_rewritten:
        log.info(
            f"SBC_TO: hairpin NG pre-offer present bytes={len(body_text)}; "
            "skip rtpengine.offer"
        )
    else:
        # /notify PC2 uses pc2_to_sbc (keep DTLS); other SBC legs keep webrtc_to_sbc.
        offer_profile = "pc2_to_sbc" if hairpin_ingress_id else "webrtc_to_sbc"
        try:
            await rtpengine.offer(call, profile=offer_profile)
            log.info(
                f"SBC_TO: rtpengine.offer ok profile={offer_profile} "
                f"hairpin={bool(hairpin_ingress_id)} body_bytes={len(_call_body_text(call))}"
            )
        except Exception as exc:  # noqa: BLE001
            log.error(f"SBC_TO: rtpengine offer failed: {exc}")
            if hairpin_ingress_id:
                client_ingress.fail_notify_call_sync(
                    f"rtpengine offer failed: {exc}",
                    ingress_id=hairpin_ingress_id,
                    cancel_sip=False,
                )
            call.reject(500, "Media Relay Error")
            return
        # Best-effort sanitize if this siphon build exposes Call.set_body.
        cleaned = client_ingress.sanitize_pstn_sdp(_call_body_text(call))
        if hasattr(call, "set_body"):
            try:
                call.set_body(cleaned, "application/sdp")
                log.info(f"SBC_TO: sanitized PSTN SDP via set_body bytes={len(cleaned)}")
            except Exception as exc:  # noqa: BLE001
                log.warn(f"SBC_TO: set_body sanitize failed: {exc}")
        elif hairpin_ingress_id:
            log.warn(
                "SBC_TO: Call.set_body missing — SBC may see WebRTC leftovers "
                f"(sanitized would be {len(cleaned)} bytes)"
            )

    try:
        _log_sbc_invite_preview(call, dial)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"SBC_TO: invite preview dump failed: {exc}")

    call.dial(
        dial.target_uri,
        next_hop=dial.next_hop_uri,
        timeout=60,
        header_policy="sip-trunk-edge@2026",
        strip=[
            "P-Asserted-Identity",
            client_ingress.SBC_HAIRPIN_HEADER,
            client_ingress.SBC_HAIRPIN_NUMBER_HEADER,
            client_ingress.SBC_HAIRPIN_ADDRESS_HEADER,
            client_ingress.SBC_HAIRPIN_NG_HEADER,
        ],
    )


def _openai_media_profile(call) -> str:
    """PSTN inbound is already RTP/AVP. webrtc_to_openai assumes ICE/WebRTC."""
    body = _call_body_text(call)
    if "a=ice-ufrag:" in body or "a=fingerprint:" in body or "UDP/TLS/RTP/SAVPF" in body:
        return "webrtc_to_openai"
    return "pstn_to_openai"


async def _hairpin_external_sip(call, route, from_user, to_user):
    uri = str((route or {}).get("sipUri") or (route or {}).get("uri") or "")
    if not uri:
        call.reject(404, "No SIP URI")
        return
    from_user = _clean_pstn_user(from_user)
    to_user = _clean_pstn_user(to_user)
    pai_user = _clean_pstn_user(_uri_user(_call_header(call, "P-Asserted-Identity")))
    if "sip.api.openai.com" in uri:
        call.remove_header("P-Asserted-Identity")
    body = _call_body_text(call)
    from_tag = ""
    try:
        from_tag = client_ingress._sip_header_tag(
            _call_header(call, "From") or _call_header(call, "f")
        )
    except Exception:  # noqa: BLE001
        from_tag = ""
    sess = client_ingress.register_product_session(
        call_id=_call_id(call),
        from_id=from_user,
        to_id=to_user,
        route=route,
        sip_call=call,
        invite_sdp=body,
        from_tag=from_tag,
    )
    if pai_user and isinstance(sess, dict) and not sess.get("sbcFromUser"):
        sess["sbcFromUser"] = pai_user
    profile = _openai_media_profile(call)
    media = _sdp_media_kind(body)
    ua = _call_user_agent(call)
    log.info(
        f"EXTERNAL-SIP: offer profile={profile} sdp_bytes={len(body)} "
        f"uri={uri} from={from_user} to={to_user} "
        f"media={media} ua={ua or '-'} {_sdp_audio_mline(body)}"
    )
    if media == "sip-rtp":
        log.info(
            f"EXTERNAL-SIP: A-leg classic SIP/RTP (not WebRTC) "
            f"from={from_user} to={to_user} ua={ua or '-'}"
        )
    if not body.strip():
        log.error("EXTERNAL-SIP: empty SDP on inbound INVITE")
        call.reject(488, "No SDP")
        return
    _log_full_sdp("EXTERNAL-SIP SDP in (A-leg INVITE)", body)
    if media == "sip-rtp" and hasattr(call, "set_body"):
        cleaned = client_ingress.normalize_sbc_answer_sdp(body)
        if cleaned != body:
            try:
                call.set_body(cleaned, "application/sdp")
                body = cleaned
                log.info(f"EXTERNAL-SIP: normalized PSTN SDP via set_body bytes={len(cleaned)}")
            except Exception as exc:  # noqa: BLE001
                log.warn(f"EXTERNAL-SIP: set_body failed: {exc}")
    try:
        await rtpengine.offer(call, profile=profile)
    except Exception as exc:  # noqa: BLE001
        log.error(f"EXTERNAL-SIP: rtpengine offer failed profile={profile}: {exc}")
        call.reject(500, "Media Relay Error")
        return
    offered = _call_body_text(call)
    _log_full_sdp("EXTERNAL-SIP SDP out (to OpenAI)", offered)
    _apply_openai_leg_identities(call, to_user, uri)
    _dial_openai_uri(call, uri)


async def _handle_openai(call, route=None):
    # Parity with OPENAI_TO_HANDLER: WebRTC -> OpenAI Realtime over TLS, PCMU.
    route = dict(route or {})
    call.remove_header("P-Asserted-Identity")
    body = _call_body_text(call)
    from_tag = ""
    try:
        from_tag = client_ingress._sip_header_tag(
            _call_header(call, "From") or _call_header(call, "f")
        )
    except Exception:  # noqa: BLE001
        from_tag = ""
    profile = _openai_media_profile(call)
    log.info(
        f"OPENAI: offer profile={profile} sdp_bytes={len(body)} "
        f"media={_sdp_media_kind(body)} ua={_call_user_agent(call) or '-'} "
        f"{_sdp_audio_mline(body)}"
    )
    if not body.strip():
        log.error("OPENAI: empty SDP on inbound INVITE")
        call.reject(488, "No SDP")
        return
    try:
        await rtpengine.offer(call, profile=profile)
    except Exception as exc:  # noqa: BLE001
        log.error(f"OPENAI: rtpengine offer failed profile={profile}: {exc}")
        call.reject(500, "Media Relay Error")
        return
    offered = _call_body_text(call)
    mline = next((ln for ln in offered.splitlines() if ln.startswith("m=audio")), "")
    log.info(
        f"OPENAI: offered {mline!r} telephone-event={'telephone-event' in offered}"
    )
    ruri = str(call.ruri or "")
    sip_uri = str(route.get("sipUri") or route.get("uri") or "")
    from_user = _clean_pstn_user(_uri_user(call.from_uri))
    to_user = _clean_pstn_user(_uri_user(call.to_uri) or _uri_user(call.ruri))
    client_ingress.register_product_session(
        call_id=_call_id(call),
        from_id=from_user,
        to_id=to_user,
        route={**route, "route": route.get("route") or "openai-sip"},
        sip_call=call,
        invite_sdp=body,
        from_tag=from_tag,
    )
    target = sip_uri or (ruri if "sip.api.openai.com" in ruri else "")
    if target:
        _apply_openai_leg_identities(call, to_user, target)
        _dial_openai_uri(call, target)
        return
    call.reject(404, "OpenAI target not configured on R-URI")


async def _handle_inbound_from_sbc(
    call,
    from_user,
    to_user,
    ruri_user,
    call_id,
    route=None,
    refer_transfer=False,
    sbc_sdp="",
    from_tag="",
    b2bua_call_id="",
    xfer_park=False,
):
    """SBC→WebRTC: inline wake (no Node :9101 callback, no REGISTER park)."""
    clean_from = policy.strip_plus_and_domain_suffix(from_user)
    clean_to = policy.strip_plus_and_domain_suffix(to_user or ruri_user)
    raw_to = _uri_user(getattr(call, "ruri", "") or "") or _uri_user(getattr(call, "to_uri", "") or "") or to_user or ruri_user
    provider, catalog_domain = policy.resolve_inbound_service_domain(raw_to)
    to_domain = policy.extract_domain_from_identity(raw_to) or catalog_domain
    diversion = policy.strip_plus_and_domain_suffix(_header_user(call, "Diversion"))
    if not from_tag:
        try:
            from_hdr = _call_header(call, "From") or _call_header(call, "f")
            from_tag = client_ingress._sip_header_tag(from_hdr)
        except Exception:  # noqa: BLE001
            from_tag = ""
    if refer_transfer and not from_tag:
        from_tag = "xfer-a"
    if not str(sbc_sdp or "").strip():
        sbc_sdp = _call_body_text(call)
    source_ip = str(getattr(call, "source_ip", "") or "")

    log.info(
        f"RELAY_FROM_SBC: from={clean_from} to={clean_to} domain={to_domain} "
        f"provider={provider} diversion={diversion} "
        f"call_id={call_id} from_tag={from_tag!r} sdp_bytes={len(sbc_sdp)} "
        f"src={source_ip or '-'} refer_transfer={refer_transfer} "
        f"xfer_park={xfer_park} "
        f"(Kamailio-parity UAS — raw NG sbc_to_webrtc, IP Contact)"
    )

    await client_ingress.start_inbound_from_sbc(
        call,
        clean_from=clean_from,
        clean_to=clean_to,
        diversion=diversion,
        call_id=str(call_id or ""),
        from_tag=from_tag,
        sbc_sdp=sbc_sdp,
        to_domain=to_domain,
        provider=provider,
        source_ip=source_ip,
        route=route,
        refer_transfer=refer_transfer,
        b2bua_call_id=b2bua_call_id,
        xfer_park=xfer_park,
    )


# Mobile SBCs retransmit / fork 183s + 200s hard — log/answer once per call.
_early_log_once: set[str] = set()
_final_answered: set[str] = set()
_dup_200_logged: set[str] = set()
_early_lock = threading.Lock()


def _early_clear(call_id: str) -> None:
    cid = str(call_id or "").strip()
    if not cid:
        return
    with _early_lock:
        _early_log_once.discard(cid)
        _final_answered.discard(cid)
        _dup_200_logged.discard(cid)


def _sdp_looks_webrtc(sdp: str) -> bool:
    text = str(sdp or "")
    return ("a=fingerprint" in text or "a=ice-ufrag" in text) and (
        "UDP/TLS/RTP" in text or "RTP/SAVPF" in text or "RTP/SAVP" in text
    )


def _inject_telephone_event_answer(call, reply, answer_sdp: str) -> str:
    """Put RFC 4733 on the SDP we send the A-leg / WebRTC client."""
    offer = ""
    sess = client_ingress.get_session_by_sip_call_id(_call_id(call))
    if sess:
        offer = str(sess.get("ringOfferSdp") or sess.get("inviteSdp") or "")
    if offer and not client_ingress.telephone_event_pt(offer):
        log.warn(
            f"ANSWER: A-leg offer has no telephone-event "
            f"{_sdp_audio_mline(offer)!r} — not injecting TE (client cannot "
            f"insertDTMF). Need telephone-event on the INVITE/offer."
        )
        return answer_sdp
    patched = client_ingress.ensure_telephone_event_sdp(answer_sdp, offer)
    if patched == answer_sdp:
        return answer_sdp
    log.info(
        f"ANSWER: telephone-event injected "
        f"{_sdp_audio_mline(answer_sdp)!r} → {_sdp_audio_mline(patched)!r}"
    )
    setter = getattr(reply, "set_body", None)
    if callable(setter):
        try:
            setter(patched, "application/sdp")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"ANSWER: telephone-event set_body failed: {exc}")
    return patched


@b2bua.on_early_media
async def on_early_media(call, reply):
    """183/180-with-SDP — log once. Do NOT rtpengine.answer on hairpin 183.

    Answering 183 rewrote reply → WebRTC SDP; later "SBC 200" arrived already
    WebRTC (poisoned), on_answer looped, callee went deaf. Anchor on final 200.
    """
    cid = _call_id(call)
    code = getattr(reply, "status_code", None) or getattr(reply, "code", "?")
    reason = getattr(reply, "reason", None) or getattr(reply, "reason_phrase", "") or ""
    body_len = len(_reply_body(reply) or "")
    ingress_id = _call_header(call, client_ingress.SBC_HAIRPIN_HEADER).strip()

    with _early_lock:
        first_log = cid not in _early_log_once
        if first_log:
            _early_log_once.add(cid)
    if first_log:
        log.info(
            f"EARLY: call {cid} {code} {reason} sdp_bytes={body_len} "
            f"hairpin={bool(ingress_id)} (further EARLY for this call suppressed; "
            "no rtpengine.answer on 183 for hairpin)"
        )


@b2bua.on_answer
async def on_answer(call, reply):
    cid = _call_id(call)
    client_ingress.remember_aleg_dialog(cid, call)
    ingress_id = _call_header(call, client_ingress.SBC_HAIRPIN_HEADER).strip()
    if not ingress_id:
        client_ingress.remember_bleg_dialog(cid, reply)
    # Retransmitted / forked 200s — process hairpin final answer once.
    # SBC keeps retransmitting 200 until B-leg ACK lands; do not log-spam.
    if ingress_id:
        with _early_lock:
            if cid in _final_answered:
                if cid not in _dup_200_logged:
                    _dup_200_logged.add(cid)
                    log.info(
                        f"ANSWER: call {cid} duplicate 200 ignored "
                        "(further duplicates silenced)"
                    )
                return
            _final_answered.add(cid)

    reply_sdp = _reply_body(reply)
    log.info(
        f"ANSWER: call {cid} code={getattr(reply, 'status_code', '')} "
        f"media={_sdp_media_kind(reply_sdp)} {_sdp_audio_mline(reply_sdp)}"
    )
    _log_full_sdp("ANSWER SDP in (B-leg 200)", reply_sdp)
    ng_owned = _call_header(call, client_ingress.SBC_HAIRPIN_NG_HEADER).strip() == "1"
    # Israeli hairpin 200 (`8 126` with no a=rtpmap). Dutch and a normal SBC
    # user already name the codec; those stay on rtpengine.answer below.
    if ingress_id and client_ingress.sbc_sdp_missing_static_rtpmap(reply_sdp):
        try:
            answer_sdp = client_ingress.hairpin_media_answer(
                call, reply, ingress_id=ingress_id
            )
        except Exception as exc:  # noqa: BLE001
            log.error(f"SBC_HAIRPIN: NG answer failed: {exc}")
            try:
                await client_ingress.ack_sbc_hairpin(call, reply)
            except Exception as ack_exc:  # noqa: BLE001
                log.warn(f"SBC_HAIRPIN: ACK after NG fail failed: {ack_exc}")
            try:
                from siphon import b2bua as _b2bua

                terminate = getattr(_b2bua, "terminate", None)
                cid = _call_id(call)
                if callable(terminate) and cid:
                    ok = terminate(cid, "media-failed")
                    log.info(f"SBC_HAIRPIN: terminate after NG fail call_id={cid} ok={ok}")
            except Exception as term_exc:  # noqa: BLE001
                log.warn(f"SBC_HAIRPIN: terminate after NG fail: {term_exc}")
            await client_ingress.fail_notify_call(
                f"rtpengine answer failed: {exc}",
                ingress_id=ingress_id,
                cancel_sip=True,
            )
            return
        answer_sdp = _inject_telephone_event_answer(call, reply, answer_sdp)
        log.info(f"ANSWER SDP (NG hairpin) bytes={len(answer_sdp)}\n{answer_sdp}")
        client_ingress.complete_sbc_hairpin_answer(ingress_id, answer_sdp)
        try:
            await client_ingress.ack_sbc_hairpin(call, reply)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"SBC_HAIRPIN: ACK failed: {exc}")
        return
    # Hairpin /notify owns media via NG pre-offer — SIPhon has no rtpengine session.
    if ingress_id and ng_owned:
        try:
            answer_sdp = client_ingress.hairpin_media_answer(
                call, reply, ingress_id=ingress_id
            )
        except Exception as exc:  # noqa: BLE001
            log.error(f"SBC_HAIRPIN: NG answer failed: {exc}")
            # Always ACK the SBC 200 even when media rewrite fails.
            try:
                await client_ingress.ack_sbc_hairpin(call, reply)
            except Exception as ack_exc:  # noqa: BLE001
                log.warn(f"SBC_HAIRPIN: ACK after NG fail failed: {ack_exc}")
            try:
                from siphon import b2bua as _b2bua

                terminate = getattr(_b2bua, "terminate", None)
                cid = _call_id(call)
                if callable(terminate) and cid:
                    ok = terminate(cid, "media-failed")
                    log.info(f"SBC_HAIRPIN: terminate after NG fail call_id={cid} ok={ok}")
            except Exception as term_exc:  # noqa: BLE001
                log.warn(f"SBC_HAIRPIN: terminate after NG fail: {term_exc}")
            await client_ingress.fail_notify_call(
                f"rtpengine answer failed: {exc}",
                ingress_id=ingress_id,
                cancel_sip=True,
            )
            return
        answer_sdp = _inject_telephone_event_answer(call, reply, answer_sdp)
        log.info(f"ANSWER SDP (NG hairpin) bytes={len(answer_sdp)}\n{answer_sdp}")
        client_ingress.complete_sbc_hairpin_answer(ingress_id, answer_sdp)
        try:
            await client_ingress.ack_sbc_hairpin(call, reply)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"SBC_HAIRPIN: ACK failed: {exc}")
        return

    # Hairpin SBC 200 is bare RTP/AVP — normalize before rtpengine.answer
    # (same fix as hairpin_media_answer / raw NG path).
    skip_rtpengine_answer = False
    if ingress_id:
        try:
            raw_sbc = _reply_body(reply)
            # If body is already WebRTC (poisoned by a prior 183 answer), do NOT
            # feed it back into rtpengine.answer — that caused answer loops +
            # callee-deaf one-way audio.
            if _sdp_looks_webrtc(raw_sbc):
                log.warn(
                    f"SBC_HAIRPIN: 200 body already WebRTC bytes={len(raw_sbc)} "
                    "— skip rtpengine.answer (use as PC2 answer)"
                )
                skip_rtpengine_answer = True
                answer_sdp = client_ingress.localize_pc2_answer_sdp(raw_sbc)
                answer_sdp = _inject_telephone_event_answer(call, reply, answer_sdp)
                log.info(f"ANSWER SDP bytes={len(answer_sdp)}\n{answer_sdp}")
                client_ingress.complete_sbc_hairpin_answer(ingress_id, answer_sdp)
                try:
                    await client_ingress.ack_sbc_hairpin(call, reply)
                except Exception as exc:  # noqa: BLE001
                    log.warn(f"SBC_HAIRPIN: ACK failed: {exc}")
                return

            norm_sbc = client_ingress.normalize_sbc_answer_sdp(raw_sbc)
            if norm_sbc and norm_sbc != raw_sbc and hasattr(reply, "set_body"):
                reply.set_body(norm_sbc, "application/sdp")
                log.info(
                    f"SBC_HAIRPIN: normalized SBC 200 SDP {len(raw_sbc)}→{len(norm_sbc)}"
                )
            elif norm_sbc and not hasattr(reply, "set_body"):
                log.warn(
                    "SBC_HAIRPIN: reply.set_body missing; rtpengine.answer sees raw SBC SDP"
                )
            log.info(
                f"SBC_HAIRPIN: SBC 200 SDP bytes={len(norm_sbc or raw_sbc)}\n"
                f"{norm_sbc or raw_sbc}"
            )
        except Exception as exc:  # noqa: BLE001
            log.warn(f"SBC_HAIRPIN: SBC SDP normalize skipped: {exc}")

    if not skip_rtpengine_answer:
        try:
            await rtpengine.answer(reply, call=call)
        except Exception as exc:  # noqa: BLE001
            log.error(f"rtpengine answer failed: {exc}")
            if ingress_id:
                _early_clear(cid)
                try:
                    await client_ingress.ack_sbc_hairpin(call, reply)
                except Exception as ack_exc:  # noqa: BLE001
                    log.warn(f"SBC_HAIRPIN: ACK after rtpengine fail: {ack_exc}")
                await client_ingress.fail_notify_call(
                    f"rtpengine answer failed: {exc}",
                    ingress_id=ingress_id,
                    cancel_sip=True,
                )
            return

    answer_sdp = _reply_body(reply)
    # Normalize for aiortc (rtcp-mux / ice-lite). Do NOT rewrite to 127.0.0.1
    # by default — that yielded ice=completed + connectionState=failed (DTLS).
    if ingress_id:
        answer_sdp = client_ingress.localize_pc2_answer_sdp(answer_sdp)
    answer_sdp = _inject_telephone_event_answer(call, reply, answer_sdp)
    _log_full_sdp("ANSWER SDP out (to A-leg)", answer_sdp)
    if ingress_id:
        client_ingress.complete_sbc_hairpin_answer(ingress_id, answer_sdp)
        # UAC hairpin often consumes 100 Trying and then misses ACK duty on 200.
        try:
            await client_ingress.ack_sbc_hairpin(call, reply)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"SBC_HAIRPIN: ACK failed: {exc}")


@b2bua.on_failure
def on_failure(call, code, reason):
    """SYNC on purpose — answer-timeout fires from a tokio worker; async
    on_failure → block_on nested runtime panic on older siphon builds."""
    log.warn(f"FAILURE: call {_call_id(call)} {code} {reason}")
    _early_clear(_call_id(call))
    ingress_id = _call_header(call, client_ingress.SBC_HAIRPIN_HEADER).strip()
    if ingress_id:
        # Hang up caller over DC + tear down (sync-safe).
        client_ingress.fail_notify_call_sync(
            f"SBC INVITE failed: {code} {reason}",
            ingress_id=ingress_id,
            cancel_sip=True,
        )
    else:
        try:
            client_ingress.hairpin_media_delete(call)
        except Exception as exc:  # noqa: BLE001
            log.error(f"rtpengine delete on failure: {exc}")
    try:
        call.reject(int(code) if code else 500, str(reason or "Error"))
    except Exception as exc:  # noqa: BLE001
        log.warn(f"FAILURE: reject failed: {exc}")


@b2bua.on_bye
async def on_bye(call, initiator):
    side = getattr(initiator, "side", initiator)
    cid = _call_id(call)
    log.info(f"BYE: call {cid} initiator={side}")
    _early_clear(cid)
    inbound = client_ingress.get_session_by_sip_call_id(cid)
    side_s = str(side or "").lower()
    # Armed transfer already decided to drop OpenAI and keep this caller.
    # terminate() BYEs the A-leg too, and that BYE shows up here as initiator=a.
    # Treating it as a caller hangup soft-ends PC1 and the hunt raises
    # "Caller abandoned". For PSTN replace_peer (ivrReplacePeer), a_leg BYE
    # is the real PSTN caller hanging up while parked/ringing.
    if (
        inbound
        and inbound.get("ivrTransferArmed")
        and not inbound.get("xferPark")
        and not inbound.get("ivrReplacePeer")
    ):
        log.info(
            f"BYE: IVR transfer armed call={cid} initiator={side} "
            f"session={inbound.get('sessionId')} — keep caller"
        )
        return
    if inbound is not None and inbound.get("xferPark"):
        if side_s not in ("a", "caller"):
            log.info(
                f"BYE: referred-away OpenAI session={inbound.get('sessionId')} "
                f"initiator={side} — keep seat"
            )
            try:
                await rtpengine.delete(call)
            except Exception as exc:  # noqa: BLE001
                log.error(f"rtpengine delete on referred-away bye: {exc}")
            return
    if inbound is not None:
        sid = str(inbound.get("sessionId") or "")
        if client_ingress._is_product_leg(inbound):
            log.info(
                f"BYE: product session={sid} routeKind={inbound.get('routeKind')} "
                "— skip webrtc fail_notify"
            )
            try:
                await client_ingress.fail_notify_call(
                    "remote-bye",
                    session=inbound,
                    session_id=sid,
                    cancel_sip=False,
                )
            except Exception as exc:  # noqa: BLE001
                log.warn(f"BYE: product session pop failed: {exc}")
        else:
            log.info(
                f"BYE: teardown inbound WebRTC session={sid} "
                f"callee_dc={bool(inbound.get('calleeDcOpen'))} "
                f"endCallSent={bool(inbound.get('endCallSent'))} "
                f"voicemail={bool(inbound.get('voicemailActive'))}"
            )
            try:
                await client_ingress.fail_notify_call(
                    "remote-bye",
                    session=inbound,
                    session_id=sid,
                    cancel_sip=bool(inbound.get("voicemailActive")),
                )
            except Exception as exc:  # noqa: BLE001
                log.warn(f"BYE: inbound teardown failed: {exc}")
    else:
        log.info(f"BYE: no notify session for call_id={cid}")
    try:
        await rtpengine.delete(call)
    except Exception as exc:  # noqa: BLE001
        log.error(f"rtpengine delete on bye: {exc}")


@b2bua.on_cancel
async def on_cancel(call):
    cid = _call_id(call)
    actor_id = str(getattr(call, "id", "") or "")
    log.info(f"CANCEL: call {cid} actor={actor_id or '-'}")
    _early_clear(cid)
    inbound = client_ingress.get_session_by_sip_call_id(cid)
    if inbound is None and actor_id:
        inbound = client_ingress.get_session_by_sip_call_id(actor_id)
    if inbound is not None:
        sid = str(inbound.get("sessionId") or "")
        log.info(
            f"CANCEL: teardown inbound WebRTC session={sid} "
            f"callee_dc={bool(inbound.get('calleeDcOpen'))}"
        )
        try:
            await client_ingress.fail_notify_call(
                "cancelled",
                session=inbound,
                session_id=sid,
                cancel_sip=False,
            )
        except Exception as exc:  # noqa: BLE001
            log.warn(f"CANCEL: inbound teardown failed: {exc}")
    else:
        log.info(f"CANCEL: no inbound WebRTC session for call_id={cid}")
    try:
        await rtpengine.delete(call)
    except Exception as exc:  # noqa: BLE001
        log.error(f"rtpengine delete on cancel: {exc}")


# Siphon terminate-mode dials Carol as a UAC. That INVITE never hits
# @b2bua.on_invite in this process (loop-detect on any siphon listen).
# SIPp Carol works because it is a different process. So 5070 is a Python
# UAS, not a siphon listener.
_XFER_PARK_HOST = "127.0.0.1"
_XFER_PARK_PORT = 5070
_park_thread = None
_siphon_loop = None
_park_loop = None


def _refer_local_uri(user: str) -> str:
    return f"sip:{user}@{_XFER_PARK_HOST}:{_XFER_PARK_PORT};transport=tcp"


def _refer_local_next_hop() -> str:
    return f"sip:{_XFER_PARK_HOST}:{_XFER_PARK_PORT};transport=tcp"


def _sip_header_map(raw_headers: list) -> dict:
    out = {}
    for name, value in raw_headers:
        key = name.lower()
        if key == "via":
            out.setdefault("via", []).append(value)
        else:
            out[key] = value
    return out


def _sip_pop_message(buf: bytes):
    sep = buf.find(b"\r\n\r\n")
    if sep < 0:
        return None, 0
    head = buf[:sep].decode("utf-8", errors="replace")
    lines = head.split("\r\n")
    if not lines or not lines[0].strip():
        return None, 0
    headers = []
    content_len = 0
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        value = value.strip()
        headers.append((name.strip(), value))
        if name.strip().lower() == "content-length":
            try:
                content_len = int(value or "0")
            except ValueError:
                content_len = 0
    total = sep + 4 + content_len
    if len(buf) < total:
        return None, 0
    body = buf[sep + 4 : total]
    start = lines[0].split()
    method = start[0] if start else ""
    ruri = start[1] if len(start) > 1 else ""
    return {
        "start": lines[0],
        "method": method.upper(),
        "ruri": ruri,
        "headers": headers,
        "body": body.decode("utf-8", errors="replace"),
    }, total


class _ParkCall:
    """Minimal Call shim so start_inbound_from_sbc can 180/200 the park UAS."""

    def __init__(self, msg: dict, writer, loop=None):
        self._msg = msg
        self._writer = writer
        self._loop = loop
        self._hdrs = _sip_header_map(msg.get("headers") or [])
        self.local_tag = f"pk-{uuid.uuid4().hex[:12]}"
        self.source_ip = "127.0.0.1"
        self.from_uri = self._hdrs.get("from") or ""
        self.to_uri = self._hdrs.get("to") or ""
        self.ruri = msg.get("ruri") or ""
        self.call_id = self._hdrs.get("call-id") or self._hdrs.get("i") or ""
        self.body = msg.get("body") or ""
        self.id = self.call_id

    def get_header(self, name: str) -> str:
        key = str(name or "").lower()
        if key == "via":
            vias = self._hdrs.get("via") or []
            return vias[0] if vias else ""
        return str(self._hdrs.get(key) or "")

    def set_header(self, name: str, value: str) -> None:
        self._hdrs[str(name or "").lower()] = str(value or "")

    def progress(self, code, reason=""):
        self._reply(int(code), str(reason or "Ringing"))

    def answer(self, code, reason="OK", body=None, content_type=None):
        self._reply(int(code), str(reason or "OK"), body=body, content_type=content_type)

    def reject(self, code, reason=""):
        self._reply(int(code), str(reason or "Error"))

    def _reply(self, code: int, reason: str, body=None, content_type=None) -> None:
        if isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        elif body:
            body_bytes = str(body).encode()
        else:
            body_bytes = b""
        to_val = self.get_header("To") or self.to_uri
        if to_val and ";tag=" not in to_val.lower():
            to_val = f"{to_val};tag={self.local_tag}"
        user = _uri_user(self.ruri or self.to_uri) or "park"
        lines = [f"SIP/2.0 {code} {reason}"]
        for name, value in self._msg.get("headers") or []:
            if name.lower() == "via":
                lines.append(f"{name}: {value}")
        lines.append(f"From: {self.get_header('From') or self.from_uri}")
        lines.append(f"To: {to_val}")
        lines.append(f"Call-ID: {self.call_id}")
        lines.append(f"CSeq: {self.get_header('CSeq')}")
        lines.append(f"Contact: <sip:{user}@{_XFER_PARK_HOST}:{_XFER_PARK_PORT};transport=tcp>")
        if body_bytes:
            lines.append(f"Content-Type: {content_type or 'application/sdp'}")
        lines.append(f"Content-Length: {len(body_bytes)}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body_bytes

        def _write():
            try:
                self._writer.write(raw)
            except Exception as exc:  # noqa: BLE001
                log.warn(f"PARK-UAS: write {code} failed: {exc}")

        park_loop = self._loop
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if park_loop is None or running is park_loop:
            _write()
        else:
            park_loop.call_soon_threadsafe(_write)
        log.info(
            f"PARK-UAS: reply {code} {reason} call_id={self.call_id} "
            f"body_bytes={len(body_bytes)}"
        )


async def _park_handle_invite(msg: dict, writer) -> None:
    call = _ParkCall(msg, writer, loop=asyncio.get_running_loop())
    dest = _clean_pstn_user(_uri_user(call.ruri or call.to_uri))
    pending = client_ingress.take_pending_xfer(dest)
    if not pending:
        log.error(f"PARK-UAS: no pending xfer to={dest} call_id={call.call_id}")
        call.reject(404, "No Pending Transfer")
        return
    stored = str(pending.get("sdp") or "").strip()
    body = stored or call.body
    from_tag = client_ingress._sip_header_tag(call.get_header("From")) or str(
        pending.get("from_tag") or ""
    )
    log.info(
        f"PARK-UAS: INVITE to={pending.get('to')} from={pending.get('from')} "
        f"a_leg={pending.get('a_leg')} park_id={call.call_id} "
        f"sdp_src={'stored-pstn' if stored else 'park-invite'} "
        f"sdp_bytes={len(body)}"
    )
    siphon_loop = _siphon_loop
    if siphon_loop is None:
        log.error("PARK-UAS: siphon loop missing — cannot wake seat")
        call.reject(500, "Server Error")
        return

    async def _wake():
        await _handle_inbound_from_sbc(
            call,
            pending.get("from") or dest,
            pending.get("to") or dest,
            pending.get("to") or dest,
            call.call_id,
            route=pending.get("route"),
            refer_transfer=False,
            sbc_sdp=body,
            from_tag=from_tag,
            b2bua_call_id=str(pending.get("a_leg") or ""),
            xfer_park=True,
        )

    fut = asyncio.run_coroutine_threadsafe(_wake(), siphon_loop)

    def _done(done):
        try:
            done.result()
        except Exception as exc:  # noqa: BLE001
            log.error(f"PARK-UAS: inbound failed park_id={call.call_id}: {exc}")

    fut.add_done_callback(_done)


async def _park_handle_bye(msg: dict, writer) -> None:
    call = _ParkCall(msg, writer, loop=asyncio.get_running_loop())
    call._reply(200, "OK")
    sess = client_ingress.get_session_by_sip_call_id(call.call_id)
    if not sess:
        return
    log.info(f"PARK-UAS: BYE session={sess.get('sessionId')} park_id={call.call_id}")
    siphon_loop = _siphon_loop
    if siphon_loop is None:
        return

    async def _teardown():
        await client_ingress.fail_notify_call(
            "park bye",
            session=sess,
            session_id=str(sess.get("sessionId") or ""),
            cancel_sip=False,
        )

    try:
        asyncio.run_coroutine_threadsafe(_teardown(), siphon_loop)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PARK-UAS: BYE teardown failed: {exc}")


async def _park_client(reader, writer) -> None:
    peer = writer.get_extra_info("peername")
    log.info(f"PARK-UAS: accepted {peer}")
    buf = b""
    try:
        while True:
            chunk = await reader.read(8192)
            if not chunk:
                break
            buf += chunk
            while True:
                msg, consumed = _sip_pop_message(buf)
                if not msg:
                    break
                buf = buf[consumed:]
                method = str(msg.get("method") or "")
                if method == "INVITE":
                    await _park_handle_invite(msg, writer)
                elif method == "ACK":
                    log.info("PARK-UAS: ACK")
                elif method == "BYE":
                    await _park_handle_bye(msg, writer)
                elif method == "CANCEL":
                    _ParkCall(msg, writer, loop=asyncio.get_running_loop())._reply(200, "OK")
                elif method == "OPTIONS":
                    _ParkCall(msg, writer, loop=asyncio.get_running_loop())._reply(200, "OK")
                else:
                    _ParkCall(msg, writer, loop=asyncio.get_running_loop())._reply(
                        405, "Method Not Allowed"
                    )
    except Exception as exc:  # noqa: BLE001
        log.warn(f"PARK-UAS: client error peer={peer}: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


def _park_thread_main() -> None:
    global _park_loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _park_loop = loop

    async def _serve():
        try:
            server = await asyncio.start_server(
                _park_client, _XFER_PARK_HOST, _XFER_PARK_PORT
            )
        except OSError as exc:
            log.error(
                f"PARK-UAS: bind {_XFER_PARK_HOST}:{_XFER_PARK_PORT} failed: {exc} "
                "(siphon must not listen on 5070)"
            )
            return
        log.info(f"PARK-UAS: listening {_XFER_PARK_HOST}:{_XFER_PARK_PORT}")
        async with server:
            await server.serve_forever()

    try:
        loop.run_until_complete(_serve())
    except Exception as exc:  # noqa: BLE001
        log.error(f"PARK-UAS: thread died: {exc}")


def _park_uas_up() -> bool:
    try:
        sock = socket.create_connection((_XFER_PARK_HOST, _XFER_PARK_PORT), 0.2)
    except OSError:
        return False
    try:
        sock.close()
    except OSError:
        pass
    return True


async def _ensure_park_uas() -> None:
    global _siphon_loop, _park_thread, _script_loop
    _siphon_loop = asyncio.get_running_loop()
    _script_loop = _siphon_loop
    client_ingress.pin_event_loop(_siphon_loop)
    if _park_thread is not None and _park_thread.is_alive():
        return
    if _park_uas_up():
        log.info(
            f"PARK-UAS: already listening {_XFER_PARK_HOST}:{_XFER_PARK_PORT} "
            "(script reload — skip rebind)"
        )
        return
    _park_thread = threading.Thread(
        target=_park_thread_main, name="xfer-park-uas", daemon=True
    )
    _park_thread.start()
    await asyncio.sleep(0.2)
    if not _park_thread.is_alive():
        log.error("PARK-UAS: thread exited immediately")


class _NullParkCall:
    """180/200 sink for IVR park wake — PSTN dialog is already answered."""

    def __init__(self, call_id: str, from_uri: str, to_uri: str):
        self.call_id = call_id
        self.local_tag = f"ivr-{uuid.uuid4().hex[:12]}"
        self.source_ip = "127.0.0.1"
        self.from_uri = from_uri
        self.to_uri = to_uri
        self.ruri = to_uri
        self.body = ""
        self.id = call_id

    def get_header(self, name: str) -> str:
        return ""

    def set_header(self, name: str, value: str) -> None:
        return None

    def progress(self, code, reason=""):
        log.info(f"NOTIFY/ACTION: park progress {code} {reason} call_id={self.call_id}")

    def answer(self, code, reason="OK", body=None, content_type=None):
        log.info(
            f"NOTIFY/ACTION: park answer {code} {reason} call_id={self.call_id} "
            f"sdp_bytes={len(body or '')}"
        )

    def reject(self, code, reason=""):
        log.warn(f"NOTIFY/ACTION: park reject {code} {reason} call_id={self.call_id}")


def _bye_openai_now(session: dict) -> None:
    """BYE OpenAI on siphon's existing B-leg TLS. Raw sockets get 481."""
    call_id = str(session.get("mediaCallId") or session.get("sessionId") or "")
    if not call_id:
        log.error("NOTIFY/ACTION: OpenAI BYE missing call_id")
        return
    bye_leg = getattr(b2bua, "bye_leg", None)
    if callable(bye_leg):
        ok = bye_leg(call_id, False)
        session["openaiDropped"] = bool(ok)
        log.info(f"NOTIFY/ACTION: OpenAI BYE via siphon B-leg call_id={call_id} ok={ok}")
        return
    if session.get("sbcHairpinId") or not str(session.get("inviteSdp") or "").strip():
        term = getattr(b2bua, "terminate", None)
        if callable(term):
            try:
                ok = term(call_id, "xfer")
                session["openaiDropped"] = bool(ok)
                log.info(
                    f"NOTIFY/ACTION: OpenAI hairpin BYE via b2bua.terminate "
                    f"call_id={call_id} ok={ok}"
                )
                return
            except Exception as exc:  # noqa: BLE001
                log.warn(f"NOTIFY/ACTION: b2bua.terminate OpenAI hairpin failed: {exc}")
    log.error(
        "NOTIFY/ACTION: b2bua.bye_leg missing — rebuild siphon with "
        "bye_leg (raw TLS BYE is 481 Call/Transaction Does Not Exist)"
    )


def _reinvite_aleg_now(call_id: str, sdp: str) -> None:
    reinv = getattr(b2bua, "reinvite_leg", None)
    if not callable(reinv):
        log.error(
            "NOTIFY/ACTION: b2bua.reinvite_leg missing — rebuild siphon; "
            "Cellact will keep old RTP ports"
        )
        return
    ok = reinv(str(call_id or ""), True, str(sdp or ""))
    log.info(
        f"NOTIFY/ACTION: A-leg re-INVITE call_id={call_id} "
        f"sdp_bytes={len(sdp or '')} ok={ok}"
    )


async def wake_ivr_xfer(session: dict, decision: dict, ident: str) -> None:
    """PSTN: replace_peer OpenAI→park UAS (seat rings while AI stays up). WebRTC: PC1."""
    sdp = str(session.get("inviteSdp") or "").strip()
    if not sdp:
        await _wake_ivr_xfer_webrtc(session, decision, ident)
        return
    a_leg = str(session.get("mediaCallId") or session.get("sessionId") or "")
    from_tag = str(session.get("fromTag") or "").strip() or "xfer-a"
    pstn_from = str(session.get("from") or "")
    replace = getattr(b2bua, "replace_peer", None)
    if not callable(replace) or not a_leg:
        log.error(
            "NOTIFY/ACTION: b2bua.replace_peer missing or no a_leg — "
            f"rebuild siphon ≥1.8.4 ident={ident!r} a_leg={a_leg!r}"
        )
        session["ivrTransferArmed"] = False
        return
    await _ensure_park_uas()
    client_ingress.put_pending_xfer(
        ident,
        {
            "from": pstn_from,
            "to": ident,
            "route": decision,
            "a_leg": a_leg,
            "sdp": sdp,
            "from_tag": from_tag,
        },
    )
    target = _refer_local_uri(ident)
    next_hop = _refer_local_next_hop()
    log.info(
        f"NOTIFY/ACTION: replace_peer ident={ident!r} a_leg={a_leg} "
        f"target={target} next_hop={next_hop} sdp_bytes={len(sdp)} "
        f"profile=sbc_to_webrtc (OpenAI stays up until park 200)"
    )
    try:
        ok = replace(
            a_leg,
            target,
            next_hop=next_hop,
            replace_a_leg=False,
            profile="sbc_to_webrtc",
            timeout=60,
        )
    except Exception as exc:  # noqa: BLE001
        client_ingress.take_pending_xfer(ident)
        session["ivrTransferArmed"] = False
        log.error(f"NOTIFY/ACTION: replace_peer failed a_leg={a_leg}: {exc}")
        return
    session["ivrReplacePeer"] = True
    log.info(f"NOTIFY/ACTION: replace_peer INVITE on wire ok={ok} a_leg={a_leg}")
    client_ingress._schedule_coro(_xfer_watchdog(ident, a_leg))


async def _wake_ivr_xfer_webrtc(session: dict, decision: dict, ident: str) -> None:
    """Arnacon caller: BYE OpenAI hairpin, notify/RING the transfer seat on PC1."""
    sid = session.get("sessionId")
    log.info(
        f"NOTIFY/ACTION: webrtc-origin IVR xfer ident={ident!r} session={sid} "
        "(drop OpenAI, keep caller PC1)"
    )
    cid = str(session.get("mediaCallId") or "")
    ingress = str(session.get("sbcHairpinId") or "")
    # Park PC1 RTP on live silence BEFORE OpenAI BYE — ended MediaRelay kills
    # aiortc's send loop and callee audio never makes it to the caller.
    try:
        await client_ingress.webrtc_pc.keep_pc1_sender_alive(session)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/ACTION: PC1 keep-alive failed session={sid}: {exc}")
    try:
        _bye_openai_now(session)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/ACTION: OpenAI bye_leg failed session={sid}: {exc}")
    if ingress:
        try:
            client_ingress.fail_sbc_hairpin(ingress, "xfer")
        except Exception as exc:  # noqa: BLE001
            log.warn(f"NOTIFY/ACTION: fail hairpin failed session={sid}: {exc}")
    session["openaiDropped"] = True
    try:
        await client_ingress.webrtc_pc.unbridge_media(session, keep_pc1_audio=True)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/ACTION: unbridge failed session={sid}: {exc}")
    try:
        client_ingress._schedule_recording_upload(session)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/ACTION: schedule prior recording upload failed session={sid}: {exc}")
    client_ingress._reset_recording_state(session)
    try:
        await client_ingress.webrtc_pc.close_pcs(session, pc1=False, callee=True)
    except Exception as exc:  # noqa: BLE001
        log.warn(f"NOTIFY/ACTION: close PC2 failed session={sid}: {exc}")
    try:
        client_ingress.rtpengine_delete(cid or sid, session.get("fromTag") or "a")
    except Exception:  # noqa: BLE001
        pass
    session["sbcNgOwned"] = False
    session["sbcHairpinId"] = None
    session["sbcAnswered"] = False
    session["productKind"] = None
    prev_route = session.get("route") if isinstance(session.get("route"), dict) else {}
    origin_route = (
        session.get("originRoute") if isinstance(session.get("originRoute"), dict) else {}
    )
    route = dict(decision or {})
    rk = str(route.get("route") or "webrtc").strip().lower()
    if rk not in ("webrtc", "webrtc-multiring"):
        rk = "webrtc"
    route["route"] = rk
    route["notifyIdentity"] = str(route.get("notifyIdentity") or ident or "")
    route["ensName"] = str(route.get("ensName") or route["notifyIdentity"] or ident)
    if not route.get("targets"):
        route["targets"] = [{"notifyIdentity": ident}]
    route["logicSp"] = (
        session.get("logicSp")
        or route.get("logicSp")
        or prev_route.get("logicSp")
        or origin_route.get("logicSp")
    )
    if not route.get("callerId"):
        fallback_cli = (
            session.get("callerId")
            or prev_route.get("callerId")
            or origin_route.get("callerId")
        )
        if fallback_cli:
            route["callerId"] = fallback_cli
    if not route.get("noAnswer"):
        fallback_na = prev_route.get("noAnswer") or origin_route.get("noAnswer")
        if fallback_na:
            route["noAnswer"] = fallback_na
    session["route"] = route
    session["routeKind"] = rk
    session["to"] = ident
    session["ringGeneration"] = int(session.get("ringGeneration") or 0) + 1
    client_ingress._set_call_nonce(session, fresh=True)
    session["ringStartedAt"] = time.monotonic()
    client_ingress._apply_recording_policy(session, route)
    session["mediaCallId"] = f"{uuid.uuid4().hex}@{policy.local_domain()}"
    session["fromTag"] = uuid.uuid4().hex[:8]
    session["toTag"] = uuid.uuid4().hex[:8]
    client_ingress._bind_session_aliases(session)
    offer_sdp = str(session.get("ringOfferSdp") or "")
    try:
        try:
            await client_ingress._execute_webrtc(session, offer_sdp)
        except RuntimeError as ring_exc:
            if str(ring_exc) in ("Callee answer timeout", "Callee declined"):
                if await client_ingress._connect_no_answer_voicemail(session, offer_sdp):
                    await client_ingress.webrtc_pc.rebridge_media(session, force=True)
                    session["ivrTransferArmed"] = False
                    return
            raise
        await client_ingress.webrtc_pc.rebridge_media(session, force=True)
        session["ivrTransferArmed"] = False
    except Exception as exc:  # noqa: BLE001
        session["ivrTransferArmed"] = False
        log.error(f"NOTIFY/ACTION: webrtc IVR xfer failed session={sid}: {exc}")
        await client_ingress.fail_notify_call(
            exc,
            session=session,
            session_id=sid,
            cancel_sip=True,
        )


async def _xfer_watchdog(did, a_leg_id):
    await asyncio.sleep(2.0)
    pending = client_ingress.peek_pending_xfer(did)
    if not pending:
        return
    log.error(
        f"REFER: park INVITE missing after 2s to={did} a_leg={a_leg_id} "
        f"target=sip:{did}@{_XFER_PARK_HOST}:{_XFER_PARK_PORT};transport=tcp "
        "(siphon UAC never reached the Python park UAS)"
    )


@b2bua.on_refer
async def on_refer(call):
    """Resolve REFER like inbound INVITE. This box has no Node :9100."""
    refer_to = getattr(call, "refer_to", None)
    if not refer_to:
        log.error("REFER: missing Refer-To")
        call.reject_refer(400, "Missing Refer-To")
        return

    refer_to_user_raw = _uri_user(refer_to) if not isinstance(refer_to, str) else ""
    refer_to_host = _uri_host(refer_to) if not isinstance(refer_to, str) else ""
    if isinstance(refer_to, str):
        parsed = policy.parse_sip_uri(refer_to) or (
            refer_to.split(":", 1)[-1].split("@", 1)[0] if "@" in refer_to else refer_to,
            refer_to.split("@", 1)[1].split(";", 1)[0] if "@" in refer_to else "",
        )
        if isinstance(parsed, tuple):
            refer_to_user_raw, refer_to_host = parsed[0], parsed[1]

    refer_to_user_clean = policy.strip_plus_and_domain_suffix(refer_to_user_raw)
    # original caller (dialog To-side) for lookup "from"
    clean_from_user = policy.strip_plus_and_domain_suffix(_uri_user(call.to_uri)) or policy.strip_plus_and_domain_suffix(
        _uri_user(call.from_uri)
    )
    provider, refer_to_domain = policy.resolve_inbound_service_domain(refer_to_user_raw)
    if not refer_to_domain:
        refer_to_domain = policy.normalize_domain(_uri_host(call.to_uri) or refer_to_host)
    call_id = _call_id(call)

    log.info(
        f"REFER: from={clean_from_user} to={refer_to_user_clean} domain={refer_to_domain} "
        f"provider={provider} call_id={call_id}"
    )

    parsed_to = client_ingress.logic_client.parse_address(refer_to_user_clean)
    parsed_from = client_ingress.logic_client.parse_address(clean_from_user)
    try:
        route = await client_ingress.logic_client.resolve_destination(
            parsed_to,
            parsed_from,
            origin="sbc",
            to=refer_to_user_clean,
            from_id=clean_from_user,
            session_id=str(call_id or ""),
            kind="inbound",
        )
    except Exception as exc:  # noqa: BLE001
        log.error(f"REFER: resolve failed: {exc}")
        call.reject_refer(500, "REFER Resolve Failed")
        return

    rk = str((route or {}).get("route") or "")
    log.info(
        f"REFER: resolve route={rk} to={refer_to_user_clean} "
        f"sp={route.get('logicSp') or '-'} "
        f"source={route.get('routingSource') or route.get('walletSource') or '-'}"
    )
    if rk in ("external-sip", "openai-sip", "openai", "ivr"):
        target = str(route.get("sipUri") or route.get("uri") or "").strip()
        if not target:
            call.reject_refer(500, "REFER Missing SIP URI")
            return
        log.info(f"REFER: terminate external target {target}")
        call.accept_refer(target=target, mode="terminate")
        return
    if rk in ("webrtc", "webrtc-multiring"):
        from_uri_u = policy.strip_plus_and_domain_suffix(_uri_user(call.from_uri))
        to_uri_u = policy.strip_plus_and_domain_suffix(_uri_user(call.to_uri))
        xfer = client_ingress.lookup_xfer_invite(
            call_id, from_uri_u, to_uri_u, clean_from_user, refer_to_user_clean
        )
        pstn_from = str((xfer or {}).get("from") or "") or (
            from_uri_u if from_uri_u and from_uri_u != refer_to_user_clean else (
                to_uri_u if to_uri_u and to_uri_u != refer_to_user_clean else (
                    from_uri_u or to_uri_u
                )
            )
        )
        stored_sdp = str((xfer or {}).get("inviteSdp") or "")
        a_leg_id = str((xfer or {}).get("sessionId") or call_id)
        stored_tag = str((xfer or {}).get("fromTag") or "")
        if not stored_sdp.strip():
            log.error(
                "REFER: no stored PSTN SDP (B-leg REFER has empty body); "
                f"cannot wake to={refer_to_user_clean}"
            )
            call.reject_refer(500, "REFER No SDP")
            return
        if xfer is not None:
            xfer["referCall"] = call
        client_ingress.put_pending_xfer(
            refer_to_user_clean,
            {
                "from": pstn_from,
                "to": refer_to_user_clean,
                "route": route,
                "a_leg": a_leg_id,
                "sdp": stored_sdp,
                "from_tag": stored_tag,
            },
        )
        await _ensure_park_uas()
        target = _refer_local_uri(refer_to_user_clean)
        next_hop = _refer_local_next_hop()
        log.info(
            f"REFER: terminate 202 + park UAS {target} next_hop={next_hop} "
            f"a_leg={a_leg_id} (Python UAS on 5070; siphon must not bind it)"
        )
        call.accept_refer(target=target, next_hop=next_hop, mode="terminate")
        client_ingress._schedule_coro(
            _xfer_watchdog(refer_to_user_clean, a_leg_id)
        )
        return
    if rk == "reject":
        call.reject_refer(
            int(route.get("statusCode") or 404),
            str(route.get("reason") or "Not Found")[:64],
        )
        return

    log.error(f"REFER: unsupported route {rk!r}")
    call.reject_refer(500, "REFER Route Unsupported")


_script_loop: asyncio.AbstractEventLoop | None = None
_dtmf_udp_started = False
_dtmf_udp_lock = threading.Lock()
_dtmf_last: tuple[str, str, float] | None = None
_DTMF_UDP = "127.0.0.1:22227"
_RFC4733_DIGIT = {
    10: "*",
    11: "#",
    12: "A",
    13: "B",
    14: "C",
    15: "D",
}


def _pin_script_loop() -> None:
    global _script_loop
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _script_loop is None or not _script_loop.is_running():
        _script_loop = loop
    client_ingress.pin_event_loop(loop)


def _rfc4733_digit(event) -> str:
    try:
        code = int(event)
    except (TypeError, ValueError):
        return str(event or "")
    if 0 <= code <= 9:
        return str(code)
    return _RFC4733_DIGIT.get(code, "")


def _schedule_dtmf_action(session, digit: str, *, from_tag: str = "") -> None:
    coro = client_ingress._run_product_action(
        session,
        {
            "msgType": "dtmf",
            "digit": digit,
            "source": "rtp",
            "fromTag": from_tag,
        },
        digit=digit,
        action="dtmf",
    )
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
        return
    except RuntimeError:
        pass
    candidates = []
    if isinstance(session, dict):
        candidates.append(session.get("eventLoop"))
    candidates.extend(
        (_script_loop, _siphon_loop, getattr(client_ingress, "_pinned_loop", None))
    )
    seen: set[int] = set()
    for loop in candidates:
        if loop is None or id(loop) in seen:
            continue
        seen.add(id(loop))
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(coro, loop)
            return
    client_ingress._schedule_coro(coro)


@rtpengine.on_dtmf
def on_dtmf(call_id, from_tag, digit, duration_ms, volume):
    log.info(
        f"DTMF hit call_id={call_id!r} from_tag={from_tag!r} digit={digit!r} "
        f"dur={duration_ms} vol={volume}"
    )
    session = client_ingress.find_session_for_dtmf(call_id, from_tag)
    if not session:
        log.warn(f"DTMF: no product session for call_id={call_id!r} from_tag={from_tag!r}")
        return
    if session.get("ivrTransferArmed"):
        log.info(
            f"DTMF: ignore digit={digit!r} transfer already armed "
            f"session={session.get('sessionId')}"
        )
        return
    if not client_ingress.session_handles_dtmf(session):
        log.warn(
            f"DTMF: session skipped route={session.get('routeKind')!r} "
            f"session={session.get('sessionId')}"
        )
        return
    if not client_ingress.note_dtmf_digit(session, str(digit)):
        log.info(
            f"DTMF: dedupe digit={digit!r} source=rtpengine "
            f"session={session.get('sessionId')}"
        )
        return
    session["lastDtmfDurationMs"] = duration_ms
    session["lastDtmfVolume"] = volume
    if from_tag and not session.get("fromTag"):
        session["fromTag"] = from_tag
    log.info(
        f"DTMF/ACTION: call_id={call_id} from_tag={from_tag} digit={digit!r} "
        f"session={session.get('sessionId')}"
    )
    _schedule_dtmf_action(session, str(digit), from_tag=str(from_tag or ""))


def _dtmf_udp_loop(sock: socket.socket) -> None:
    global _dtmf_last
    while True:
        try:
            payload, _peer = sock.recvfrom(4096)
        except Exception as exc:  # noqa: BLE001
            log.warn(f"DTMF/UDP: recv failed: {exc}")
            continue
        raw = payload.decode(errors="replace").strip()
        if not raw:
            continue
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            log.warn(f"DTMF/UDP: not json {raw[:200]!r}")
            continue
        if str(body.get("type") or "").upper() != "DTMF" and "event" not in body:
            continue
        call_id = str(body.get("callid") or body.get("call_id") or "")
        from_tag = str(body.get("source_tag") or body.get("from_tag") or "")
        digit = _rfc4733_digit(body.get("event") if "event" in body else body.get("digit"))
        duration_ms = int(body.get("duration") or 0)
        volume = int(body.get("volume") or 0)
        if not call_id or not digit:
            log.warn(f"DTMF/UDP: missing callid/digit {body!r}")
            continue
        now = time.monotonic()
        with _dtmf_udp_lock:
            last = _dtmf_last
            if last and last[0] == call_id and last[1] == digit and (now - last[2]) < 2.0:
                continue
            _dtmf_last = (call_id, digit, now)
        log.info(f"DTMF/UDP: {raw[:300]}")
        on_dtmf(call_id, from_tag, digit, duration_ms, volume)


def _start_dtmf_udp_listener() -> None:
    global _dtmf_udp_started
    if _dtmf_udp_started:
        return
    host, _, port_s = _DTMF_UDP.partition(":")
    try:
        port = int(port_s or "22227")
    except ValueError:
        log.error(f"DTMF/UDP: bad address {_DTMF_UDP!r}")
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host or "127.0.0.1", port))
    except OSError as exc:
        log.warn(f"DTMF/UDP: bind {_DTMF_UDP} failed: {exc}")
        sock.close()
        return
    _dtmf_udp_started = True
    threading.Thread(target=_dtmf_udp_loop, args=(sock,), name="dtmf-udp", daemon=True).start()
    log.info(f"DTMF/UDP: listening {_DTMF_UDP} (rtpengine dtmf-log-dest)")


_start_dtmf_udp_listener()
