"""
Arnacon SIP routing policy for SIPhon.

This is the full replacement for the old Kamailio pair
(``ron_kamailio.cfg`` + ``kamailio.py``). It runs as a hot-reloaded SIPhon
script: a stateful proxy for REGISTER/OPTIONS/in-dialog glue and SBC<->WebRTC
relay, plus a B2BUA for OpenAI/local UE call handling.

Direction model (decided in @b2bua.on_invite):

  * A-leg source IP in a provider's trusted SBC IPs  -> INBOUND  (SBC -> UE)
  * R-URI user == "2005"                             -> OPENAI   (UE  -> OpenAI)
  * R-URI user is an E.164/number or a provider id   -> OUTBOUND (UE  -> SBC)
  * otherwise                                        -> LOCAL    (UE  -> UE)

Media is anchored through RTPEngine using the custom profiles defined in
``siphon.yaml`` (webrtc_to_sbc / sbc_to_webrtc / openai_bridge), which mirror
the rtpengine_offer/answer flag strings the old cfg used by hand.

Cross-server: the inbound HTTP callback goes to ``webrtcServiceHost`` from
config.json (not localhost), so SIPhon and arnacon-webrtc-service can live on
separate boxes.
"""

from __future__ import annotations

import asyncio
import json
import os
import re

import httpx
from siphon import proxy, b2bua, registrar, rtpengine, log

# ---------------------------------------------------------------------------
# Config + catalog load (mirrors kamailio.py module init)
# ---------------------------------------------------------------------------

_DEPLOY_ENV = os.environ.get("DEPLOY_ENV", "development")
_CONFIG_PATH = os.environ.get("SIPHON_CONFIG_JSON") or "/etc/siphon/repo/sip_code/config.json"

with open(_CONFIG_PATH) as _f:
    _raw_env_config = json.load(_f).get(_DEPLOY_ENV, {})
_common_cfg = _raw_env_config.get("common", {})

DOMAIN = _common_cfg.get("domain", "")
# Where SIPhon reaches the arnacon-webrtc-service /inbound-call callback.
# Defaults to bindIp for a co-located deploy; set webrtcServiceHost in
# config.json for a split-server deploy.
WEBRTC_SERVICE_HOST = (
    _common_cfg.get("webrtcServiceHost")
    or _common_cfg.get("bindIp")
    or "127.0.0.1"
)

_GLOBAL_CONFIG_PATH = (
    os.environ.get("SIPHON_GLOBAL_CONFIG_JSON")
    or _common_cfg.get("globalServiceConfigPath", "")
)
_PROVIDERS_PATH = (
    os.environ.get("SIPHON_PROVIDERS_JSON")
    or _common_cfg.get("providersPath", "")
)

# OpenAI realtime SIP edge (hardcoded test extension 2005), carried over verbatim.
OPENAI_EXT = "2005"
OPENAI_RURI = "sip:proj_KSL2713VJDZwecei11z7gVul@sip.api.openai.com;transport=tls"
OPENAI_NEXT_HOP = "sip:sip.api.openai.com:5061;transport=tls"

# Per-caller concurrency guard (max 2 concurrent calls per From identity).
MAX_CALLS_PER_FROM = 2

# Inbound wait-for-register timeout (cfg parked transactions until the woken
# client registered; the SBC INVITE server transaction tolerates ~3 min).
INBOUND_REGISTER_TIMEOUT_S = 60

_NUMBER_RE = re.compile(r"^(\+?[0-9]{4,21}|\*[0-9]{4})$")


def _normalize_domain(domain: str) -> str:
    return str(domain or "").strip().lower().rstrip(".")


def _parse_minimal_catalog(root: dict):
    """Parse minimal SIP catalog from providers.json.

    Supported shapes:
      1) env-wrapped:
           {"development": {"services": {...}}}
      2) direct:
           {"services": {...}}

    Service/provider entry fields used by SIP:
      providerId, status, domains, outboundSbcAddress, trustedIngressIps,
      callbackPort (or callbackUrl/notifyPort as fallback).
    """
    providers = {}            # provider_id -> {canonicalDomain, domains, outboundSbcAddress, trustedIngressIps}
    provider_to_service = {}  # provider_id -> service_id
    domain_to_callback = {}   # normalized domain -> callback endpoint value
    service_to_callback = {}  # service_id -> callback endpoint value

    env_cfg = root.get(_DEPLOY_ENV, root) if isinstance(root, dict) else {}
    services = (env_cfg.get("services", {}) or {}) if isinstance(env_cfg, dict) else {}
    if not services and isinstance(env_cfg, dict):
        # Optional alias
        services = env_cfg.get("providers", {}) or {}

    if isinstance(services, list):
        # Optional list shape: [{serviceId, ...}, ...]
        normalized = {}
        for i, entry in enumerate(services):
            if not isinstance(entry, dict):
                continue
            service_id = str(entry.get("serviceId") or entry.get("providerId") or f"service{i}").strip()
            normalized[service_id] = entry
        services = normalized

    for service_id, entry in (services or {}).items():
        if not isinstance(entry, dict):
            continue
        if str(entry.get("status", "active")).lower() != "active":
            continue

        provider_id = str(entry.get("providerId") or service_id).strip()
        domains = [_normalize_domain(d) for d in (entry.get("domains", []) or []) if _normalize_domain(d)]
        canonical = domains[0] if domains else ""
        providers[provider_id] = {
            "canonicalDomain": canonical,
            "domains": domains,
            "outboundSbcAddress": str(entry.get("outboundSbcAddress", "")).strip(),
            "trustedIngressIps": entry.get("trustedIngressIps", []) or [],
        }
        provider_to_service[provider_id] = service_id

        callback_value = entry.get("callbackPort")
        if callback_value in (None, ""):
            callback_value = entry.get("callbackUrl")
        if callback_value in (None, ""):
            callback_value = entry.get("notifyPort")
        if callback_value in (None, ""):
            callback_value = 8067

        service_to_callback[service_id] = callback_value
        for d in domains:
            domain_to_callback[d] = callback_value

    return providers, provider_to_service, domain_to_callback, service_to_callback


def _load_catalog():
    """Build the provider/domain catalog from globalserviceconfig.json + per-service
    json files — the same files arnacon-webrtc-service reads, so the two never drift."""
    providers = {}            # provider_id -> {canonicalDomain, domains, outboundSbcAddress, trustedIngressIps}
    provider_to_service = {}  # provider_id -> service_id
    domain_to_callback = {}   # normalized domain -> callback endpoint value
    service_to_callback = {}  # service_id -> callback endpoint value

    # Optional: lightweight SIP-only providers catalog.
    if _PROVIDERS_PATH:
        if os.path.isfile(_PROVIDERS_PATH):
            try:
                with open(_PROVIDERS_PATH) as pf:
                    parsed = _parse_minimal_catalog(json.load(pf))
                log.info(f"arnacon: loaded SIP providers catalog from {_PROVIDERS_PATH!r}")
                return parsed
            except (OSError, ValueError) as e:
                log.warn(f"arnacon: cannot read SIP providers catalog {_PROVIDERS_PATH!r}: {e}")
        else:
            log.warn(f"arnacon: SIP providers catalog not found at {_PROVIDERS_PATH!r}")

    if not (_GLOBAL_CONFIG_PATH and os.path.isfile(_GLOBAL_CONFIG_PATH)):
        log.warn(f"arnacon: global service config not found at {_GLOBAL_CONFIG_PATH!r}")
        return providers, provider_to_service, domain_to_callback, service_to_callback

    with open(_GLOBAL_CONFIG_PATH) as gf:
        global_env = json.load(gf).get(_DEPLOY_ENV, {})

    base_dir = os.path.dirname(_GLOBAL_CONFIG_PATH)
    for service_id, entry in (global_env.get("services", {}) or {}).items():
        cfg_path = entry.get("configPath", "")
        if cfg_path and not os.path.isabs(cfg_path):
            cfg_path = os.path.join(base_dir, cfg_path)
        try:
            with open(cfg_path) as sf:
                svc_env = json.load(sf).get(_DEPLOY_ENV, {})
        except (OSError, ValueError) as e:
            log.warn(f"arnacon: cannot read service config {cfg_path!r}: {e}")
            svc_env = {}

        provider_id = entry.get("providerId") or svc_env.get("providerId") or service_id
        static = svc_env.get("static", {}) or {}
        if str(static.get("status", "active")).lower() != "active":
            continue

        domains = [_normalize_domain(d) for d in (static.get("domains", []) or []) if _normalize_domain(d)]
        canonical = domains[0] if domains else ""
        providers[provider_id] = {
            "canonicalDomain": canonical,
            "domains": domains,
            "outboundSbcAddress": str(static.get("outboundSbcAddress", "")).strip(),
            "trustedIngressIps": static.get("trustedIngressIps", []) or [],
        }
        provider_to_service[provider_id] = service_id

        callback_value = entry.get("callbackPort")
        if callback_value in (None, ""):
            callback_value = entry.get("notifyPort")
        if callback_value in (None, ""):
            callback_value = 8067

        service_to_callback[service_id] = callback_value
        for d in domains:
            domain_to_callback[d] = callback_value

    return providers, provider_to_service, domain_to_callback, service_to_callback


_PROVIDERS, _PROVIDER_TO_SERVICE, _DOMAIN_TO_CALLBACK, _SERVICE_TO_CALLBACK = _load_catalog()


def _trusted_sbc_ips() -> set:
    ips = set()
    for cfg in _PROVIDERS.values():
        if cfg.get("outboundSbcAddress"):
            ips.add(cfg["outboundSbcAddress"])
        for ip in cfg.get("trustedIngressIps", []):
            if ip:
                ips.add(ip)
    return ips


_TRUSTED_SBC_IPS = _trusted_sbc_ips()
log.info(
    f"arnacon: loaded {len(_PROVIDERS)} provider(s); trusted SBC IPs={sorted(_TRUSTED_SBC_IPS)}; "
    f"webrtcServiceHost={WEBRTC_SERVICE_HOST}"
)


def _resolve_provider_by_domain(domain: str):
    d = _normalize_domain(domain)
    if not d:
        return None
    for provider, cfg in _PROVIDERS.items():
        if d == cfg.get("canonicalDomain") or d in cfg.get("domains", []):
            return provider
    return None


def _provider_sbc_address(provider: str) -> str:
    return _PROVIDERS.get(provider, {}).get("outboundSbcAddress", "")


def _canonical_domain_for_provider(provider: str) -> str:
    return _PROVIDERS.get(provider, {}).get("canonicalDomain", "")


def _extract_domain_from_identity(identity: str) -> str:
    """user@dom -> dom ;  user.provider.global -> provider.global ; else ''."""
    value = str(identity or "").strip().lower()
    if not value:
        return ""
    if "@" in value:
        return value.split("@", 1)[1].split(";", 1)[0]
    if value.endswith(".global"):
        parts = value.split(".")
        if len(parts) >= 3:
            return ".".join(parts[1:])
    return ""


def _resolve_provider_from_identity(identity: str):
    return _resolve_provider_by_domain(_extract_domain_from_identity(identity))


def _strip_sbc_username(username: str) -> str:
    """Strip a leading '+' and a trailing '.<provider>.global' from an SBC user."""
    username = str(username or "")
    if username.startswith("+"):
        username = username[1:]
    parts = username.split(".")
    if len(parts) == 3 and parts[2] == "global":
        username = parts[0]
    return username


def _normalize_inbound_number(user: str) -> str:
    """Strip '+' and any '.<domain>.global' suffix down to a bare number."""
    user = str(user or "")
    if user.startswith("+"):
        user = user[1:]
    if "." in user:
        user = user.split(".", 1)[0]
    return user


def _callback_endpoint_for_domain(domain: str):
    d = _normalize_domain(domain)
    if d and d in _DOMAIN_TO_CALLBACK:
        return _DOMAIN_TO_CALLBACK[d]
    provider = _resolve_provider_by_domain(d)
    if provider:
        service_id = _PROVIDER_TO_SERVICE.get(provider)
        if service_id and service_id in _SERVICE_TO_CALLBACK:
            return _SERVICE_TO_CALLBACK[service_id]
    if _SERVICE_TO_CALLBACK:
        return next(iter(_SERVICE_TO_CALLBACK.values()))
    return 8067


def _callback_url_for_domain(domain: str) -> str:
    """Resolve per-domain callback endpoint from catalog.

    Supported callbackPort values (backward compatible):
      - int/number/string digits: 9100                  -> http://WEBRTC_SERVICE_HOST:9100/inbound-call
      - host[:port] string:      webrtc.box:9100        -> http://webrtc.box:9100/inbound-call
      - full URL:                https://x:9100/hook     -> https://x:9100/hook (or /inbound-call appended if missing)
    """
    raw = str(_callback_endpoint_for_domain(domain) or "").strip()
    if not raw:
        raw = "8067"

    lower = raw.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        base = raw.rstrip("/")
    elif raw.isdigit():
        base = f"http://{WEBRTC_SERVICE_HOST}:{raw}"
    else:
        # host[:port] (or host/path) form.
        base = f"http://{raw.lstrip('/')}"

    if base.rstrip("/").endswith("/inbound-call"):
        return base
    return f"{base.rstrip('/')}/inbound-call"


def _safe_header(obj, name: str):
    try:
        return obj.get_header(name)
    except Exception:
        return None


def _sdp_preview_from_obj(obj, max_chars: int = 1200) -> str:
    try:
        body = obj.body()
    except Exception:
        body = None
    if not body:
        return ""
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = str(body)
    text = text.strip()
    if not text:
        return ""
    if len(text) > max_chars:
        return text[:max_chars] + "\n...<truncated>..."
    return text


def _log_request_ingress(request):
    call_id = _safe_header(request, "Call-ID") or "-"
    content_type = _safe_header(request, "Content-Type") or "-"
    content_length = _safe_header(request, "Content-Length") or "-"
    contact = _safe_header(request, "Contact") or "-"
    via = _safe_header(request, "Via") or "-"
    log.info(
        "req: "
        f"method={request.method} call={call_id} "
        f"src={request.source_ip}:{request.source_port} transport={request.transport} "
        f"from={request.from_uri} to={request.to_uri} ruri={request.ruri} "
        f"ct={content_type} cl={content_length} contact={contact!r} via={via!r}"
    )
    sdp = _sdp_preview_from_obj(request)
    if sdp:
        log.info(f"req-sdp: call={call_id}\n{sdp}")


def _log_call_stage(call, stage: str):
    try:
        call_id = call.call_id or "-"
    except Exception:
        call_id = "-"
    log.info(
        f"call-stage: stage={stage} call={call_id} "
        f"src={getattr(call, 'source_ip', '?')} from={call.from_uri} to={call.to_uri} ruri={call.ruri}"
    )
    sdp = _sdp_preview_from_obj(call)
    if sdp:
        log.info(f"call-sdp: stage={stage} call={call_id}\n{sdp}")


# ---------------------------------------------------------------------------
# Proxy plane: REGISTER (no auth), OPTIONS, in-dialog glue, SBC<->UE INVITE relay
# ---------------------------------------------------------------------------

@proxy.on_request
async def route(request):
    _log_request_ingress(request)

    # Hard-switch: SBC<->UE INVITE routing runs in proxy flow-relay mode.
    # Everything else falls through to B2BUA handlers.
    if request.method == "INVITE":
        src = request.source_ip
        ruri_user = (request.ruri.user if request.ruri else "") or ""
        to_user = (request.to_uri.user if request.to_uri else "") or ""

        # 1) INBOUND from a trusted SBC IP — park until callee registers, then
        # relay using the captured REGISTER flow.
        if src in _TRUSTED_SBC_IPS:
            await _handle_inbound_from_sbc_request(request)
            return

        # 2) OUTBOUND to SBC — number-only dialing or provider-domain identity.
        to_domain = _extract_domain_from_identity(to_user) or _extract_domain_from_identity(str(request.to_uri or ""))
        provider = _resolve_provider_by_domain(to_domain) if to_domain else None
        if _NUMBER_RE.match(ruri_user) or provider:
            await _handle_outbound_to_sbc_request(request, provider)
            return

        # 3) OPENAI/local UE->UE stays on the B2BUA plane.
        return

    # OPTIONS keepalive to the bare host -> 200, no auth.
    if request.method == "OPTIONS" and not request.ruri.user:
        request.reply(200, "OK")
        return

    # REGISTER: auth is intentionally bypassed (crypto validated client/service
    # side, exactly as route[AUTH] did in the cfg). NAT-fix then save + 200 OK.
    if request.method == "REGISTER":
        src_ip = getattr(request, "source_ip", "?")
        src_port = getattr(request, "source_port", "?")
        transport = getattr(request, "transport", "?")
        before_contact = request.get_header("Contact")
        before_expires = request.get_header("Expires")
        log.info(
            "register: incoming "
            f"src={src_ip}:{src_port} transport={transport} to={request.to_uri} "
            f"contact={before_contact!r} expires={before_expires!r}"
        )
        request.fix_nated_register()
        after_contact = request.get_header("Contact")
        # Python-only safeguard: ensure 200 REGISTER can include Contact for
        # strict clients (SIP.js drops REGISTER responses with no Contact).
        if after_contact:
            request.set_reply_header("Contact", after_contact)
        log.info(
            "register: after-nat-fix "
            f"to={request.to_uri} contact={after_contact!r} "
            f"reply_contact_set={bool(after_contact)}"
        )
        flow_token = _flow_token_for_register(request)
        registrar.save(request, force=True, flow_token=flow_token)
        return

    # Sequential (in-dialog) non-INVITE requests that reach the proxy plane
    # (B2BUA owns OpenAI/local call dialogs). Follow Route set, then relay.
    if request.in_dialog:
        if request.method == "BYE":
            # Keep media sessions tidy for proxy-relayed dialogs.
            await rtpengine.delete(request)
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    if request.method == "CANCEL":
        request.relay()
        return

    # Everything else addressed to a local user (e.g. MESSAGE): registrar lookup.
    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return
    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return
    request.fork([getattr(c, "received", None) or c.uri for c in contacts])


# ---------------------------------------------------------------------------
# Concurrency guard (replaces the callguard htable + dialog-profile logic)
# ---------------------------------------------------------------------------

_active_by_from: dict[str, int] = {}   # from-key -> count
_call_from_key: dict[str, str] = {}    # call_id  -> from-key


def _from_key(call) -> str:
    fu = call.from_uri
    user = (fu.user if fu else "") or ""
    host = (fu.host if fu else "") or ""
    return f"{user}@{host}"


def _guard_acquire(call) -> bool:
    key = _from_key(call)
    if _active_by_from.get(key, 0) >= MAX_CALLS_PER_FROM:
        return False
    _active_by_from[key] = _active_by_from.get(key, 0) + 1
    _call_from_key[call.call_id] = key
    return True


def _guard_release(call) -> None:
    key = _call_from_key.pop(call.call_id, None)
    if key is None:
        return
    if _active_by_from.get(key, 0) <= 1:
        _active_by_from.pop(key, None)
    else:
        _active_by_from[key] -= 1


# ---------------------------------------------------------------------------
# Inbound park/resume (replaces t_suspend/t_continue + the vtp htable)
# ---------------------------------------------------------------------------

# number -> (loop, future). The future resolves when the woken client REGISTERs.
_pending_inbound: dict[str, tuple] = {}


@registrar.on_change
def on_reg_change(aor, event_type, contacts):
    if event_type not in ("registered", "refreshed"):
        return
    top = contacts[0] if contacts else None
    top_uri = getattr(top, "uri", "") if top else ""
    top_received = getattr(top, "received", "") if top else ""
    log.info(
        f"register-change: aor={aor} event={event_type} "
        f"contacts={len(contacts or [])} top_uri={top_uri!r} top_received={top_received!r}"
    )
    # AoR user part is the bare number the SBC dialed (clients register by number).
    user = aor.split("@", 1)[0].rsplit(":", 1)[-1]
    number = _normalize_inbound_number(user)
    entry = _pending_inbound.get(number)
    if not entry:
        if _pending_inbound:
            log.info(
                f"register-change: no pending match for number={number}; "
                f"pending_keys={list(_pending_inbound.keys())}"
            )
        return
    loop, fut = entry
    if not fut.done():
        loop.call_soon_threadsafe(fut.set_result, list(contacts or []))


# ---------------------------------------------------------------------------
# B2BUA plane: every INVITE
# ---------------------------------------------------------------------------

@b2bua.on_invite
async def on_invite(call):
    _log_call_stage(call, "invite-in")
    src = call.source_ip
    ruri_user = (call.ruri.user if call.ruri else "") or ""
    to_user = (call.to_uri.user if call.to_uri else "") or ""

    log.info(f"INVITE {call.from_uri} -> {call.ruri} (src={src}) call={call.call_id}")

    # Inbound/outbound SBC routes are handled in proxy flow-relay mode.
    # B2BUA remains for OpenAI and local UE->UE handling.
    # Concurrency guard for everything the UE originates on this plane.
    if not _guard_acquire(call):
        log.warn(f"call-limit: blocking >{MAX_CALLS_PER_FROM} concurrent for {_from_key(call)}")
        call.reject(486, "Busy Here")
        return

    try:
        # 2) OpenAI realtime bridge.
        if ruri_user == OPENAI_EXT:
            await _handle_openai(call)
            return

        # 3) LOCAL UE -> UE.
        contacts = registrar.lookup(call.ruri)
        if not contacts:
            call.reject(404, "Not Found")
            return
        await rtpengine.offer(call, profile="rtp_passthrough")
        contact = contacts[0]
        target = getattr(contact, "uri", "")
        next_hop = getattr(contact, "received", None)
        # Mirror Kamailio lookup+relay semantics:
        # keep contact identity in R-URI, route transport via received flow when present.
        if next_hop:
            call.dial(target, next_hop=next_hop)
        else:
            call.dial(target)
    except Exception:
        _guard_release(call)
        raise


def _flow_token_for_register(request) -> str:
    """Stable per-AoR token so registrar stores a captured flow."""
    to_uri = request.to_uri
    user = _normalize_inbound_number((to_uri.user if to_uri else "") or "")
    host = (to_uri.host if to_uri else "") or DOMAIN or "unknown-domain"
    return f"aor:{user}@{_normalize_domain(host)}"


def _rewrite_nameaddr_user(raw_value: str, user: str) -> str:
    if not raw_value:
        return raw_value
    return re.sub(r"(?i)(sips?:)([^@;>]+)@", rf"\1{user}@", raw_value, count=1)


async def _relay_on_reply(request, reply):
    status = reply.status_code()
    reason = reply.reason()
    call_id = _safe_header(request, "Call-ID") or "-"
    log.info(f"relay-reply: call={call_id} status={status} reason={reason}")
    reply_sdp = _sdp_preview_from_obj(reply)
    if reply_sdp:
        log.info(f"relay-reply-sdp: call={call_id}\n{reply_sdp}")
    if reply.has_body("application/sdp"):
        await rtpengine.answer(reply)


async def _relay_on_failure(request, code, reason):
    call_id = _safe_header(request, "Call-ID") or "-"
    log.warn(f"relay-failure: call={call_id} code={code} reason={reason}")
    await rtpengine.delete(request)


async def _handle_outbound_to_sbc_request(request, provider):
    # Resolve the SBC from the From identity (provider-scoped), like the cfg.
    from_user = (request.from_uri.user if request.from_uri else "") or ""
    sbc_provider = _resolve_provider_from_identity(from_user) or provider
    if not sbc_provider:
        log.error(f"outbound: no provider match for From={from_user}; refusing SBC route")
        request.reply(403, "No Route To Provider")
        return
    sbc_address = _provider_sbc_address(sbc_provider)
    if not sbc_address:
        log.error(f"outbound: no outboundSbcAddress for provider {sbc_provider!r}")
        request.reply(503, "No SBC Configured")
        return

    number = _strip_sbc_username((request.ruri.user if request.ruri else "") or "")
    # Normalize From + R-URI user the way ksr_edit_from_header_for_sbc /
    # ksr_extract_number_for_sbc did (strip '+' and '.<provider>.global').
    normalized_from = _strip_sbc_username(from_user)
    from_raw = request.get_header("From") or ""
    to_raw = request.get_header("To") or ""
    if from_raw:
        request.set_header("From", _rewrite_nameaddr_user(from_raw, normalized_from))
    if to_raw:
        request.set_header("To", _rewrite_nameaddr_user(to_raw, number))
    request.ruri = f"sip:{number}@{sbc_address}:5061;transport=tls"
    # WebRTC PAI isn't trusted upstream; caller-id rides on From.
    request.remove_header("P-Asserted-Identity")

    call_id = _safe_header(request, "Call-ID") or "-"
    log.info(f"rtpengine: offer profile=webrtc_to_sbc call={call_id}")
    await rtpengine.offer(request, profile="webrtc_to_sbc")
    log.info(f"rtpengine: offer-ok profile=webrtc_to_sbc call={call_id}")

    # Match Kamailio SBC_TO_HANDLER: explicit R-URI identity + separate transport destination.
    next_hop = f"sip:{sbc_address}:5061;transport=tls"
    log.info(f"outbound -> SBC {sbc_provider}: target={request.ruri} next_hop={next_hop}")
    request.record_route()
    request.relay(next_hop=next_hop, on_reply=_relay_on_reply, on_failure=_relay_on_failure)


async def _handle_openai(call):
    call.remove_header("P-Asserted-Identity")
    log.info(f"rtpengine: offer profile=openai_bridge call={call.call_id}")
    await rtpengine.offer(call, profile="openai_bridge")
    log.info(f"rtpengine: offer-ok profile=openai_bridge call={call.call_id}")
    log.info(f"openai: bridging call {call.call_id} -> {OPENAI_NEXT_HOP}")
    call.dial(OPENAI_RURI, next_hop=OPENAI_NEXT_HOP, header_policy="sip-trunk-edge@2026")


async def _handle_inbound_from_sbc_request(request):
    call_id = _safe_header(request, "Call-ID") or "-"
    from_user = _normalize_inbound_number((request.from_uri.user if request.from_uri else "") or "")
    to_user = (request.to_uri.user if request.to_uri else "") or ""
    number = _normalize_inbound_number(to_user)

    # Resolve provider/canonical service domain from the dialed identity.
    to_domain = ""
    if "." in to_user:
        parts = to_user.split(".")
        if len(parts) >= 3:
            to_domain = ".".join(parts[1:])
    provider = _resolve_provider_by_domain(to_domain) if to_domain else None
    service_domain = _canonical_domain_for_provider(provider) if provider else ""

    diversion = _diversion_number_request(request)

    # FCM-wake the client via the service callback (cross-box capable).
    payload = {"from": from_user, "to": number, "callId": call_id}
    if diversion:
        payload["diversion"] = diversion
    if service_domain:
        payload["toDomain"] = service_domain
    if provider:
        payload["serviceId"] = _PROVIDER_TO_SERVICE.get(provider)

    callback_url = _callback_url_for_domain(service_domain or to_domain)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(callback_url, json=payload)
        if resp.status_code not in (200, 202):
            log.error(f"inbound: callback {callback_url} -> {resp.status_code} {resp.text}")
            request.reply(404, "Not Found")
            return
    except Exception as e:
        log.error(f"inbound: callback {callback_url} failed: {e}")
        request.reply(404, "Not Found")
        return

    # Park: wait for the woken client (resolved by @registrar.on_change). The
    # proxy transaction stays open while we await registration wake-up.
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    # Track all reasonable wake keys for this parked inbound leg.
    # Some trunks send Diversion in local format (e.g. 0557...) while the UE
    # registers in E.164/national canonical form (e.g. 972557...). We index by
    # both so registrar.on_change can wake reliably.
    pending_keys = []
    for candidate in (diversion, number):
        c = _normalize_inbound_number(candidate)
        if c and c not in pending_keys:
            pending_keys.append(c)
    if not pending_keys:
        pending_keys = [number]
    for key in pending_keys:
        _pending_inbound[key] = (loop, fut)
    log.info(f"inbound: parked call {call_id} on pending keys={pending_keys}")
    try:
        contacts = await asyncio.wait_for(fut, timeout=INBOUND_REGISTER_TIMEOUT_S)
    except asyncio.TimeoutError:
        log.warn(
            f"inbound: client never registered within {INBOUND_REGISTER_TIMEOUT_S}s "
            f"for pending keys={pending_keys}"
        )
        request.reply(480, "Temporarily Unavailable")
        return
    finally:
        for key in pending_keys:
            _pending_inbound.pop(key, None)

    log.info(f"inbound: register wake for keys={pending_keys} produced {len(contacts or [])} contact(s)")

    # Pick the freshest contact (Diversion target first, then the dialed number).
    contact = _best_contact(diversion) or _best_contact(number) or (contacts[0] if contacts else None)
    if contact is None:
        request.reply(404, "Not Found")
        return

    flow = getattr(contact, "flow", None)
    if flow is None:
        log.error(f"inbound: no captured flow for keys={pending_keys}; cannot relay")
        request.reply(480, "Temporarily Unavailable")
        return
    log.info(f"rtpengine: offer profile=sbc_to_webrtc call={call_id}")
    await rtpengine.offer(request, profile="sbc_to_webrtc")
    log.info(f"rtpengine: offer-ok profile=sbc_to_webrtc call={call_id}")
    target = str(getattr(contact, "uri", "") or "").strip() or f"sip:{number}@{DOMAIN}"
    request.ruri = target
    log.info(
        f"inbound: resuming keys={pending_keys} "
        f"target={target!r} flow={flow!r}"
    )
    request.record_route()
    request.relay(on_reply=_relay_on_reply, on_failure=_relay_on_failure, flow=flow)


def _best_contact(number: str):
    if not number or not DOMAIN:
        return None
    contacts = registrar.lookup(f"sip:{number}@{DOMAIN}")
    return contacts[0] if contacts else None


def _diversion_number_request(request) -> str:
    raw = request.get_header("Diversion") or ""
    if not raw:
        return ""
    m = re.search(r"sips?:([^@>;]+)@", raw)
    if not m:
        return ""
    return _normalize_inbound_number(m.group(1))


# ---------------------------------------------------------------------------
# B2BUA media + lifecycle
# ---------------------------------------------------------------------------

@b2bua.on_answer
async def on_answer(call, reply):
    status = reply.status_code()
    reason = reply.reason()
    log.info(f"answer: call={call.call_id} status={status} reason={reason}")
    reply_sdp = _sdp_preview_from_obj(reply)
    if reply_sdp:
        log.info(f"answer-sdp: call={call.call_id}\n{reply_sdp}")
    if reply.has_body("application/sdp"):
        # Profile is inferred from the matching offer (keyed by A-leg Call-ID).
        log.info(f"rtpengine: answer call={call.call_id}")
        await rtpengine.answer(reply, call=call)
        log.info(f"rtpengine: answer-ok call={call.call_id}")


@b2bua.on_failure
async def on_failure(call, code, reason):
    log.warn(f"call-failure: call={call.call_id} code={code} reason={reason}")
    await rtpengine.delete(call)
    _guard_release(call)
    call.reject(code, reason)


@b2bua.on_bye
async def on_bye(call, initiator):
    log.info(f"call-bye: call={call.call_id} initiator={initiator}")
    await rtpengine.delete(call)
    _guard_release(call)
    call.terminate()
