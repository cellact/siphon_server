"""Arnacon SIPhon policy helpers — port of kamailio.py without KSR."""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any, Optional

import requests

_deploy_env = os.environ.get("DEPLOY_ENV", "development")
_config_path = (
    os.environ.get("SIPHON_CONFIG_PATH")
    or os.environ.get("KAMAILIO_CONFIG_PATH")
    or "/etc/siphon/config.json"
)

with open(_config_path, encoding="utf-8") as f:
    _raw_env_config = json.load(f)[_deploy_env]

_common_cfg = _raw_env_config.get("common", {})

_inline_providers = _common_cfg.get("providers")
if not isinstance(_inline_providers, dict) or not _inline_providers:
    raise RuntimeError(
        f"SIPhon config {_config_path} ({_deploy_env}) common.providers is missing or empty"
    )

_providers_cfg: dict[str, Any] = {}
_service_provider_map: dict[str, str] = {}
_services_cfg: dict[str, Any] = {}
_service_domain_callback_map: dict[str, str] = {}
_service_callback_target_map: dict[str, str] = {}
_domain_service_alias_map: dict[str, str] = {}
_domain_provider_alias_map: dict[str, str] = {}

for _provider_id, _static_cfg in _inline_providers.items():
    if str(_provider_id).startswith("_") or not isinstance(_static_cfg, dict):
        continue
    _pid = str(_provider_id).strip()
    if not _pid:
        continue
    _domains = _static_cfg.get("domains", []) or []
    _canonical = str(_domains[0] if len(_domains) > 0 else "").strip().lower().rstrip(".")
    _providers_cfg[_pid] = {
        "status": _static_cfg.get("status", "active"),
        "canonicalDomain": _canonical,
        "acceptedDomains": _domains,
        "trustedIngressIps": _static_cfg.get("trustedIngressIps", []) or [],
        "outboundSbcAddress": _static_cfg.get("outboundSbcAddress", ""),
        "outboundSbcPort": _static_cfg.get("outboundSbcPort", 5061),
        "outboundSbcShim": _static_cfg.get("outboundSbcShim") or {},
    }
    # Alias targets are provider ids (lightpbx.global -> lightpbx).
    _service_provider_map[_pid] = _pid

if not _providers_cfg:
    raise RuntimeError(
        f"SIPhon config {_config_path} ({_deploy_env}) common.providers has no provider objects"
    )

_raw_domain_aliases = _common_cfg.get("domainServiceAliases", {}) or {}
if isinstance(_raw_domain_aliases, dict):
    for _alias_domain, _alias_target in _raw_domain_aliases.items():
        _alias = str(_alias_domain or "").strip().lower().rstrip(".")
        _target = str(_alias_target or "").strip()
        if not _alias or not _target:
            continue
        _service_id = None
        _provider_id = None

        if _target in _services_cfg:
            _service_id = _target
        elif _target in _service_provider_map:
            _provider_id = _target
            _service_id = _service_provider_map.get(_provider_id)

        if _service_id and not _provider_id:
            for _pid, _sid in _service_provider_map.items():
                if _sid == _service_id:
                    _provider_id = _pid
                    break

        if _service_id:
            _domain_service_alias_map[_alias] = _service_id
        if _provider_id:
            _domain_provider_alias_map[_alias] = _provider_id

_config = dict(_common_cfg)
_config["providers"] = _providers_cfg
_config["services"] = _services_cfg
_config["webrtcServiceHost"] = (
    os.environ.get("WEBRTC_SERVICE_HOST")
    or _common_cfg.get("webrtcServiceHost")
    or _common_cfg.get("bindIp")
    or "127.0.0.1"
)
_config["callbackScheme"] = (
    os.environ.get("WEBRTC_CALLBACK_SCHEME")
    or _common_cfg.get("callbackScheme")
    or "http"
)
_config["callbackPath"] = (
    os.environ.get("WEBRTC_CALLBACK_PATH")
    or _common_cfg.get("callbackPath")
    or "/inbound-call"
)
_config["callbackTlsVerify"] = str(
    os.environ.get("WEBRTC_CALLBACK_TLS_VERIFY")
    or _common_cfg.get("callbackTlsVerify", "true")
).strip().lower() in ("1", "true", "yes", "on")

OPENAI_SIP_URI_RE = re.compile(
    r"sip:proj_[A-Za-z0-9]+@sip\.api\.openai\.com;transport=tls"
)

_http = requests.Session()


def normalize_domain(domain: Any) -> str:
    return str(domain or "").strip().lower().rstrip(".")


def parse_sip_uri(header: str) -> Optional[tuple[str, str]]:
    match = re.search(r"<sips?:([^@]+)@([^>]+)>", header)
    if not match:
        match = re.search(r"sips?:([^@]+)@([^;\s>]+)", header)
    if not match:
        return None
    return (match.group(1), match.group(2))


def strip_sbc_username(username: str) -> str:
    if username.startswith("+"):
        username = username[1:]
    username_parts = username.split(".")
    if len(username_parts) == 3 and username_parts[2] == "global":
        username = username_parts[0]
    return username


_SBC_FORCED_USER_SUFFIXES = (
    ".cellactm.global",
    ".cellactl.global",
    ".cellactm",
    ".cellactl",
)


def strip_plus_and_domain_suffix(user: str) -> str:
    """Bare DID. SBC still sends 972….cellactm.global / cellactl.global."""
    value = str(user or "").strip()
    if value.startswith("+"):
        value = value[1:]
    lower = value.lower()
    for suffix in _SBC_FORCED_USER_SUFFIXES:
        if lower.endswith(suffix):
            value = value[: -len(suffix)]
            break
    if re.match(r"^[0-9]+\.", value):
        value = value.split(".", 1)[0]
    return value


def provider_catalog() -> dict[str, Any]:
    catalog = {}
    for provider, cfg in _config.get("providers", {}).items():
        if str(cfg.get("status", "active")).lower() != "active":
            continue
        canonical = cfg.get("canonicalDomain", "")
        if not canonical:
            env_domains = cfg.get("environmentDomains", {}) or {}
            canonical = (
                env_domains.get(_deploy_env)
                or env_domains.get("development")
                or env_domains.get("production")
                or ""
            )
        accepted = cfg.get("acceptedDomains", []) or []
        domains = [normalize_domain(x) for x in accepted if normalize_domain(x)]
        if canonical and normalize_domain(canonical) not in domains:
            domains.append(normalize_domain(canonical))
        catalog[provider] = {
            "canonicalDomain": normalize_domain(canonical),
            "domains": domains,
            "outboundSbcAddress": cfg.get("outboundSbcAddress", ""),
            "outboundSbcPort": cfg.get("outboundSbcPort", 5061),
            "outboundSbcShim": cfg.get("outboundSbcShim") or {},
            "trustedIngressIps": cfg.get("trustedIngressIps", []) or [],
        }
    return catalog


def resolve_provider_by_domain(domain: str) -> Optional[str]:
    d = normalize_domain(domain)
    if not d:
        return None
    if d in _domain_provider_alias_map:
        return _domain_provider_alias_map[d]
    for provider, cfg in provider_catalog().items():
        canonical = normalize_domain(cfg.get("canonicalDomain"))
        aliases = [normalize_domain(x) for x in cfg.get("domains", [])]
        if d == canonical or d in aliases:
            return provider
    return None


def canonical_domain_for_provider(provider: str) -> str:
    cfg = provider_catalog().get(provider, {})
    canonical = normalize_domain(cfg.get("canonicalDomain"))
    if canonical:
        return canonical
    aliases = [normalize_domain(x) for x in cfg.get("domains", [])]
    return aliases[0] if aliases else ""


def provider_sbc_address(provider: str) -> str:
    cfg = provider_catalog().get(provider, {})
    return str(cfg.get("outboundSbcAddress", "")).strip()


def extract_domain_from_identity(identity: str) -> str:
    value = str(identity or "").strip().lower()
    if not value:
        return ""
    if "@" in value:
        return value.split("@", 1)[1].split(";", 1)[0]
    if value.endswith(".global"):
        parts = value.split(".")
        if len(parts) >= 3:
            return ".".join(parts[1:])
        return value
    return ""


def resolve_provider_from_identity(identity: str) -> Optional[str]:
    return resolve_provider_by_domain(extract_domain_from_identity(identity))


def _provider_trunk_ips(cfg: dict[str, Any]) -> set[str]:
    """Ingress IPs plus the outbound SBC address. Same set is_from_sbc unions."""
    ips: set[str] = set()
    address = str(cfg.get("outboundSbcAddress") or "").strip()
    if address:
        ips.add(address)
    for ip in cfg.get("trustedIngressIps") or []:
        text = str(ip or "").strip()
        if text:
            ips.add(text)
    return ips


def trusted_sbc_ips() -> set[str]:
    ips: set[str] = set()
    for _, cfg in provider_catalog().items():
        ips.update(_provider_trunk_ips(cfg))
    return ips


def providers_for_ingress_ip(source_ip: str) -> list[str]:
    """Providers that list this source. Shared trunks return more than one."""
    ip = str(source_ip or "").strip()
    if not ip:
        return []
    return [
        pid
        for pid, cfg in provider_catalog().items()
        if ip in _provider_trunk_ips(cfg)
    ]


def is_from_sbc(source_ip: str) -> bool:
    return str(source_ip or "") in trusted_sbc_ips()


def determine_sbc_for_number(number: str, from_user: str, from_domain: str) -> Optional[str]:
    provider = resolve_provider_from_identity(from_user)
    if not provider:
        provider = resolve_provider_by_domain(from_domain)
    if not provider:
        return None
    return provider_sbc_address(provider) or None


def resolve_inbound_service_domain(to_user: str) -> tuple[str, str]:
    """Return (provider_id, canonical_domain)."""
    domain = ""
    if "." in to_user:
        parts = to_user.split(".")
        if len(parts) >= 3:
            domain = ".".join(parts[1:])
    provider = resolve_provider_by_domain(domain)
    if not provider:
        return "", ""
    return provider, canonical_domain_for_provider(provider)


def callback_target_for_inbound_domain(domain: str) -> str:
    normalized = normalize_domain(domain)
    if normalized and normalized in _domain_service_alias_map:
        service_id = _domain_service_alias_map.get(normalized)
        if service_id and service_id in _service_callback_target_map:
            return _service_callback_target_map[service_id]
    if normalized and normalized in _service_domain_callback_map:
        return _service_domain_callback_map[normalized]
    provider = resolve_provider_by_domain(normalized)
    if provider:
        service_id = _service_provider_map.get(provider)
        if service_id and service_id in _service_callback_target_map:
            return _service_callback_target_map[service_id]
    if _service_callback_target_map:
        return next(iter(_service_callback_target_map.values()))
    return "8067"


def callback_url_for_inbound_domain(domain: str) -> str:
    target = str(callback_target_for_inbound_domain(domain) or "8067").strip()
    if target.startswith("http://") or target.startswith("https://"):
        return target

    scheme = str(_config.get("callbackScheme", "http") or "http").strip().lower()
    if scheme not in ("http", "https"):
        scheme = "http"
    host = str(_config.get("webrtcServiceHost", "127.0.0.1") or "127.0.0.1").strip()
    default_path = str(_config.get("callbackPath", "/inbound-call") or "/inbound-call").strip()
    if not default_path.startswith("/"):
        default_path = "/" + default_path

    if target.isdigit():
        return f"{scheme}://{host}:{target}{default_path}"

    if "/" in target:
        host_part, raw_path = target.split("/", 1)
        path_part = "/" + raw_path.lstrip("/")
        if "://" in host_part:
            return target
        return f"{scheme}://{host_part}{path_part}"

    return f"{scheme}://{target}{default_path}"


def callback_verify_tls(callback_url: str) -> bool:
    parsed = urllib.parse.urlparse(callback_url)
    if parsed.scheme != "https":
        return True
    host = (parsed.hostname or "").strip().lower()
    if host in ("127.0.0.1", "localhost", "::1"):
        return False
    return bool(_config.get("callbackTlsVerify", True))


def notify_webrtc_gateway(
    from_number: str,
    to_number: str,
    call_id: str,
    diversion_number: str = "",
    to_domain: str = "",
    source_event: str = "inbound",
    refer_presented_from: str = "",
    refer_from_tag: str = "",
    refer_to_tag: str = "",
    refer_event_id: str = "",
) -> dict[str, Any]:
    """POST inbound/refer payload to webrtc-service. Returns result dict."""
    result = {
        "ok": False,
        "route": "",
        "external_sip_uri": "",
        "error": "",
    }
    try:
        gateway_url = callback_url_for_inbound_domain(to_domain)
        payload: dict[str, Any] = {
            "from": from_number,
            "to": to_number,
            "callId": call_id,
        }
        if source_event == "refer":
            payload["callType"] = "refer"
            if refer_presented_from:
                payload["referPresentedFrom"] = refer_presented_from
            if refer_from_tag:
                payload["referFromTag"] = refer_from_tag
            if refer_to_tag:
                payload["referToTag"] = refer_to_tag
            if refer_event_id:
                payload["referEventId"] = refer_event_id
            payload["referDialogCallId"] = call_id
            payload["transferId"] = f"refer:{call_id}:{refer_event_id or '0'}"
        if diversion_number:
            payload["diversion"] = diversion_number
        provider = resolve_provider_by_domain(to_domain) if to_domain else None
        if provider:
            payload["serviceId"] = _service_provider_map.get(provider)

        verify_tls = callback_verify_tls(gateway_url)
        response = _http.post(
            gateway_url,
            json=payload,
            timeout=10,
            verify=verify_tls,
        )
        if response.status_code not in (200, 202):
            result["error"] = f"{response.status_code} {response.text}"
            return result

        try:
            response_payload = response.json()
        except (TypeError, ValueError):
            response_payload = {}

        route = str(response_payload.get("route") or "")
        if route == "external-sip":
            sip_uri = str(response_payload.get("sipUri") or "").strip()
            if not OPENAI_SIP_URI_RE.fullmatch(sip_uri):
                result["error"] = f"invalid external SIP target: {sip_uri}"
                return result
            result["external_sip_uri"] = sip_uri
            result["route"] = "external-sip"
        elif route in ("refer-local-bridge-accepted", "refer-pass-through"):
            result["route"] = route
        result["ok"] = True
        return result
    except Exception as exc:  # noqa: BLE001 — parity with kamailio.py catch-all
        result["error"] = str(exc)
        return result


def clean_from_user_for_sbc(from_user: str) -> str:
    return strip_sbc_username(str(from_user or ""))


def extract_number_for_sbc(to_user: str) -> str:
    """Dial user. A leading + is kept; domain suffixes still come off."""
    raw = str(to_user or "").strip()
    plus = raw.startswith("+")
    cleaned = strip_sbc_username(raw)
    if plus and cleaned and not cleaned.startswith("+"):
        return f"+{cleaned}"
    return cleaned


def local_domain() -> str:
    return str(_config.get("domain") or "").strip()


def local_bind_ip() -> str:
    """IP used to hairpin SIP back into this SIPhon instance."""
    return (
        os.environ.get("SIPHON_BIND_IP")
        or os.environ.get("SIPHON_PUBLIC_IP")
        or str(_common_cfg.get("bindIp") or "")
        or str(_common_cfg.get("publicIp") or "")
        or "127.0.0.1"
    ).strip()


def local_public_ip() -> str:
    """Address peers outside the VPC can route to. Not the bind address."""
    return (
        os.environ.get("SIPHON_PUBLIC_IP")
        or str(_common_cfg.get("publicIp") or "")
        or local_bind_ip()
    ).strip()


def config() -> dict[str, Any]:
    return _config


def _ingress() -> dict[str, Any]:
    return _common_cfg.get("clientIngress") or {}


def _logic_entry(provider_id: str, blob: Any, *, notify_port: int, env_url: str, env_ms: str) -> Optional[dict[str, Any]]:
    data = blob if isinstance(blob, dict) else {}
    url = str(data.get("baseUrl") or "").strip().rstrip("/")
    if not url:
        return None
    ms = 3000
    try:
        ms = int(data.get("timeoutMs") or 3000)
    except (TypeError, ValueError):
        ms = 3000
    port = int(data.get("notifyPort") or notify_port)
    entry = {
        "id": provider_id,
        "baseUrl": url,
        "timeoutMs": max(500, ms),
        "notifyPort": port,
    }
    sms_url = str(data.get("smsUrl") or "").strip()
    if sms_url:
        entry["smsUrl"] = sms_url
    return entry


def logic_providers() -> list[dict[str, Any]]:
    """SP decision backends. Client /notify port pins from; dest fan-out otherwise."""
    ingress = _ingress()
    raw = ingress.get("logicProviders")
    out: list[dict[str, Any]] = []
    if isinstance(raw, list) and raw:
        for item in raw:
            if not isinstance(item, dict):
                continue
            pid = str(item.get("id") or "").strip().lower()
            url = str(item.get("baseUrl") or "").strip().rstrip("/")
            if not pid or not url:
                continue
            try:
                port = int(item.get("notifyPort") or 0)
            except (TypeError, ValueError):
                port = 0
            try:
                ms = int(item.get("timeoutMs") or 3000)
            except (TypeError, ValueError):
                ms = 3000
            entry = {
                "id": pid,
                "baseUrl": url,
                "timeoutMs": max(500, ms),
                "notifyPort": port,
            }
            sms_url = str(item.get("smsUrl") or "").strip()
            if sms_url:
                entry["smsUrl"] = sms_url
            out.append(entry)
        if out:
            return out
    ports_raw = ingress.get("notifyPorts") if isinstance(ingress.get("notifyPorts"), dict) else {}
    ports: dict[str, int] = {}
    for key, val in (ports_raw or {}).items():
        pid = str(key or "").strip().lower()
        if not pid:
            continue
        try:
            ports[pid] = int(val)
        except (TypeError, ValueError):
            continue
    out = []
    for pid, port in ports.items():
        blob = None
        want = f"{pid}logic"
        for k, v in ingress.items():
            if str(k).lower() == want:
                blob = v
                break
        env_prefix = pid.upper().replace("-", "_")
        entry = _logic_entry(
            pid,
            blob,
            notify_port=port,
            env_url=f"{env_prefix}_LOGIC_URL",
            env_ms=f"{env_prefix}_LOGIC_TIMEOUT_MS",
        )
        if not entry:
            continue
        out.append(entry)
    return out


def logic_provider(provider_id: str) -> Optional[dict[str, Any]]:
    want = str(provider_id or "").strip().lower()
    for item in logic_providers():
        if item["id"] == want:
            return item
    return None


def logic_provider_for_notify_port(port: Any) -> Optional[dict[str, Any]]:
    try:
        n = int(port)
    except (TypeError, ValueError):
        return None
    for item in logic_providers():
        if int(item.get("notifyPort") or 0) == n:
            return item
    return None


# ---------------------------------------------------------------------------
# SBC dial planning — separate SIP identity (R-URI/To) from wire next-hop.
#
# Carrier SBC at :5061 often only offers RSA-kx TLS suites. SIPhon/rustls does
# not. When a TLS shim (OpenSSL/socat) terminates that hop locally, R-URI/To
# still name the real SBC; next_hop points at the shim over plain TCP.
# ---------------------------------------------------------------------------

_DEFAULT_SBC_PORT = 5061
# TLS listen on the shim so B-leg Via/Contact advertise TLS:5061 (prod parity).
_DEFAULT_SHIM_TRANSPORT = "tls"
_VALID_WIRE_TRANSPORTS = frozenset({"tcp", "tls", "udp"})
_DEFAULT_SHIM_PORTS_BY_SBC: dict[str, int] = {
    "185.62.121.10": 15061,
    "3.66.95.165": 15062,
}


@dataclass(frozen=True)
class SbcDialPlan:
    """How to place an outbound INVITE toward a PSTN/SBC peer."""

    number: str
    sbc_address: str
    target_uri: str
    next_hop_uri: str
    signaling_transport: str
    wire_transport: str
    via_shim: bool
    provider: Optional[str] = None

    def to_header_uri(self) -> str:
        """To URI host = local domain (Kamailio parity); R-URI still targets SBC."""
        host = local_domain() or self.sbc_address
        return f"sip:{self.number}@{host}"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _normalize_wire_transport(value: Any, *, default: str = "tls") -> str:
    transport = str(value or default).strip().lower()
    if transport not in _VALID_WIRE_TRANSPORTS:
        return default
    return transport


def _parse_host_port(raw: str, *, default_port: int) -> Optional[tuple[str, int]]:
    text = str(raw or "").strip()
    if not text:
        return None
    if text.startswith("["):
        # [ipv6]:port
        if "]" not in text:
            return None
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return None
        return host, default_port
    if text.count(":") == 1:
        host, _, port_s = text.partition(":")
        try:
            return host.strip(), int(port_s)
        except ValueError:
            return None
    return text, default_port


def _shim_from_mapping(raw: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw, dict) or not raw:
        return None
    if "enabled" in raw and not _truthy(raw.get("enabled")):
        return None
    host = str(raw.get("host") or "").strip()
    if not host:
        return None
    try:
        port = int(raw.get("port") or 15061)
    except (TypeError, ValueError):
        port = 15061
    transport = _normalize_wire_transport(raw.get("transport"), default=_DEFAULT_SHIM_TRANSPORT)
    return {"host": host, "port": port, "transport": transport}


def resolve_provider_for_sbc(
    *,
    sbc_address: str = "",
    from_user: str = "",
    from_domain: str = "",
    provider: Optional[str] = None,
) -> Optional[str]:
    if provider and provider in provider_catalog():
        return provider
    resolved = resolve_provider_from_identity(from_user) or resolve_provider_by_domain(from_domain)
    if resolved:
        return resolved
    sbc = str(sbc_address or "").strip()
    if not sbc:
        return None
    for pid, cfg in provider_catalog().items():
        if str(cfg.get("outboundSbcAddress") or "").strip() == sbc:
            return pid
    return None


def _outbound_sbc_addresses() -> set[str]:
    """Hosts a local TLS shim is piped to. Any other route host is dialed direct."""
    out: set[str] = set(_DEFAULT_SHIM_PORTS_BY_SBC.keys())
    for cfg in provider_catalog().values():
        address = str(cfg.get("outboundSbcAddress") or "").strip()
        if address:
            out.add(address)
    common_outbound = _common_cfg.get("sbcOutbound") or {}
    if isinstance(common_outbound, dict):
        by_addr = common_outbound.get("shimsByAddress")
        if isinstance(by_addr, dict):
            for addr, raw in by_addr.items():
                addr_s = str(addr or "").strip()
                if not addr_s:
                    continue
                if _shim_from_mapping(raw):
                    out.add(addr_s)
                else:
                    out.discard(addr_s)
    return out


def _resolve_sbc_shim(
    provider: Optional[str], sbc_address: str = ""
) -> Optional[dict[str, Any]]:
    """Shim from config.json: shimsByAddress, then the provider, then sbcOutbound.shim."""
    addr = str(sbc_address or "").strip()
    common_outbound = _common_cfg.get("sbcOutbound") or {}
    if addr and isinstance(common_outbound, dict):
        by_addr = common_outbound.get("shimsByAddress")
        if isinstance(by_addr, dict) and addr in by_addr:
            return _shim_from_mapping(by_addr.get(addr))

    shim: Optional[dict[str, Any]] = None
    if provider:
        shim = _shim_from_mapping(provider_catalog().get(provider, {}).get("outboundSbcShim"))

    if not shim and isinstance(common_outbound, dict):
        shim = _shim_from_mapping(common_outbound.get("shim"))

    if shim and addr in _DEFAULT_SHIM_PORTS_BY_SBC and shim.get("port") == 15061:
        shim = dict(shim)
        shim["port"] = _DEFAULT_SHIM_PORTS_BY_SBC[addr]
    return shim


def _direct_sbc_port(provider: Optional[str]) -> int:
    if provider:
        try:
            return int(provider_catalog().get(provider, {}).get("outboundSbcPort") or _DEFAULT_SBC_PORT)
        except (TypeError, ValueError):
            pass
    common_outbound = _common_cfg.get("sbcOutbound") or {}
    if isinstance(common_outbound, dict):
        try:
            return int(common_outbound.get("port") or _DEFAULT_SBC_PORT)
        except (TypeError, ValueError):
            pass
    return _DEFAULT_SBC_PORT


def build_sbc_dial_plan(
    number: str,
    *,
    sbc_address: Optional[str] = None,
    from_user: str = "",
    from_domain: str = "",
    provider: Optional[str] = None,
) -> SbcDialPlan:
    """Build R-URI + next-hop for an outbound SBC INVITE.

    Raises ValueError when the number or SBC address cannot be resolved.
    """
    cleaned_number = extract_number_for_sbc(number)
    if not cleaned_number:
        raise ValueError("SBC dial requires a destination number")

    provider_id = resolve_provider_for_sbc(
        sbc_address=str(sbc_address or ""),
        from_user=from_user,
        from_domain=from_domain,
        provider=provider,
    )
    address = str(sbc_address or "").strip()
    if not address:
        address = determine_sbc_for_number(cleaned_number, from_user, from_domain) or ""
    if not address:
        raise ValueError(f"Failed to determine SBC for number {cleaned_number}")

    if not provider_id:
        provider_id = resolve_provider_for_sbc(
            sbc_address=address, from_user=from_user, from_domain=from_domain
        )

    signaling_transport = "tls"
    # Kamailio prod R-URI shape: sip:*9225@SBC;transport=tls;port=5061
    sbc_port = _direct_sbc_port(provider_id)
    target_uri = (
        f"sip:{cleaned_number}@{address};transport={signaling_transport};port={sbc_port}"
    )

    shim = _resolve_sbc_shim(provider_id, sbc_address=address)
    if shim and address not in _outbound_sbc_addresses():
        shim = None
    if shim:
        next_hop_uri = f"sip:{shim['host']}:{shim['port']};transport={shim['transport']}"
        return SbcDialPlan(
            number=cleaned_number,
            sbc_address=address,
            target_uri=target_uri,
            next_hop_uri=next_hop_uri,
            signaling_transport=signaling_transport,
            wire_transport=shim["transport"],
            via_shim=True,
            provider=provider_id,
        )

    port = _direct_sbc_port(provider_id)
    next_hop_uri = f"sip:{address}:{port};transport={signaling_transport}"
    return SbcDialPlan(
        number=cleaned_number,
        sbc_address=address,
        target_uri=target_uri,
        next_hop_uri=next_hop_uri,
        signaling_transport=signaling_transport,
        wire_transport=signaling_transport,
        via_shim=False,
        provider=provider_id,
    )
