"""HTTP decision API to logic wrappers (auth / route / action)."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from typing import Any, Optional

import requests

import identity
import policy

PRODUCT_ROUTE_KINDS = frozenset({"openai-sip", "openai", "ivr", "external-sip"})
CLAIMED_ROUTE_KINDS = PRODUCT_ROUTE_KINDS | frozenset({"webrtc", "webrtc-multiring"})
_http = requests.Session()
_sp_by_identity: dict[str, str] = {}
_route_sp_by_pair: dict[tuple[str, str], str] = {}
_recording_sps_by_pair: dict[tuple[str, str], list[str]] = {}
_id_token_cache: dict[str, tuple[str, int]] = {}

_SA_JSON_CANDIDATES = (
    os.environ.get("GCP_SERVICE_ACCOUNT_JSON_FILE") or "",
    os.environ.get("ARNACON_GCP_SERVICE_ACCOUNT_JSON_FILE") or "",
    os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets", "kamailio-gcp-mapping-sa.json"),
    "/etc/kamailio/sip_code/secrets/kamailio-gcp-mapping-sa.json",
)


def normalize_phone(value: Any) -> str:
    """Normalize destination for routing / SBC dial.

    Keep a leading ``*`` (shortcodes like ``*9225``). Kamailio/prod dials the
    star to the SBC; stripping it → bare ``9225`` gets 603 Decline.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    star = raw.startswith("*")
    digits = identity.normalize_phone_label(raw)
    if digits:
        return f"*{digits}" if star else digits
    return raw.lstrip("+")


def parse_address(addr: Any) -> dict[str, Any]:
    if not addr:
        return {"type": "unknown", "value": addr, "full": addr}
    value = str(addr).strip()
    if value and value[0] in "0123456789*+" and len(value) <= 21 and all(
        c.isdigit() or c in "*+" for c in value
    ):
        return {"type": "raw", "value": value, "full": value}
    if "@" in value and not value.endswith(".global"):
        local, _, domain = value.partition("@")
        if local and domain and "." in domain:
            return {"type": "email", "value": value, "full": value}
    # foo.bar.global or foo.secnum.global.
    # PSTN trunks still force 972….cellactm.global / cellactl.global — that is
    # a DID label, not an ENS name.
    if value.endswith(".global"):
        parts = value.split(".")
        if len(parts) >= 3:
            domain = ".".join(parts[-2:])
            label = ".".join(parts[:-2])
            digits = identity.normalize_phone_label(label)
            if len(digits) >= 8:
                return {"type": "raw", "value": digits, "full": digits}
            return {"type": "ens", "value": label, "domain": domain, "full": value}
        if len(parts) == 2:
            return {"type": "ens", "value": parts[0], "domain": value, "full": value}
    return {"type": "unknown", "value": value, "full": value}


def _log_route(msg: str) -> None:
    try:
        from siphon import log  # type: ignore

        log.info(msg)
    except Exception:  # noqa: BLE001
        print(f"[logic] {msg}", flush=True)


def is_product_route(route: Optional[dict[str, Any]]) -> bool:
    if not isinstance(route, dict):
        return False
    kind = str(route.get("route") or "").strip().lower()
    ptype = str(route.get("type") or "").strip().lower()
    return kind in PRODUCT_ROUTE_KINDS or ptype in PRODUCT_ROUTE_KINDS


def _req_headers(req: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    try:
        raw = getattr(req, "headers", None) or {}
        if isinstance(raw, dict):
            headers = {str(k).lower(): str(v) for k, v in raw.items()}
    except Exception:  # noqa: BLE001
        headers = {}
    return headers


def _header(req: Any, headers: dict[str, str], *names: str) -> str:
    for name in names:
        try:
            val = (req.header(name) if req is not None else None) or headers.get(name.lower())
        except Exception:  # noqa: BLE001
            val = headers.get(name.lower())
        if val:
            return str(val).strip()
    return ""


def _port_from_authority(host: str) -> Optional[int]:
    host = str(host or "").strip()
    if not host:
        return None
    if host.startswith("["):
        _, _, rest = host.partition("]")
        if rest.startswith(":"):
            try:
                return int(rest[1:].split("/")[0])
            except ValueError:
                return None
        return None
    if host.count(":") == 1:
        try:
            return int(host.rsplit(":", 1)[1].split("/")[0])
        except ValueError:
            return None
    return None


def resolve_notify_port(req: Any) -> tuple[Optional[int], str]:
    """Listen port the /notify TCP actually hit. Never invent 9001.

    siphon-http Request only has client=remote ip:port (docs). No local_port.
    HTTP/2 often omits Host; then we cannot see 9002 vs 9001 from headers.
    """
    headers = _req_headers(req)
    host = _header(req, headers, "host", ":authority", "authority")
    port = _port_from_authority(host)
    if port:
        return port, "authority"
    xfp = _header(req, headers, "x-forwarded-port")
    if xfp:
        try:
            return int(str(xfp).split(",")[0].strip()), "x-forwarded-port"
        except ValueError:
            pass
    for attr in (
        "local_port",
        "server_port",
        "listen_port",
        "local_addr",
        "server_addr",
    ):
        val = getattr(req, attr, None) if req is not None else None
        if val is None:
            continue
        if hasattr(val, "port"):
            try:
                return int(val.port), attr
            except (TypeError, ValueError):
                pass
        text = str(val)
        port = _port_from_authority(text) if ":" in text else None
        if port:
            return port, attr
        try:
            return int(val), attr
        except (TypeError, ValueError):
            continue
    return None, "unknown"


def notify_port_from_req(req: Any) -> Optional[int]:
    port, _src = resolve_notify_port(req)
    return port


def notify_req_probe(req: Any) -> str:
    """One-line dump so we can see why listen port was/wasn't recovered."""
    headers = _req_headers(req)
    attrs = []
    for name in (
        "client",
        "path",
        "method",
        "local_port",
        "server_port",
        "listen_port",
        "local_addr",
        "server_addr",
    ):
        if req is None or not hasattr(req, name):
            continue
        try:
            attrs.append(f"{name}={getattr(req, name)!r}")
        except Exception as exc:  # noqa: BLE001
            attrs.append(f"{name}=err:{exc}")
    return (
        f"hdr_host={(_header(req, headers, 'host') or '-')!r} "
        f"hdr_authority={(_header(req, headers, ':authority', 'authority') or '-')!r} "
        f"xfwd_port={(_header(req, headers, 'x-forwarded-port') or '-')!r} "
        f"hdr_keys={sorted(headers.keys())} {' '.join(attrs) or '-'}"
    )


def _identity_key(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    try:
        label = identity.identity_label(raw)
        if label:
            return str(label).strip().lower()
    except Exception:  # noqa: BLE001
        pass
    return raw


def remember_logic_sp(*identities: Any, logic_sp: str = "") -> None:
    sp = str(logic_sp or "").strip().lower()
    if not sp or not policy.logic_provider(sp):
        return
    for ident in identities:
        key = _identity_key(ident)
        if key:
            _sp_by_identity[key] = sp


def lookup_logic_sp(*identities: Any) -> Optional[str]:
    for ident in identities:
        key = _identity_key(ident)
        if key and key in _sp_by_identity:
            return _sp_by_identity[key]
    return None


def _route_pair_key(from_id: Any, to_id: Any) -> Optional[tuple[str, str]]:
    src = _identity_key(from_id)
    dst = _identity_key(to_id)
    if not src or not dst:
        return None
    return (src, dst)


def lookup_route_sp(from_id: Any, to_id: Any) -> Optional[str]:
    key = _route_pair_key(from_id, to_id)
    if not key:
        return None
    sp = _route_sp_by_pair.get(key)
    if sp and policy.logic_provider(sp):
        return sp
    return None


def remember_route_sp(from_id: Any, to_id: Any, logic_sp: str = "") -> None:
    key = _route_pair_key(from_id, to_id)
    sp = str(logic_sp or "").strip().lower()
    if not key or not sp or not policy.logic_provider(sp):
        return
    _route_sp_by_pair[key] = sp
    _log_route(f"route cache store from={key[0]!r} to={key[1]!r} sp={sp}")


def forget_route_sp(from_id: Any, to_id: Any) -> None:
    key = _route_pair_key(from_id, to_id)
    if key:
        _route_sp_by_pair.pop(key, None)
        _recording_sps_by_pair.pop(key, None)


def lookup_recording_sps(from_id: Any, to_id: Any) -> list[str]:
    key = _route_pair_key(from_id, to_id)
    if not key:
        return []
    out: list[str] = []
    for item in _recording_sps_by_pair.get(key) or []:
        sid = str(item or "").strip().lower()
        if sid and policy.logic_provider(sid) and sid not in out:
            out.append(sid)
    return out


def remember_recording_sps(from_id: Any, to_id: Any, sps: list[str]) -> None:
    key = _route_pair_key(from_id, to_id)
    if not key:
        return
    clean: list[str] = []
    for item in sps:
        sid = str(item or "").strip().lower()
        if sid and policy.logic_provider(sid) and sid not in clean:
            clean.append(sid)
    _recording_sps_by_pair[key] = clean


def _route_cache_usable(raw: Any) -> bool:
    return isinstance(raw, dict) and (
        _accept_claimed_route(raw, "") or _is_sbc_route(raw)
    )


def _provider_or_raise(logic_sp: str) -> dict[str, Any]:
    p = policy.logic_provider(logic_sp)
    if not p:
        raise RuntimeError(f"logic provider {logic_sp!r} is not configured")
    return p


def _post_logic(path: str, body: dict[str, Any], provider: dict[str, Any]) -> dict[str, Any]:
    base = str(provider.get("baseUrl") or "").strip().rstrip("/")
    if not base:
        raise RuntimeError(f"logic URL missing for {provider.get('id')}")
    url = f"{base}{path if path.startswith('/') else '/' + path}"
    timeout = max(0.5, int(provider.get("timeoutMs") or 3000) / 1000.0)
    _log_route(f"logic POST sp={provider.get('id')} {url} keys={sorted(body.keys())}")
    resp = _http.post(url, json=body, timeout=timeout)
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        data = {}
    if not isinstance(data, dict):
        data = {"raw": data}
    data["_httpStatus"] = resp.status_code
    data["_logicSp"] = provider.get("id")
    if resp.status_code >= 400 and "ok" not in data and "route" not in data and "action" not in data:
        data.setdefault("ok", False)
        data.setdefault("reason", f"http_{resp.status_code}")
    return data


async def _post_logic_async(
    path: str,
    body: dict[str, Any],
    provider: dict[str, Any],
) -> dict[str, Any]:
    return await asyncio.to_thread(_post_logic, path, body, provider)


def minutes_denied(data: Any) -> bool:
    """True only when the wrapper explicitly says this call must stop."""
    if not isinstance(data, dict):
        return False
    if data.get("allowed") is False:
        return True
    if "remainingMs" not in data or data.get("remainingMs") is None:
        return False
    try:
        return float(data.get("remainingMs")) <= 0
    except (TypeError, ValueError):
        return False


def minutes_remaining_ms(data: Any) -> Optional[float]:
    if not isinstance(data, dict) or "remainingMs" not in data or data.get("remainingMs") is None:
        return None
    try:
        return max(0.0, float(data.get("remainingMs")))
    except (TypeError, ValueError):
        return None


async def check_outgoing_minutes(logic_sp: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST /minutes. Missing route, timeout, and 5xx let the call through."""
    sp = str(logic_sp or "").strip().lower()
    if not sp:
        return {"ok": True, "allowed": True}
    try:
        provider = policy.logic_provider(sp)
        if not provider:
            return {"ok": True, "allowed": True}
        data = await _post_logic_async("/minutes", body, provider)
    except Exception as exc:  # noqa: BLE001
        _log_route(f"minutes fail-open sp={sp}: {exc}")
        return {"ok": True, "allowed": True}
    if not isinstance(data, dict):
        return {"ok": True, "allowed": True}
    try:
        status = int(data.get("_httpStatus") or 0)
    except (TypeError, ValueError):
        status = 0
    if status == 0 or status == 404 or status >= 500:
        _log_route(f"minutes fail-open sp={sp} http={status}")
        return {"ok": True, "allowed": True}
    if status >= 400 and data.get("allowed") is not False:
        return {"ok": True, "allowed": True}
    return data


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _service_account_json() -> Optional[dict[str, Any]]:
    for path in _SA_JSON_CANDIDATES:
        p = str(path or "").strip()
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(data, dict) and data.get("client_email") and data.get("private_key"):
            return data
    return None


def _mint_gcp_id_token(audience: str) -> str:
    """Same flow as Node identityMappingAuthService: SA JWT → Google id_token."""
    aud = str(audience or "").strip().split("?")[0]
    if not aud:
        raise RuntimeError("recording audience missing")
    now = int(time.time())
    cached = _id_token_cache.get(aud)
    if cached and cached[1] - now > 120:
        return cached[0]
    sa = _service_account_json()
    if not sa:
        raise RuntimeError(
            "kamailio-gcp-mapping SA JSON not found "
            "(GCP_SERVICE_ACCOUNT_JSON_FILE or /etc/kamailio/sip_code/secrets/kamailio-gcp-mapping-sa.json)"
        )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    oauth = str(sa.get("token_uri") or "https://oauth2.googleapis.com/token")
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps(
            {
                "iss": sa["client_email"],
                "sub": sa["client_email"],
                "aud": oauth,
                "iat": now,
                "exp": now + 3600,
                "target_audience": aud,
            },
            separators=(",", ":"),
        ).encode()
    )
    unsigned = f"{header}.{payload}".encode()
    key = serialization.load_pem_private_key(str(sa["private_key"]).encode(), password=None)
    sig = key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
    assertion = f"{unsigned.decode()}.{_b64url(sig)}"
    resp = _http.post(
        oauth,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        timeout=10,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"gcp id_token mint http_{resp.status_code}: {resp.text[:200]}")
    token = str((resp.json() or {}).get("id_token") or "").strip()
    if not token:
        raise RuntimeError("gcp id_token mint missing id_token")
    exp = now + 3600
    try:
        pad = "=" * ((4 - len(token.split(".")[1]) % 4) % 4)
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + pad))
        exp = int(claims.get("exp") or exp)
    except Exception:  # noqa: BLE001
        pass
    _id_token_cache[aud] = (token, exp)
    return token


def _post_recording_wav(provider: dict[str, Any], headers: dict[str, str], wav: bytes) -> dict[str, Any]:
    base = str(provider.get("baseUrl") or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("logic URL missing for recording upload")
    url = f"{base}/recording"
    token = _mint_gcp_id_token(base)
    hdrs = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "audio/wav",
        **headers,
    }
    timeout = 120.0
    _log_route(
        f"logic POST recording sp={provider.get('id')} {url} bytes={len(wav)} "
        f"callId={headers.get('x-call-id')!r} auth=sa-id-token"
    )
    resp = _http.post(url, data=wav, headers=hdrs, timeout=timeout)
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        data = {}
    if not isinstance(data, dict):
        data = {"raw": data}
    data["_httpStatus"] = resp.status_code
    if resp.status_code >= 400:
        data.setdefault("ok", False)
        data.setdefault("reason", f"http_{resp.status_code}")
    return data


async def post_recording_wav(
    provider: dict[str, Any], headers: dict[str, str], wav: bytes
) -> dict[str, Any]:
    return await asyncio.to_thread(_post_recording_wav, provider, headers, wav)


def fetch_voicemail_greeting(provider: dict[str, Any], sha: str) -> bytes:
    """Current greeting wav from the wrapper. One download per no-answer."""
    base = str(provider.get("baseUrl") or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("logic URL missing for voicemail greeting")
    url = f"{base}/voicemail-greeting"
    token = _mint_gcp_id_token(base)
    resp = _http.post(
        url,
        json={"sha": sha},
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=20.0,
    )
    if resp.status_code >= 400 or not resp.content.startswith(b"RIFF"):
        raise RuntimeError(
            f"voicemail greeting http_{resp.status_code} bytes={len(resp.content)}"
        )
    return resp.content


def _is_claimed_route(decision: dict[str, Any]) -> bool:
    kind = str(decision.get("route") or "").strip().lower()
    return kind in CLAIMED_ROUTE_KINDS


def _is_sbc_route(raw: dict[str, Any]) -> bool:
    """Default trunk. Not a claim — only used when no SP owns the dest."""
    if not isinstance(raw, dict) or not _http_ok(raw):
        return False
    d = normalize_route_decision(raw)
    if str(d.get("route") or "").strip().lower() != "sbc":
        return False
    return bool(d.get("host") or d.get("sbcAddress") or d.get("number"))


def _http_ok(raw: dict[str, Any]) -> bool:
    status = int(raw.get("_httpStatus") or 0)
    if status >= 400:
        return False
    if raw.get("ok") is False:
        return False
    return True


async def _fanout_first_good(
    path: str,
    body: dict[str, Any],
    *,
    accept,
    fallback=None,
    hold_sp: str = "",
    hold_raw_out: Optional[list[dict[str, Any]]] = None,
    cli_raw_out: Optional[list[dict[str, Any]]] = None,
    recording_sps_out: Optional[list[str]] = None,
    wait_all: bool = False,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Hit every SP in parallel. First *claimed/good* response wins; cancel the rest.

    Dest /route uses wait_all so the caller wrapper can still return callerId
    (cover DID). Siphon never invents CLI. With wait_all, a claim from an
    earlier logicProviders entry beats a later one (esimera is last).
    """
    providers = policy.logic_providers()
    if not providers:
        return None, None
    rank = {
        str(p.get("id") or "").strip().lower(): i for i, p in enumerate(providers)
    }
    claims: list[tuple[int, dict[str, Any], str]] = []
    tasks = {
        asyncio.create_task(_post_logic_async(path, body, p)): p for p in providers
    }
    hold_key = str(hold_sp or "").strip().lower()
    hold_done = not bool(hold_key)
    winner: Optional[dict[str, Any]] = None
    winner_sp: Optional[str] = None
    fallback_raw: Optional[dict[str, Any]] = None
    fallback_sp: Optional[str] = None
    pending: set[asyncio.Task] = set(tasks)

    def _task_sp(task: asyncio.Task) -> str:
        return str(tasks[task].get("id") or "").strip().lower()

    def _keep_hold() -> set[asyncio.Task]:
        keep: set[asyncio.Task] = set()
        for leftover in pending:
            if hold_key and not hold_done and _task_sp(leftover) == hold_key:
                keep.add(leftover)
            else:
                leftover.cancel()
        return keep

    try:
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            pending = set(pending)
            claimed_now = False
            for task in done:
                prov = tasks[task]
                sp = str(prov.get("id") or "")
                try:
                    raw = task.result()
                except Exception as exc:  # noqa: BLE001
                    _log_route(f"logic fan-out sp={sp} {path} failed: {exc}")
                    if hold_key and sp.strip().lower() == hold_key:
                        hold_done = True
                    continue
                if hold_key and sp.strip().lower() == hold_key:
                    hold_done = True
                    if isinstance(raw, dict) and hold_raw_out is not None:
                        hold_raw_out.clear()
                        hold_raw_out.append(raw)
                if not isinstance(raw, dict) or not _http_ok(raw):
                    _log_route(
                        f"logic fan-out sp={sp} {path} miss status={raw.get('_httpStatus') if isinstance(raw, dict) else '-'}"
                    )
                    continue
                if cli_raw_out is not None and (_route_caller_id(raw) or _route_privacy(raw)):
                    cli_raw_out.append(raw)
                if (
                    recording_sps_out is not None
                    and bool(raw.get("callRecordingEnabled"))
                ):
                    sid = sp.strip().lower()
                    if sid and sid not in recording_sps_out:
                        recording_sps_out.append(sid)
                if accept(raw, sp):
                    if wait_all:
                        claims.append((rank.get(sp.strip().lower(), 10_000), raw, sp))
                    elif winner is None:
                        winner, winner_sp = raw, sp
                        claimed_now = True
                    continue
                if (
                    fallback is not None
                    and fallback_raw is None
                    and fallback(raw, sp)
                ):
                    fallback_raw, fallback_sp = raw, sp
            if wait_all:
                continue
            if claimed_now:
                pending = _keep_hold()
            if winner is not None and (hold_done or not pending):
                for leftover in pending:
                    leftover.cancel()
                pending.clear()
                break
    finally:
        for leftover in pending:
            leftover.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    if wait_all and claims:
        claims.sort(key=lambda item: item[0])
        return claims[0][1], claims[0][2]
    if winner is not None:
        return winner, winner_sp
    return fallback_raw, fallback_sp


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _host_from_decision(raw: dict[str, Any]) -> str:
    for key in ("host", "ip", "domain", "sbc", "sbcAddress", "nextHop", "address"):
        val = str(raw.get(key) or "").strip()
        if val:
            return val
    return ""


def _truthy_is_extension(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("true", "1", "yes")


def _extension_fields(raw: dict[str, Any]) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    if _truthy_is_extension(raw.get("isExtension")):
        extras["isExtension"] = True
    item_id = str(raw.get("productItemId") or "").strip()
    if item_id:
        extras["productItemId"] = item_id
    return extras


def _caller_id_digits(raw: Any) -> str:
    return "".join(ch for ch in str(raw or "") if ch.isdigit())


def _route_caller_id(raw: dict[str, Any]) -> dict[str, Any]:
    caller_id = _caller_id_digits(raw.get("callerId"))
    return {"callerId": caller_id} if len(caller_id) >= 8 else {}


def _route_privacy(raw: dict[str, Any]) -> dict[str, Any]:
    value = str(raw.get("privacy") or "").strip().lower()
    return {"privacy": "id"} if value == "id" else {}


def _targets_from_decision(raw: dict[str, Any]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for item in _as_list(raw.get("targets")):
        if isinstance(item, dict):
            ident = (
                item.get("notifyIdentity")
                or item.get("ensName")
                or item.get("number")
                or item.get("to")
                or ""
            )
            row = {
                "notifyIdentity": str(ident),
                "ensName": str(item.get("ensName") or ident),
                "wallet": item.get("wallet"),
                "number": str(item.get("number") or ident),
            }
            row.update(_extension_fields(item))
            targets.append(row)
        elif item:
            ident = str(item)
            targets.append(
                {
                    "notifyIdentity": ident,
                    "ensName": ident,
                    "wallet": None,
                    "number": ident,
                }
            )
    for item in _as_list(raw.get("numbers")):
        ident = str(item.get("number") if isinstance(item, dict) else item)
        if ident:
            targets.append(
                {
                    "notifyIdentity": ident,
                    "ensName": ident,
                    "wallet": item.get("wallet") if isinstance(item, dict) else None,
                    "number": ident,
                }
            )
    return [t for t in targets if t.get("notifyIdentity") or t.get("number")]


def _route_recording_fields(raw: dict[str, Any]) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    extras["callRecordingEnabled"] = bool(raw.get("callRecordingEnabled"))
    try:
        extras["ringTimeoutSeconds"] = int(raw.get("ringTimeoutSeconds") or 25)
    except (TypeError, ValueError):
        extras["ringTimeoutSeconds"] = 25
    sys_id = str(raw.get("systemId") or "").strip()
    if sys_id:
        extras["systemId"] = sys_id
    digits = "".join(ch for ch in str(raw.get("number") or "") if ch.isdigit())
    if len(digits) >= 8:
        extras["number"] = digits
    no_ans = raw.get("noAnswer")
    if isinstance(no_ans, dict):
        sip_uri = str(no_ans.get("sipUri") or no_ans.get("uri") or "").strip()
        text = str(no_ans.get("text") or "").strip()
        # mode alone is the stock sentence: voicemail on, no text, no bot.
        if sip_uri or text or str(no_ans.get("mode") or "").strip():
            na_num = "".join(ch for ch in str(no_ans.get("number") or "") if ch.isdigit())
            parsed: dict[str, Any] = {
                "route": str(no_ans.get("route") or "external-sip").strip() or "external-sip",
                "mode": str(no_ans.get("mode") or "voicemail").strip() or "voicemail",
                "systemId": str(no_ans.get("systemId") or sys_id or "").strip() or None,
                "number": na_num if len(na_num) >= 8 else (extras.get("number") or None),
                "businessName": str(no_ans.get("businessName") or "").strip() or None,
                "language": str(no_ans.get("language") or "").strip() or None,
                "callRecordingEnabled": bool(
                    no_ans.get("callRecordingEnabled", True)
                ),
                "recordingEmail": str(no_ans.get("recordingEmail") or "").strip() or None,
            }
            if sip_uri:
                parsed["sipUri"] = sip_uri
            if text:
                parsed["text"] = text
            sha = str(no_ans.get("greetingSha") or "").strip().lower()
            if len(sha) == 64:
                parsed["greetingSha"] = sha
            extras["noAnswer"] = parsed
    return extras


def normalize_route_decision(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Map logic-service JSON onto SIPhon route dicts."""
    if not isinstance(raw, dict):
        return {"route": "reject", "reason": "Invalid route response", "statusCode": 502}
    if raw.get("route") == "reject" or raw.get("ok") is False:
        return {
            "route": "reject",
            "reason": str(raw.get("reason") or raw.get("error") or "rejected"),
            "statusCode": int(raw.get("statusCode") or raw.get("_httpStatus") or 403),
        }

    targets = _targets_from_decision(raw)
    ptype = str(raw.get("type") or "").strip().lower()
    declared = str(raw.get("route") or "").strip().lower()
    host = _host_from_decision(raw)
    number = str(raw.get("number") or raw.get("target") or raw.get("to") or "").strip()
    if not number and len(targets) == 1:
        number = str(targets[0].get("number") or targets[0].get("notifyIdentity") or "")

    if declared == "webrtc-multiring" or len(targets) > 1:
        out = {
            "route": "webrtc-multiring",
            "targets": targets,
            "numbers": [t.get("number") or t.get("notifyIdentity") for t in targets],
            "mode": raw.get("mode"),
            "groupId": raw.get("groupId"),
            "wallet": (targets[0].get("wallet") if targets else raw.get("wallet")),
            "notifyIdentity": (targets[0].get("notifyIdentity") if targets else number),
        }
        out.update(_route_recording_fields(raw))
        out.update(_extension_fields(raw))
        out.update(_route_caller_id(raw))
        return out

    if declared in PRODUCT_ROUTE_KINDS or ptype in PRODUCT_ROUTE_KINDS:
        kind = declared if declared in PRODUCT_ROUTE_KINDS else ptype
        if kind == "openai":
            kind = "openai-sip"
        sip_uri = str(raw.get("sipUri") or raw.get("uri") or "").strip()
        if not number and sip_uri:
            user, _, _rest = sip_uri.replace("sip:", "", 1).partition("@")
            number = str(user or "").strip()
        if not number and not sip_uri:
            return {
                "route": "reject",
                "reason": "product route missing sipUri/number",
                "statusCode": 501,
            }
        out = {
            "route": kind,
            "type": ptype or kind,
            "number": number,
            "target": raw.get("target") or "openai-realtime",
            "sipUri": sip_uri,
        }
        out.update({k: v for k, v in raw.items() if k not in out and not str(k).startswith("_")})
        return out

    if declared == "sbc" or (number and host):
        out = {
            "route": "sbc",
            "number": number or normalize_phone(raw.get("to")),
            "host": host,
            "sbcAddress": host or str(raw.get("sbcAddress") or ""),
        }
        caller_id = _caller_id_digits(raw.get("callerId"))
        if caller_id:
            out["callerId"] = caller_id
        out.update(_route_privacy(raw))
        out.update(_route_recording_fields(raw))
        return out

    if declared == "webrtc" or (number and not host) or raw.get("wallet") or raw.get("ensName"):
        ident = str(
            raw.get("notifyIdentity")
            or raw.get("ensName")
            or number
            or (targets[0].get("notifyIdentity") if targets else "")
        )
        out = {
            "route": "webrtc",
            "wallet": raw.get("wallet") or (targets[0].get("wallet") if targets else None),
            "ensName": raw.get("ensName") or ident,
            "targetValue": raw.get("targetValue") or number or ident,
            "walletSource": raw.get("walletSource") or "logic",
            "notifyIdentity": ident,
            **_route_recording_fields(raw),
            **_route_caller_id(raw),
        }
        out.update(_extension_fields(raw))
        if not out.get("productItemId") and targets:
            out.update(_extension_fields(targets[0]))
        return out

    if declared:
        out = dict(raw)
        out["route"] = declared
        return out
    return {"route": "reject", "reason": "Unrecognized route response", "statusCode": 502}


async def authenticate_offer(
    payload: dict[str, Any],
    *,
    origin: str = "client",
    logic_sp: str = "",
) -> dict[str, Any]:
    """POST /auth. Raises IdentityError on deny. Skip caller-side when origin=sbc.

    Known SP: that wrapper only. Unknown listen port: try each configured
    provider in config order; first ok wins.
    """
    if origin == "sbc":
        return {"ok": True, "skipped": True, "origin": "sbc"}
    pinned = str(logic_sp or "").strip().lower()
    if pinned:
        providers = [_provider_or_raise(pinned)]
    else:
        providers = list(policy.logic_providers())
        if not providers:
            raise identity.IdentityError(400, "unknown notify port / service provider")
        _log_route(
            f"auth fan-out origin={origin} from={payload.get('from')!r} "
            f"sps={[p.get('id') for p in providers]}"
        )
    last_exc: Optional[BaseException] = None
    for provider in providers:
        sp = str(provider.get("id") or "").strip().lower()
        try:
            return await _authenticate_offer_one(payload, origin=origin, provider=provider)
        except identity.IdentityError as exc:
            last_exc = exc
            _log_route(
                f"auth try sp={sp} from={payload.get('from')!r} "
                f"fail={exc.status_code} {exc}"
            )
            if pinned or len(providers) == 1:
                raise
            continue
        except Exception as exc:  # noqa: BLE001
            last_exc = identity.IdentityError(503, f"auth service unreachable: {exc}")
            _log_route(f"auth try sp={sp} from={payload.get('from')!r} unreachable: {exc}")
            if pinned or len(providers) == 1:
                raise last_exc from exc
            continue
    if last_exc is not None:
        raise last_exc
    raise identity.IdentityError(401, "authentication failed")


async def _authenticate_offer_one(
    payload: dict[str, Any],
    *,
    origin: str,
    provider: dict[str, Any],
) -> dict[str, Any]:
    sp = str(provider.get("id") or "").strip().lower()
    body = {
        "origin": origin,
        "from": payload.get("from"),
        "to": payload.get("to"),
        "sdp": payload.get("sdp"),
        "sessionId": payload.get("sessionId"),
        "xsign": payload.get("xsign") or payload.get("x-sign"),
        "xdata": payload.get("xdata") or payload.get("x-data"),
        "type": payload.get("type") or "offer",
    }
    try:
        data = await _post_logic_async("/auth", body, provider)
    except Exception as exc:  # noqa: BLE001
        raise identity.IdentityError(503, f"auth service unreachable: {exc}") from exc
    status = int(data.get("_httpStatus") or 0)
    ok = data.get("ok")
    if status >= 400 or ok is False:
        raise identity.IdentityError(
            int(data.get("statusCode") or (status if status >= 400 else 401)),
            str(data.get("reason") or data.get("error") or "authentication failed"),
        )
    remember_logic_sp(body.get("from"), logic_sp=sp)
    data["logicSp"] = sp
    _log_route(
        f"auth ok sp={sp} origin={origin} from={body.get('from')!r} "
        f"mode={data.get('mode')} signer={data.get('signer')}"
    )
    return data


def _accept_claimed_route(raw: dict[str, Any], _sp: str) -> bool:
    """Provider owns this dest (webrtc/product). SBC is never a claim.

    Lightpbx DID maps return route=sbc + routingSource. That used to win
    fan-out over secnum webrtc. Trunk is the fallback when nobody claims.
    """
    if not isinstance(raw, dict) or not _http_ok(raw):
        return False
    d = normalize_route_decision(raw)
    if str(d.get("route") or "").strip().lower() == "sbc":
        return False
    if str(raw.get("routingSource") or d.get("routingSource") or "").strip():
        return True
    return _is_claimed_route(d)


async def resolve_destination(
    parsed_to: Optional[dict[str, Any]],
    parsed_from: Optional[dict[str, Any]] = None,
    *,
    origin: str = "client",
    to: str = "",
    from_id: str = "",
    session_id: str = "",
    kind: str = "outbound",
    logic_sp: str = "",
    diversion: str = "",
    to_domain: str = "",
    pin_sp: str = "",
) -> dict[str, Any]:
    if not parsed_to and not to:
        return {"route": "reject", "reason": "Missing destination"}
    body = {
        "kind": kind,
        "origin": origin,
        "from": from_id or (parsed_from or {}).get("full"),
        "to": to or (parsed_to or {}).get("full"),
        "sessionId": session_id or None,
        "parsedTo": parsed_to,
        "parsedFrom": parsed_from,
    }
    div = str(diversion or "").strip()
    domain = str(to_domain or "").strip()
    if div:
        body["diversion"] = div
    if domain:
        body["toDomain"] = domain
    to_id = str(body.get("to") or "")
    from_val = str(body.get("from") or "")
    clean_to = policy.strip_plus_and_domain_suffix(to_id) or to_id
    clean_from = policy.strip_plus_and_domain_suffix(from_val) or from_val
    if clean_to != to_id:
        to_id = clean_to
        body["to"] = to_id
        parsed_to = parse_address(to_id)
        body["parsedTo"] = parsed_to
    if clean_from != from_val:
        from_val = clean_from
        body["from"] = from_val
        parsed_from = parse_address(from_val)
        body["parsedFrom"] = parsed_from
    raw: Optional[dict[str, Any]] = None
    sp = ""
    from_cache = False
    caller_hold: list[dict[str, Any]] = []
    cli_hold: list[dict[str, Any]] = []
    recording_sps: list[str] = []
    pin = str(pin_sp or "").strip()
    cached_sp = lookup_route_sp(from_val, to_id)
    if pin and cached_sp and cached_sp.strip().lower() != pin.lower():
        _log_route(
            f"route cache skip pin={pin} cached={cached_sp} "
            f"from={from_val!r} to={to_id!r}"
        )
        cached_sp = ""
    if cached_sp:
        try:
            cached_raw = await _post_logic_async(
                "/route", body, _provider_or_raise(cached_sp)
            )
        except Exception as exc:  # noqa: BLE001
            forget_route_sp(from_val, to_id)
            _log_route(
                f"route cache drop from={from_val!r} to={to_id!r} "
                f"sp={cached_sp} err={exc}"
            )
        else:
            if _route_cache_usable(cached_raw):
                raw, sp = cached_raw, cached_sp
                from_cache = True
                _log_route(
                    f"route cache hit from={from_val!r} to={to_id!r} sp={cached_sp}"
                )
            else:
                forget_route_sp(from_val, to_id)
                status = (
                    cached_raw.get("_httpStatus") if isinstance(cached_raw, dict) else "-"
                )
                _log_route(
                    f"route cache drop from={from_val!r} to={to_id!r} "
                    f"sp={cached_sp} status={status}"
                )
    if not from_cache and pin:
        try:
            pinned_raw = await _post_logic_async(
                "/route", body, _provider_or_raise(pin)
            )
        except Exception as exc:  # noqa: BLE001
            _log_route(f"resolveDestination: pin={pin} unreachable: {exc}")
            return {
                "route": "reject",
                "reason": f"route service unreachable: {exc}",
                "statusCode": 503,
            }
        if isinstance(pinned_raw, dict) and _http_ok(pinned_raw):
            raw, sp = pinned_raw, pin
            if _route_caller_id(pinned_raw) or _route_privacy(pinned_raw):
                cli_hold.append(pinned_raw)
            if bool(pinned_raw.get("callRecordingEnabled")) and pin.lower() not in recording_sps:
                recording_sps.append(pin.lower())
        else:
            status = pinned_raw.get("_httpStatus") if isinstance(pinned_raw, dict) else "-"
            _log_route(f"resolveDestination: pin={pin} miss status={status}")
            return {
                "route": "reject",
                "reason": "no logic provider claimed destination",
                "statusCode": 404,
            }
    elif not from_cache:
        try:
            fan_raw, fan_sp = await _fanout_first_good(
                "/route",
                body,
                accept=_accept_claimed_route,
                fallback=lambda r, _s: _is_sbc_route(r),
                hold_sp=str(logic_sp or ""),
                hold_raw_out=caller_hold,
                cli_raw_out=cli_hold,
                recording_sps_out=recording_sps,
                wait_all=True,
            )
            if fan_raw is not None:
                raw, sp = fan_raw, str(fan_sp or "")
            else:
                return {
                    "route": "reject",
                    "reason": "no logic provider claimed destination",
                    "statusCode": 404,
                }
            # Nobody owns `to`. The authenticator of `from` owns the trunk
            # (Dutch vs Israeli). Another wrapper's sbc body is their trunk.
            auth = str(logic_sp or "").strip()
            if auth and not _accept_claimed_route(raw, sp):
                caller_sbc = next((b for b in caller_hold if _is_sbc_route(b)), None)
                if caller_sbc is None:
                    _log_route(f"resolveDestination: caller trunk miss sp={auth}")
                    return {
                        "route": "reject",
                        "reason": "no logic provider claimed destination",
                        "statusCode": 404,
                    }
                _log_route(
                    f"resolveDestination: caller trunk sp={auth} "
                    f"fallbackSp={sp or '-'}"
                )
                raw, sp = caller_sbc, auth
        except Exception as exc:  # noqa: BLE001
            _log_route(f"resolveDestination: logic unreachable: {exc}")
            return {"route": "reject", "reason": f"route service unreachable: {exc}", "statusCode": 503}
    if not raw:
        return {"route": "reject", "reason": "no logic provider claimed destination", "statusCode": 404}
    claimed = _accept_claimed_route(raw, sp or "")
    if not claimed and not _is_sbc_route(raw):
        return {"route": "reject", "reason": "no logic provider claimed destination", "statusCode": 404}
    if not from_cache:
        # Claim caches the owner. An unclaimed trunk caches the wrapper whose
        # SBC body we kept (the caller provider after the trunk swap).
        remember_route_sp(from_val, to_id, sp)
    decision = normalize_route_decision(raw)
    if not decision.get("callerId"):
        for blob in (*cli_hold, *caller_hold):
            decision.update(_route_caller_id(blob))
            if decision.get("callerId"):
                break
    if str(decision.get("privacy") or "").strip().lower() != "id":
        for blob in (*cli_hold, *caller_hold):
            privacy = _route_privacy(blob)
            if privacy:
                decision.update(privacy)
                break
    if not decision.get("callerId") and str(logic_sp or "").strip():
        try:
            extra = await _post_logic_async(
                "/route", body, _provider_or_raise(str(logic_sp))
            )
            if isinstance(extra, dict) and _http_ok(extra):
                decision.update(_route_caller_id(extra))
                _log_route(
                    f"resolveDestination: callerId pin sp={logic_sp} "
                    f"cli={decision.get('callerId') or '-'}"
                )
        except Exception as exc:  # noqa: BLE001
            _log_route(f"resolveDestination: callerId pin sp={logic_sp} failed: {exc}")
    src = str(raw.get("routingSource") or "").strip()
    if src:
        decision["routingSource"] = src
    if from_cache:
        for sid in lookup_recording_sps(from_val, to_id):
            if sid not in recording_sps:
                recording_sps.append(sid)
    else:
        remember_recording_sps(from_val, to_id, recording_sps)
    winner_sp = str(sp or "").strip().lower()
    if isinstance(raw, dict) and bool(raw.get("callRecordingEnabled")) and winner_sp:
        if winner_sp not in recording_sps:
            recording_sps.append(winner_sp)
    if recording_sps:
        decision["callRecordingEnabled"] = True
        decision["recordingSps"] = recording_sps
    if sp:
        remember_logic_sp(to_id, logic_sp=sp)
        decision["logicSp"] = sp
    ext_n = sum(1 for t in (decision.get("targets") or []) if t.get("isExtension"))
    _log_route(
        f"resolveDestination: sp={decision.get('logicSp') or sp or '-'} origin={origin} "
        f"to={to_id!r} route={decision.get('route')} host={decision.get('host') or '-'} "
        f"targets={len(decision.get('targets') or [])} destFanout={not from_cache} "
        f"claimed={claimed} "
        f"isExtension={bool(decision.get('isExtension'))} extTargets={ext_n} "
        f"productItemId={decision.get('productItemId') or '-'} "
        f"record={bool(decision.get('callRecordingEnabled'))} "
        f"recordingSps={decision.get('recordingSps') or '-'} "
        f"did={decision.get('number') or '-'} "
        f"cli={decision.get('callerId') or '-'} callerHint={str(logic_sp or '-')}"
    )
    return decision


def _as_step(item: Any) -> Optional[dict[str, str]]:
    if not isinstance(item, dict):
        return None
    return {
        "url": str(item.get("url") or ""),
        "method": str(item.get("method") or ""),
        "contentType": str(item.get("contentType") or item.get("content_type") or ""),
        "body": str(item.get("body") or ""),
        "headers": str(item.get("headers") or "{}"),
        "fallbackUrl": str(item.get("fallbackUrl") or item.get("fallback_url") or ""),
        "responseExtractField": str(
            item.get("responseExtractField") or item.get("response_extract_field") or ""
        ),
        "placeholderKey": str(item.get("placeholderKey") or item.get("placeholder_key") or ""),
        "protocol": str(item.get("protocol") or ""),
    }


def _accept_notify_plan(raw: dict[str, Any], _sp: str) -> bool:
    steps = raw.get("steps") or raw.get("plan") or []
    return isinstance(steps, list) and any(_as_step(item) for item in steps)


async def fetch_notify_plan(
    *,
    from_id: str,
    to_id: str,
    message: str,
    notification_type: int,
    target_wallet: str = "",
    session_id: str = "",
    logic_sp: str = "",
) -> dict[str, Any]:
    """POST /notify-plan — GCP owns plan fetch. Fail closed. No chain fallback."""
    body = {
        "from": from_id,
        "to": to_id,
        "message": message,
        "notificationType": notification_type,
        "targetWallet": target_wallet or None,
        "sessionId": session_id or None,
    }
    pinned = str(logic_sp or lookup_logic_sp(to_id) or "").strip().lower()
    data: Optional[dict[str, Any]] = None
    sp = pinned
    try:
        if pinned:
            try:
                data = await _post_logic_async("/notify-plan", body, _provider_or_raise(pinned))
            except Exception as exc:  # noqa: BLE001
                _log_route(f"notify-plan pin sp={pinned} failed: {exc}")
                data = None
            if data is not None and (not _http_ok(data) or not _accept_notify_plan(data, pinned)):
                _log_route(
                    f"notify-plan pin miss sp={pinned} "
                    f"status={data.get('_httpStatus') if isinstance(data, dict) else '-'}"
                )
                data = None
            else:
                sp = pinned
        if data is None or not _accept_notify_plan(data, sp or ""):
            fan_raw, fan_sp = await _fanout_first_good(
                "/notify-plan", body, accept=_accept_notify_plan
            )
            if fan_raw is not None:
                data, sp = fan_raw, fan_sp
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"notify-plan unreachable: {exc}") from exc
    if not data:
        raise RuntimeError("notify-plan: no provider returned a plan")
    status = int(data.get("_httpStatus") or 0)
    if status >= 400 or data.get("ok") is False:
        raise RuntimeError(
            str(data.get("reason") or data.get("error") or f"notify-plan http_{status}")
        )
    raw_steps = data.get("steps") or data.get("plan") or []
    if not isinstance(raw_steps, list):
        raw_steps = []
    steps = [s for s in (_as_step(item) for item in raw_steps) if s]
    if not steps:
        raise RuntimeError("notify-plan returned no steps")
    if sp:
        remember_logic_sp(to_id, logic_sp=sp)
    wallet = str(data.get("targetWallet") or data.get("wallet") or target_wallet or "")
    signaling_to = str(data.get("to") or data.get("notifyIdentity") or to_id or "")
    _log_route(
        f"notify-plan ok sp={sp or '-'} from={from_id!r} to={signaling_to or to_id!r} "
        f"requested={to_id!r} steps={len(steps)} wallet={wallet or '-'}"
    )
    return {
        "steps": steps,
        "targetWallet": wallet,
        "to": signaling_to,
        "raw": data,
        "logicSp": sp,
    }


async def decide_action(
    session: dict[str, Any],
    msg: dict[str, Any],
    *,
    digit: Any = None,
    action: str = "",
) -> dict[str, Any]:
    """POST /action for product-leg DTMF/buttons. Default: forward as usual (none)."""
    route = session.get("route") or {}
    raw_digit = (
        digit
        if digit is not None
        else msg.get("digit") or (msg.get("payload") or {}).get("digit")
    )
    src = str(msg.get("source") or "dc").strip().lower() or "dc"
    sp = str(
        session.get("logicSp")
        or (route or {}).get("logicSp")
        or lookup_logic_sp(session.get("to"), session.get("from"))
        or ""
    ).strip().lower()
    if not sp:
        _log_route("action: no logicSp on session → forwardDtmf")
        return {
            "action": "none",
            "forwardDtmf": True,
            "digit": raw_digit,
            "source": src,
            "reason": "no logicSp",
        }
    hop = int(session.get("dtmfCount") or 0)
    session["dtmfCount"] = hop + 1
    body = {
        "origin": session.get("routeKind") or "client",
        "from": session.get("from"),
        "to": session.get("to"),
        "sessionId": session.get("sessionId"),
        "digit": raw_digit,
        "action": action or msg.get("action") or msg.get("msgType"),
        "dtmfIndex": hop,
        "dtmfCount": hop + 1,
        "route": route.get("route"),
        "type": route.get("type"),
        "message": msg,
    }
    try:
        data = await _post_logic_async("/action", body, _provider_or_raise(sp))
    except Exception as exc:  # noqa: BLE001
        _log_route(f"action: logic unreachable: {exc} → forwardDtmf")
        return {
            "action": "none",
            "forwardDtmf": True,
            "digit": raw_digit,
            "dtmfIndex": hop,
            "dtmfCount": hop + 1,
            "source": src,
            "reason": str(exc),
        }
    if not isinstance(data, dict):
        data = {}
    try:
        status = int(data.get("_httpStatus") or 0)
    except (TypeError, ValueError):
        status = 0
    # A 4xx/5xx body is {ok:false, reason}. It has no action, and the old
    # parser turned that into forwardDtmf=false, so the digit was dropped.
    if status >= 400 or (data.get("ok") is False and not data.get("action")):
        reason = str(data.get("reason") or data.get("error") or f"http_{status}")
        _log_route(f"action: logic error sp={sp} {reason} → forwardDtmf")
        return {
            "action": "none",
            "forwardDtmf": True,
            "digit": raw_digit,
            "dtmfIndex": hop,
            "dtmfCount": hop + 1,
            "source": src,
            "reason": reason,
        }
    decision = dict(data)
    decision["action"] = str(data.get("action") or "none").strip().lower() or "none"
    if data.get("forwardDtmf") is not None:
        decision["forwardDtmf"] = bool(data.get("forwardDtmf"))
    else:
        decision["forwardDtmf"] = decision["action"] == "forward"
    decision["target"] = str(
        data.get("target") or data.get("notifyIdentity") or data.get("number") or ""
    )
    decision["digit"] = data.get("digit", body.get("digit"))
    decision["dtmfIndex"] = data.get("dtmfIndex", hop)
    decision["dtmfCount"] = data.get("dtmfCount", hop + 1)
    decision["source"] = src
    decision["logicSp"] = sp
    if data.get("route") in ("webrtc", "webrtc-multiring"):
        decision.update(normalize_route_decision(data))
        decision["action"] = "transfer"
    ext_n = sum(1 for t in (decision.get("targets") or []) if t.get("isExtension"))
    _log_route(
        f"action sp={sp} session={session.get('sessionId')} digit={decision.get('digit')!r} "
        f"dtmfIndex={decision.get('dtmfIndex')} "
        f"→ {decision.get('action')} forwardDtmf={bool(decision.get('forwardDtmf'))} "
        f"reason={decision.get('reason') or '-'} "
        f"route={decision.get('route')!r} "
        f"target={decision.get('target')!r} "
        f"targets={len(decision.get('targets') or [])} "
        f"isExtension={bool(decision.get('isExtension'))} extTargets={ext_n} "
        f"productItemId={decision.get('productItemId') or '-'} "
        f"record={bool(decision.get('callRecordingEnabled'))} "
        f"did={decision.get('number') or '-'}"
    )
    return decision
