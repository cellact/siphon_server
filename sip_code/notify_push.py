"""Secnum notification push — port of NotificationApi plan execution."""

from __future__ import annotations

import json
import os
import time
import uuid
import asyncio
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

NOTI_TYPE_CALL = 0
# Response. Old realtime signaling was 4; that value is rejected by the new contracts.
NOTI_TYPE_REALTIME = 2

_ephemeral = Account.create()


def _replace_placeholders(template: Any, placeholders: dict[str, str]) -> Any:
    if template is None:
        return template
    result = str(template)
    for key, value in placeholders.items():
        result = result.replace(str(key), str(value))
    return result


def _escape_embedded_json(value: str) -> str:
    """Same escapes as NotificationService.sanitizeJsonBody."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _sanitize_json_body(body: str, message: str) -> str:
    """If a raw offer was dropped inside a JSON string, escape that substring.

    Valid JSON is left alone, so a VoIP body that is the offer itself stays raw.
    """
    if not body or not message:
        return body
    try:
        json.loads(body)
        return body
    except Exception:  # noqa: BLE001
        pass
    if message not in body:
        return body
    fixed = body.replace(message, _escape_embedded_json(message))
    try:
        json.loads(fixed)
    except Exception:  # noqa: BLE001
        _log_warn("notify_push: escaped body still not valid JSON")
        return body
    _log_info("notify_push: sanitized JSON body (escaped embedded message)")
    return fixed


def _extract_json_field(body: str, field: str) -> Optional[str]:
    try:
        obj = json.loads(body)
        cur: Any = obj
        for part in str(field or "").split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        if cur is None:
            return None
        return cur if isinstance(cur, str) else str(cur)
    except Exception:  # noqa: BLE001
        return None


def _handle_client_generate(fmt: str) -> str:
    if fmt == "uuid_timestamp":
        return f"{uuid.uuid4()}:{int(time.time())}"
    return uuid.uuid4().hex


def _handle_client_eth_sign(data_to_sign: str) -> str:
    msg = encode_defunct(text=data_to_sign)
    signed = _ephemeral.sign_message(msg)
    sig = signed.signature
    hex_sig = sig.hex() if hasattr(sig, "hex") else bytes(sig).hex()
    return hex_sig if hex_sig.startswith("0x") else f"0x{hex_sig}"


def _coerce_abi_arg(param_type: str, value: Any) -> Any:
    """Match ethers encodeFunctionData loose coercion for plan templates."""
    t = str(param_type or "").strip()
    if t.startswith("uint") or t.startswith("int"):
        if isinstance(value, bool):
            raise TypeError(f"bool not allowed for {t}")
        return int(value, 0) if isinstance(value, str) else int(value)
    if t == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")
    if t == "address":
        return str(value).strip()
    if t.startswith("bytes") and t != "bytes":
        raw = str(value).strip()
        if raw.startswith("0x"):
            return bytes.fromhex(raw[2:])
        return bytes.fromhex(raw)
    return value


def _handle_client_abi_encode(body: str) -> Optional[str]:
    try:
        colon = body.index(":")
        func_sig = body[:colon]
        args_str = body[colon + 1 :]
        paren_open = func_sig.index("(")
        paren_close = func_sig.rindex(")")
        func_name = func_sig[:paren_open]
        param_types_str = func_sig[paren_open + 1 : paren_close]
        param_types = [t.strip() for t in param_types_str.split(",")] if param_types_str else []
        if len(param_types) <= 1:
            args = [] if not param_types else [args_str]
        else:
            args = args_str.split(":")[: len(param_types)]
        args = [_coerce_abi_arg(t, a) for t, a in zip(param_types, args)]
        selector = keccak(text=f"{func_name}({param_types_str})")[:4]
        encoded = abi_encode(param_types, args) if param_types else b""
        return "0x" + (selector + encoded).hex()
    except Exception as exc:  # noqa: BLE001
        _log_warn(f"notify_push: CLIENT_ABI_ENCODE failed body={body!r}: {exc}")
        return None


def _log_info(msg: str) -> None:
    try:
        from siphon import log  # type: ignore

        log.info(msg)
    except Exception:  # noqa: BLE001
        print(f"[notify_push] {msg}", flush=True)


def _log_warn(msg: str) -> None:
    try:
        from siphon import log  # type: ignore

        log.warn(msg)
    except Exception:  # noqa: BLE001
        print(f"[notify_push] WARN {msg}", flush=True)

def _handle_client_abi_decode(body: str) -> Optional[str]:
    try:
        colon = body.index(":")
        return_type = body[:colon]
        hex_data = body[colon + 1 :]
        raw = bytes.fromhex(hex_data[2:] if hex_data.startswith("0x") else hex_data)
        decoded = abi_decode([return_type], raw)[0]
        if isinstance(decoded, (bytes, bytearray)):
            return "0x" + bytes(decoded).hex()
        return str(decoded)
    except Exception:  # noqa: BLE001
        return None


def _handle_client_json_extract(body: str) -> Optional[str]:
    try:
        colon = body.index(":")
        field = body[:colon]
        obj = json.loads(body[colon + 1 :])
        value = obj.get(field)
        if value is None:
            return None
        return value if isinstance(value, str) else str(value)
    except Exception:  # noqa: BLE001
        return None


def _handle_client_condition(body: str) -> int:
    try:
        parts = []
        start = 0
        text = str(body or "")
        for i, ch in enumerate(text):
            if ch == ":" and len(parts) < 3:
                parts.append(text[start:i])
                start = i + 1
        parts.append(text[start:])
        if len(parts) < 4:
            return 0
        op, left, right, skip_str = parts[:4]
        skip = int(skip_str)
        if op == "eq":
            return 0 if left == right else skip
        if op == "ne":
            return 0 if left != right else skip
        return 0
    except Exception:  # noqa: BLE001
        return 0


def _env_url(*names: str) -> str:
    for name in names:
        value = str(os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def _rpc_urls(chain_id: int) -> list[str]:
    if chain_id == 137:
        urls = [_env_url("POLYGON_RPC_URL"), _env_url("POLYGON_RPC_FALLBACK")]
    elif chain_id == 23294:
        urls = [_env_url("SAPPHIRE_RPC_URL")]
    elif chain_id == 1:
        urls = [_env_url("ETH_MAINNET_RPC_URL", "URL_RPC")]
    elif chain_id == 11155111:
        urls = [_env_url("SEPOLIA_RPC_URL", "URL_SEPOLIA_RPC")]
    elif chain_id == 80002:
        urls = [_env_url("AMOY_RPC_URL")]
    else:
        return []
    return [url for url in urls if url]


def _chain_read_transport_failure(result: dict[str, Any]) -> bool:
    status = int(result.get("statusCode") if result.get("statusCode") is not None else -1)
    if status < 0 or status == 429 or status >= 500:
        return True
    return False


def _handle_chain_read(body: str) -> tuple[Optional[str], Optional[str]]:
    try:
        spec = json.loads(body or "")
    except Exception as exc:  # noqa: BLE001
        return None, f"CHAIN_READ body is not JSON: {exc}"
    if not isinstance(spec, dict):
        return None, "CHAIN_READ body is not an object"
    try:
        chain_id = int(spec.get("chainId"))
    except (TypeError, ValueError):
        return None, "CHAIN_READ missing chainId"
    to = str(spec.get("to") or "").strip()
    data = str(spec.get("data") or "").strip()
    if not to or not data:
        return None, "CHAIN_READ missing to or data"
    urls = _rpc_urls(chain_id)
    if not urls:
        return None, f"CHAIN_READ no RPC for chainId {chain_id}"
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": to, "data": data}, "latest"],
            "id": 1,
        }
    )
    last: dict[str, Any] = {}
    for url in urls:
        result = _execute_http(url, "POST", "application/json", payload, "{}")
        last = result
        if _chain_read_transport_failure(result):
            _log_warn(
                f"notify_push: CHAIN_READ chain={chain_id} transport fail "
                f"status={result.get('statusCode')} url={url[:80]!r}"
            )
            continue
        if not result.get("success"):
            return None, (
                f"CHAIN_READ HTTP {result.get('statusCode')} "
                f"{result.get('error') or result.get('responseBody') or ''}"
            )
        try:
            obj = json.loads(result.get("responseBody") or "")
        except Exception as exc:  # noqa: BLE001
            return None, f"CHAIN_READ response is not JSON: {exc}"
        if isinstance(obj, dict) and obj.get("error") is not None:
            err = obj["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            return None, f"CHAIN_READ eth_call error: {msg}"
        value = obj.get("result") if isinstance(obj, dict) else None
        if not isinstance(value, str) or not value:
            return None, "CHAIN_READ response has no result"
        return value, None
    return None, (
        f"CHAIN_READ all RPCs failed for chainId {chain_id}: "
        f"{last.get('error') or last.get('statusCode')}"
    )


def _execute_http(url: str, method: str, content_type: str, body_str: str, headers_json: str) -> dict[str, Any]:
    if "push.apple.com" in (url or ""):
        return _execute_apns(url, method, content_type, body_str, headers_json)
    try:
        headers: dict[str, str] = {}
        if headers_json and headers_json != "{}":
            try:
                headers.update({str(k): str(v) for k, v in json.loads(headers_json).items()})
            except Exception:  # noqa: BLE001
                pass
        method_u = (method or "GET").upper()
        if method_u == "POST":
            headers["Content-Type"] = content_type or "application/json"
            resp = requests.post(url, data=body_str or "", headers=headers, timeout=10)
        else:
            resp = requests.request(method_u, url, headers=headers, timeout=10)
        return {
            "success": 200 <= resp.status_code < 300,
            "statusCode": resp.status_code,
            "responseBody": resp.text,
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "statusCode": -1, "responseBody": None, "error": str(exc)}


def _execute_apns(url: str, method: str, content_type: str, body_str: str, headers_json: str) -> dict[str, Any]:
    try:
        import httpx
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "statusCode": -1, "error": f"httpx unavailable for APNS: {exc}"}
    try:
        parsed = urlparse(url)
        headers = {":method": method or "POST", ":path": parsed.path or "/"}
        if content_type:
            headers["content-type"] = content_type
        if headers_json and headers_json != "{}":
            try:
                for k, v in json.loads(headers_json).items():
                    headers[str(k).lower()] = str(v)
            except Exception:  # noqa: BLE001
                pass
        with httpx.Client(http2=True, timeout=10.0) as client:
            resp = client.request(
                method or "POST",
                url,
                content=body_str or "",
                headers={k: v for k, v in headers.items() if not k.startswith(":")},
            )
        return {
            "success": 200 <= resp.status_code < 300,
            "statusCode": resp.status_code,
            "responseBody": resp.text,
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "statusCode": -1, "error": str(exc)}


def execute_plan(
    steps: list[dict[str, str]],
    *,
    initial_placeholders: Optional[dict[str, str]] = None,
    abort: Optional[Any] = None,
) -> dict[str, Any]:
    placeholders = dict(initial_placeholders or {})
    last_http = None
    i = 0
    while i < len(steps):
        if callable(abort) and abort():
            _log_info(f"notify_push: abort before step {i} (caller cancelled)")
            return {"success": True, "statusCode": 0, "aborted": True, "responseBody": ""}
        step = steps[i]
        method = _replace_placeholders(step.get("method"), placeholders)
        url = _replace_placeholders(step.get("url"), placeholders)
        body = _replace_placeholders(step.get("body"), placeholders)
        headers = _replace_placeholders(step.get("headers"), placeholders)
        content_type = _replace_placeholders(step.get("contentType"), placeholders)
        fallback_url = _replace_placeholders(step.get("fallbackUrl"), placeholders)
        extract_field = step.get("responseExtractField") or ""
        placeholder_key = step.get("placeholderKey") or ""
        protocol = str(step.get("protocol") or "").strip().lower()

        if method == "CLIENT_GENERATE":
            value = _handle_client_generate(body)
            if placeholder_key:
                placeholders[placeholder_key] = value
            i += 1
            continue
        if method == "CLIENT_ETH_SIGN":
            signature = _handle_client_eth_sign(body)
            if placeholder_key:
                placeholders[placeholder_key] = signature
            i += 1
            continue
        if method == "CLIENT_ABI_ENCODE":
            calldata = _handle_client_abi_encode(body)
            if not calldata:
                err = f"CLIENT_ABI_ENCODE failed: {body}"
                _log_warn(f"notify_push: step {i} {err}")
                return {"success": False, "statusCode": -1, "error": err}
            if placeholder_key:
                placeholders[placeholder_key] = calldata
            i += 1
            continue
        if method == "CLIENT_ABI_DECODE":
            decoded = _handle_client_abi_decode(body)
            if decoded is None:
                err = f"CLIENT_ABI_DECODE failed: {body}"
                _log_warn(f"notify_push: step {i} {err}")
                return {"success": False, "statusCode": -1, "error": err}
            if placeholder_key:
                placeholders[placeholder_key] = decoded
            i += 1
            continue
        if method == "CLIENT_JSON_EXTRACT":
            extracted = _handle_client_json_extract(body)
            if extracted is not None and placeholder_key:
                placeholders[placeholder_key] = extracted
            i += 1
            continue
        if method == "CLIENT_CONDITION":
            skip = _handle_client_condition(body)
            if skip > 0:
                i += skip
            i += 1
            continue
        if method == "CLIENT_RETURN":
            return {"success": True, "statusCode": 200, "responseBody": body}
        if method == "CHAIN_READ":
            value, err = _handle_chain_read(str(body or ""))
            if err:
                _log_warn(f"notify_push: step {i} {err}")
                return {"success": False, "statusCode": -1, "error": err}
            if placeholder_key and value is not None:
                placeholders[placeholder_key] = value
            i += 1
            continue

        if protocol == "plaintext":
            err = f"step {i} protocol=plaintext; siphon only sends webrtc"
            _log_warn(f"notify_push: {err}")
            return {"success": False, "statusCode": -1, "error": err}
        if protocol and protocol != "webrtc":
            err = f"step {i} unknown protocol={protocol!r}"
            _log_warn(f"notify_push: {err}")
            return {"success": False, "statusCode": -1, "error": err}
        if protocol == "webrtc":
            _log_info(f"notify_push: step {i} protocol=webrtc")

        if "application/json" in str(content_type or "").lower():
            body = _sanitize_json_body(str(body or ""), str(placeholders.get("{{MESSAGE}}") or ""))

        _log_info(f"notify_push: step {i} HTTP {method} url={str(url)[:120]!r}")
        if extract_field:
            result = _execute_http(url, method, content_type, body, headers)
            if not result.get("success") and fallback_url:
                result = _execute_http(fallback_url, method, content_type, body, headers)
            if not result.get("success"):
                err = (
                    f"Intermediate step {i + 1} failed "
                    f"(HTTP {result.get('statusCode')}) err={result.get('error')!r}"
                )
                _log_warn(f"notify_push: {err} body={str(result.get('responseBody') or '')[:200]!r}")
                return {
                    "success": False,
                    "statusCode": result.get("statusCode", -1),
                    "error": err,
                }
            extracted = _extract_json_field(result.get("responseBody") or "", extract_field)
            if extracted and placeholder_key:
                placeholders[placeholder_key] = extracted
        else:
            result = _execute_http(url, method, content_type, body, headers)
            if not result.get("success") and fallback_url:
                result = _execute_http(fallback_url, method, content_type, body, headers)
            if not result.get("success"):
                err = (
                    f"HTTP step {i + 1} failed "
                    f"(HTTP {result.get('statusCode')}) err={result.get('error')!r}"
                )
                _log_warn(f"notify_push: {err} body={str(result.get('responseBody') or '')[:200]!r}")
                return {
                    "success": False,
                    "statusCode": result.get("statusCode", -1),
                    "error": err,
                    "responseBody": result.get("responseBody"),
                }
            last_http = result
        i += 1

    if not last_http:
        return {"success": False, "statusCode": -1, "error": "No final HTTP step found in plan"}
    return last_http


async def send_notification(
    caller_ens: str,
    callee_ens: str,
    message: str,
    notification_type: int = NOTI_TYPE_CALL,
    options: Optional[dict[str, Any]] = None,
    abort: Optional[Any] = None,
) -> dict[str, Any]:
    options = options or {}
    import logic_client

    if callable(abort) and abort():
        _log_info("notify_push: abort before plan (caller cancelled)")
        return {"success": True, "statusCode": 0, "aborted": True}

    plan = await logic_client.fetch_notify_plan(
        from_id=caller_ens,
        to_id=callee_ens,
        message=message,
        notification_type=notification_type,
        session_id=str(options.get("sessionId") or ""),
        logic_sp=str(options.get("logicSp") or options.get("serviceId") or ""),
    )
    if callable(abort) and abort():
        _log_info("notify_push: abort after plan (caller cancelled)")
        return {"success": True, "statusCode": 0, "aborted": True}
    steps = plan["steps"]
    signaling_to = str(plan.get("to") or callee_ens)
    if signaling_to and signaling_to != callee_ens:
        try:
            obj = json.loads(message)
            if isinstance(obj, dict):
                obj["to"] = signaling_to
                message = json.dumps(obj)
        except Exception:  # noqa: BLE001
            pass
        _log_info(f"notify_push: rewrite to {callee_ens!r} → {signaling_to!r}")
        callee_ens = signaling_to
    wallet = str(plan.get("targetWallet") or options.get("targetWallet") or "")
    placeholders: dict[str, str] = {"{{MESSAGE}}": message}
    if wallet:
        placeholders["{{TARGET_ADDR}}"] = wallet
    _log_info(
        f"notify_push: executing GCP plan steps={len(steps)} "
        f"target={wallet or callee_ens}"
    )
    result = await asyncio.to_thread(
        execute_plan,
        steps,
        initial_placeholders=placeholders,
        abort=abort,
    )
    if result.get("aborted"):
        return result
    if not result.get("success"):
        raise RuntimeError(
            f"Plan-based execution failed (HTTP {result.get('statusCode')}): "
            f"{result.get('error') or 'unknown'}"
        )
    _log_info(
        f"notify_push: ok status={result.get('statusCode')} "
        f"from={caller_ens!r} to={callee_ens!r}"
    )
    return result
