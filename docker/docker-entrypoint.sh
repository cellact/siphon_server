#!/bin/sh
set -eu

: "${DEPLOY_ENV:=development}"
: "${SIPHON_CONFIG_PATH:=/etc/arnacon/config.json}"
: "${SIPHON_YAML_TEMPLATE:=/etc/siphon/siphon.yaml}"
: "${SIPHON_RENDERED_YAML:=/run/siphon/siphon.yaml}"
: "${SIPHON_RENDERED_HTTP_YAML:=/run/siphon/http.yaml}"
: "${SIPHON_SCRIPT_PATH:=/etc/siphon/scripts/siphon_app.py}"

mkdir -p /run/siphon

# Hash from/to on the log stream. Call handling is unchanged.
# Installed before node (production) and before siphon so both inherit it.
case "${LOG_HASH_NUMBERS:-0}" in
  1|true|TRUE|yes|YES)
    if [ ! -f /usr/local/bin/arnaserver-mask ]; then
      echo "ERROR: LOG_HASH_NUMBERS is on and /usr/local/bin/arnaserver-mask is missing" >&2
      exit 1
    fi
    _mask_fifo=/run/siphon/logmask.fifo
    rm -f "$_mask_fifo"
    mkfifo "$_mask_fifo"
    python3 /usr/local/bin/arnaserver-mask < "$_mask_fifo" &
    exec > "$_mask_fifo" 2>&1
    ;;
esac

render_exports="$(
python3 <<'PY'
import json
import os
import shlex
import sys

deploy_env = os.environ.get("DEPLOY_ENV", "development")
config_path = os.environ.get("SIPHON_CONFIG_PATH", "/etc/arnacon/config.json")

with open(config_path, encoding="utf-8") as f:
    root = json.load(f)

env_cfg = root.get(deploy_env)
if not env_cfg:
    print(f"ERROR: environment {deploy_env!r} not found in {config_path}", file=sys.stderr)
    sys.exit(1)

common = env_cfg.get("common", {})
providers = common.get("providers")
if not isinstance(providers, dict) or not providers:
    print(
        f"ERROR: {config_path} ({deploy_env}) common.providers is missing or empty",
        file=sys.stderr,
    )
    sys.exit(1)


def as_cidr(ip):
    ip = str(ip or "").strip()
    if not ip:
        return "127.0.0.1/32"
    if "/" in ip:
        return ip
    return f"{ip}/32"


seen_peers = []
for provider_id, static in providers.items():
    if str(provider_id).startswith("_") or not isinstance(static, dict):
        continue
    for ip in static.get("trustedIngressIps", []) or []:
        if ip and str(ip) not in seen_peers:
            seen_peers.append(str(ip))

outbound_cidrs = []
for provider_id, static in providers.items():
    if str(provider_id).startswith("_") or not isinstance(static, dict):
        continue
    cidr = as_cidr(static.get("outboundSbcAddress"))
    if cidr != "127.0.0.1/32" and cidr not in outbound_cidrs:
        outbound_cidrs.append(cidr)
while len(outbound_cidrs) < 3:
    outbound_cidrs.append("127.0.0.1/32")
exports = {
    "SIPHON_DOMAIN": common.get("domain", ""),
    "SIPHON_PUBLIC_IP": common.get("publicIp", ""),
    "SIPHON_BIND_IP": common.get("bindIp", ""),
    "SIPHON_WSS_PORT": str(common.get("kamailioWssPort", "")),
    "TLS_CERT_PATH": common.get("tlsCertPath", ""),
    "RTPENGINE_ADDRESS": common.get("rtpengineAddress", "127.0.0.1:22222"),
    "WEBRTC_SERVICE_HOST": (
        common.get("webrtcServiceHost")
        or common.get("bindIp", "")
    ),
    "WEBRTC_CALLBACK_SCHEME": common.get("callbackScheme", "http"),
    "WEBRTC_CALLBACK_PATH": common.get("callbackPath", "/inbound-call"),
    "SBC_CIDR": outbound_cidrs[0],
    "SBC_CIDR_2": outbound_cidrs[1],
    "SBC_CIDR_3": outbound_cidrs[2],
    "TRUSTED_PEER_1": seen_peers[0] if len(seen_peers) > 0 else "",
    "TRUSTED_PEER_2": seen_peers[1] if len(seen_peers) > 1 else "",
    "TRUSTED_PEER_1_CIDR": as_cidr(seen_peers[0] if len(seen_peers) > 0 else ""),
    "TRUSTED_PEER_2_CIDR": as_cidr(seen_peers[1] if len(seen_peers) > 1 else ""),
    "SIPHON_CONFIG_PATH": config_path,
    "SIPHON_SCRIPT_PATH": os.environ.get(
        "SIPHON_SCRIPT_PATH", "/etc/siphon/scripts/siphon_app.py"
    ),
    "DEPLOY_ENV": deploy_env,
}

required = [
    "SIPHON_DOMAIN",
    "SIPHON_PUBLIC_IP",
    "SIPHON_BIND_IP",
    "SIPHON_WSS_PORT",
    "TLS_CERT_PATH",
    "WEBRTC_SERVICE_HOST",
]
missing = [name for name in required if exports.get(name, "") == ""]
if missing:
    print("ERROR: missing SIPhon render values: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)

for name, value in exports.items():
    print(f"export {name}={shlex.quote(str(value))}")
PY
)"
eval "$render_exports"

# SIPhon expands ${VAR} itself for the main yaml — copy template into runtime path.
cp "$SIPHON_YAML_TEMPLATE" "$SIPHON_RENDERED_YAML"

# siphon-http does NOT expand ${VAR}. One listen per logicProviders.notifyPort.
python3 - "$SIPHON_RENDERED_HTTP_YAML" <<'PY'
import json
import os
import sys

dst = sys.argv[1]
tls = os.environ.get("TLS_CERT_PATH", "").rstrip("/")
if not tls:
    print("ERROR: TLS_CERT_PATH empty; cannot render http.yaml", file=sys.stderr)
    sys.exit(1)
deploy_env = os.environ.get("DEPLOY_ENV", "development")
config_path = os.environ.get("SIPHON_CONFIG_PATH", "/etc/arnacon/config.json")
with open(config_path, encoding="utf-8") as f:
    common = json.load(f).get(deploy_env, {}).get("common", {})
ingress = common.get("clientIngress") or {}
providers = ingress.get("logicProviders") or []
ports = []
for item in providers:
    if not isinstance(item, dict):
        continue
    try:
        port = int(item.get("notifyPort") or 0)
    except (TypeError, ValueError):
        continue
    if port > 0 and port not in ports:
        ports.append(port)
dtmf = ingress.get("openaiDtmf") if isinstance(ingress.get("openaiDtmf"), dict) else {}
try:
    dtmf_port = int(dtmf.get("port") or 0)
except (TypeError, ValueError):
    dtmf_port = 0
if dtmf_port > 0 and dtmf_port not in ports:
    ports.append(dtmf_port)
if not ports:
    print(
        f"ERROR: {config_path} ({deploy_env}) has no logicProviders.notifyPort",
        file=sys.stderr,
    )
    sys.exit(1)
blocks = []
for port in ports:
    blocks.append(
        "\n".join(
            [
                f'  - listen: "[::]:{port}"',
                "    tls:",
                f'      cert_path: "{tls}/fullchain.pem"',
                f'      key_path: "{tls}/privkey.pem"',
                "    max_body_bytes: 262144",
                "    request_timeout_ms: 120000",
            ]
        )
    )
text = (
    "# Rendered from clientIngress.logicProviders[].notifyPort and openaiDtmf.port\n"
    "servers:\n" + "\n".join(blocks) + "\n"
)
with open(dst, "w", encoding="utf-8") as out:
    out.write(text)
print(f"rendered http.yaml -> {dst} ports={','.join(str(p) for p in ports)}")
PY

export SIPHON_CONFIG_PATH
export SIPHON_SCRIPT_PATH
export DEPLOY_ENV

exec "$@"
