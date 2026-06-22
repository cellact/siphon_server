#!/bin/sh
# SIPhon entrypoint: pick the active config.json, turn its [$DEPLOY_ENV].common
# into the ${VAR} env that siphon.yaml expands, then exec the siphon binary.
#
# Config precedence (first that exists wins):
#   1. $REPO/config/config.json   -- user/server-managed, gitignored (NOT in git)
#   2. $REPO/sip_code/config.json -- committed default (ours)
# Override either with SIPHON_CONFIG_JSON to point anywhere.
#
# The policy script (arnacon_policy.py) reads DEPLOY_ENV / SIPHON_CONFIG_JSON /
# SIPHON_GLOBAL_CONFIG_JSON from the same exported env.
set -eu

: "${DEPLOY_ENV:=development}"
: "${SIPHON_REPO:=/etc/siphon/repo}"
: "${SIPHON_YAML:=${SIPHON_REPO}/sip_code/siphon.yaml}"

if [ -z "${SIPHON_CONFIG_JSON:-}" ]; then
    if [ -f "${SIPHON_REPO}/config/config.json" ]; then
        SIPHON_CONFIG_JSON="${SIPHON_REPO}/config/config.json"
    else
        SIPHON_CONFIG_JSON="${SIPHON_REPO}/sip_code/config.json"
    fi
fi
export SIPHON_CONFIG_JSON
echo "siphon-entrypoint: using config ${SIPHON_CONFIG_JSON} (env=${DEPLOY_ENV})" >&2

render_exports="$(
python3 <<'PY'
import json
import os
import shlex
import sys

deploy_env = os.environ.get("DEPLOY_ENV", "development")
config_path = os.environ["SIPHON_CONFIG_JSON"]

with open(config_path, encoding="utf-8") as f:
    root = json.load(f)

env_cfg = root.get(deploy_env)
if not env_cfg:
    print(f"ERROR: environment {deploy_env!r} not found in {config_path}", file=sys.stderr)
    sys.exit(1)

common = env_cfg.get("common", {})

exports = {
    # Consumed by siphon.yaml ${VAR} expansion.
    "SIPHON_DOMAIN": common.get("domain", ""),
    "SIPHON_PUBLIC_IP": common.get("publicIp", ""),
    "SIPHON_BIND_IP": common.get("bindIp", ""),
    "SIPHON_WSS_PORT": common.get("wssPort", ""),
    "TLS_CERT_PATH": common.get("tlsCertPath", ""),
    "RTPENGINE_ADDRESS": common.get("rtpengineAddress", "127.0.0.1:22222"),
    # Consumed by arnacon_policy.py.
    "SIPHON_GLOBAL_CONFIG_JSON": (
        os.environ.get("SIPHON_GLOBAL_CONFIG_JSON")
        or common.get("globalServiceConfigPath", "")
    ),
}

required = [
    "SIPHON_DOMAIN",
    "SIPHON_PUBLIC_IP",
    "SIPHON_BIND_IP",
    "SIPHON_WSS_PORT",
    "TLS_CERT_PATH",
]
missing = [name for name in required if str(exports.get(name, "")) == ""]
if missing:
    print("ERROR: missing SIPhon config values: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)

for name, value in exports.items():
    print(f"export {name}={shlex.quote(str(value))}")
PY
)"
eval "$render_exports"

exec /usr/local/bin/siphon --config "$SIPHON_YAML"
