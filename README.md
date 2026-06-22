# test2_kamailio (SIPhon)

The SIP plane for the Arnacon WebRTC stack. This used to be Kamailio
(`ron_kamailio.cfg` + `kamailio.py`); it is now **SIPhon** — a single Rust
binary driven by one `siphon.yaml` plus one hot-reloaded Python policy script.

The `arnacon-webrtc-service` is unchanged: it still speaks SIP-over-WSS via
sip.js, still owns FCM / blockchain / werift media. SIPhon is just the router +
RTPEngine driver it connects to, and it can run on a separate box.

## Layout

- `sip_code/` — the SIP-engine code (named generically so it's interchangeable
  for any SIP stack, not just SIPhon).
  - `siphon.yaml` — listeners (wss/tls/udp/tcp), TLS cert, RTPEngine media
    profiles, registrar, NAT, script path. Uses `${VAR}` env expansion.
  - `arnacon_policy.py` — the whole routing brain (proxy for REGISTER/OPTIONS,
    B2BUA for calls: WebRTC↔SBC, OpenAI bridge, inbound park/resume).
  - `config.json` — committed **default** per-env SIP source (domain/IPs/ports/
    cert path + `webrtcServiceHost`). See `config.md`.
  - `config.example.json`, `config.md`.
- `config/` — **gitignored**, server-managed. Drop a `config/config.json` here
  on each box; it **takes precedence** over `sip_code/config.json`. This lets
  each deployment own its IPs/domain/cert path without touching tracked files.
- `docker/`
  - `docker-compose.yml` — builds SIPhon from a pinned git context (BuildKit
    fetches the source), mounts the repo (`sip_code/` + optional `config/`),
    host network.
  - `docker-entrypoint.sh` — picks the active `config.json` (config/ over
    sip_code/), exports `SIPHON_*` env from it, then `exec siphon --config`.
- `certs/` — local cert material (prod uses `/etc/letsencrypt`).

## Prerequisites

- Docker with BuildKit (default on modern Docker). The compose `build.context`
  is a **git URL** pinned to a SIPhon commit, so BuildKit fetches and builds the
  SIPhon source itself — no local clone needed. Bump the ref in
  `docker/docker-compose.yml` (or use `#main`) to track upstream.
- RTPEngine reachable from the SIPhon box. Configure endpoint via
  `rtpengineAddress` in `config.json` (`127.0.0.1:22222` local or remote
  `host:port` NG endpoint).
- TLS certs at `tlsCertPath` (Let's Encrypt `fullchain.pem` + `privkey.pem`).

## Config injection

The active `config.json` is resolved at container start, first match wins:

1. `config/config.json` — server-managed, gitignored
2. `sip_code/config.json` — committed default
3. or override with the `SIPHON_CONFIG_JSON` env var (absolute path)

`docker-entrypoint.sh` reads `<active config>[$DEPLOY_ENV].common` and exports:

| config.json key   | exported env       | used by                                |
| ----------------- | ------------------ | -------------------------------------- |
| `domain`          | `SIPHON_DOMAIN`    | siphon.yaml (cert CN / advertise / local domain) |
| `publicIp`        | `SIPHON_PUBLIC_IP` | siphon.yaml `advertised_address`       |
| `bindIp`          | `SIPHON_BIND_IP`   | siphon.yaml listener bind              |
| `wssPort`         | `SIPHON_WSS_PORT`  | siphon.yaml wss listener               |
| `tlsCertPath`     | `TLS_CERT_PATH`    | siphon.yaml TLS cert/key               |
| `rtpengineAddress`| `RTPENGINE_ADDRESS`| siphon.yaml RTPEngine NG endpoint      |
| `globalServiceConfigPath` | `SIPHON_GLOBAL_CONFIG_JSON` | arnacon_policy.py catalog load |

`webrtcServiceHost` is read directly by the policy for the `/inbound-call`
callback. SIPhon expands the `${VAR}` refs in `siphon.yaml` at load.

## Run (Docker)

First start / image rebuild:

```bash
cd /path/to/test2Server/test2_kamailio
DEPLOY_ENV=production docker compose -f docker/docker-compose.yml up -d --build siphon
```

Config-only redeploy (siphon.yaml / policy / config.json are mounted, so a
restart re-reads them; the policy also hot-reloads on change):

```bash
cd /path/to/test2Server/test2_kamailio
DEPLOY_ENV=production docker compose -f docker/docker-compose.yml restart siphon
```

Validate the YAML loads (dry run):

```bash
cd /path/to/test2Server/test2_kamailio
DEPLOY_ENV=production docker compose -f docker/docker-compose.yml \
  run --rm --entrypoint /usr/local/bin/siphon siphon --config /etc/siphon/repo/sip_code/siphon.yaml --check
```

Logs:

```bash
docker compose -f docker/docker-compose.yml logs -f siphon
```

Per-server config: create `config/config.json` (gitignored) with this box's
`development`/`production` block — it overrides `sip_code/config.json`
automatically, no compose changes needed. Catalog overrides still available:

```bash
DEPLOY_ENV=production
WEBRTC_GLOBAL_CONFIG_SOURCE=/shared/runtime/globalserviceconfig.json
WEBRTC_SERVICES_SOURCE=/shared/runtime/services
```

## Split-server deployment

SIPhon and `arnacon-webrtc-service` can run on different boxes:

- **webrtc-service → SIPhon**: set the service's `kamailioWssHost` /
  `kamailioWssPort` to SIPhon's **public IP** + `wssPort`.
- **SIPhon → webrtc-service**: set `webrtcServiceHost` in `config.json` to the
  service box IP. Callback ports come from the service catalog.
- **RTPEngine** can be remote. Set `rtpengineAddress` in `config.json` to the
  remote NG endpoint (for example `3.125.225.232:2223`), allow SIPhon to reach
  that port, and open RTPEngine media UDP range (typically `20000-40000`) to
  and from the webrtc-service and SBC peers.

## Smoke tests (do these first, in order)

1. **WSS handshake + framing**: one REGISTER + one INVITE from the real
   webrtc-service through SIPhon's WSS listener.
2. **`wss_to_rtp`/custom profiles**: verify werift accepts the SDP SIPhon
   produces (ICE/DTLS/BUNDLE). If werift rejects a missing
   `a=group:BUNDLE`, re-add it (the old cfg did the same hack).
3. **Inbound park/resume**: confirm `@registrar.on_change` resolves the parked
   A-leg INVITE when the woken client REGISTERs (60s timeout).

## Notes

- `DEPLOY_ENV` defaults to `development`.
- Keep `config.json` as the single source of truth for env-specific values; keep
  provider/SBC/trusted-IP data in `globalserviceconfig.json` so SIPhon and the
  webrtc-service never drift.
- REGISTER auth is intentionally bypassed in the policy (crypto is validated
  client/service-side), matching the previous Kamailio behaviour.
- Prepaid per-call cutoff now lives in `arnacon-webrtc-service` (it owns the
  minute counter); the old `Limit`-header path is gone.
