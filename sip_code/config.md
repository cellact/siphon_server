# `config.json` Reference (SIPhon)

`config.json` is the SIP-plane environment source for SIPhon. It is read at
container start by `docker/docker-entrypoint.sh`, which exports the values as
`${VAR}` environment variables that `siphon.yaml` expands, and by
`arnacon_policy.py` for the inbound HTTP callback target.

Provider/domain/SBC/trusted-IP catalog is **not** here — it is loaded from
`arnacon-webrtc-service/globalserviceconfig.json` (+ the per-service
`services/<name>.json` files), the same files the webrtc-service reads, so the
two planes never drift.

## Which file is used

Resolved at container start, first match wins:

1. `config/config.json` — server-managed, **gitignored** (each box owns its own)
2. `sip_code/config.json` — committed default (this repo)
3. `SIPHON_CONFIG_JSON` env var — explicit absolute-path override

So for a new server: drop a `config/config.json` with that box's IPs/domain/cert
path and leave `sip_code/config.json` alone.

## Top-Level Shape

```json
{
  "development": { "common": {} },
  "production":  { "common": {} }
}
```

The active block is selected by the `DEPLOY_ENV` environment variable
(`development` | `production`, default `development`).

## `common` Keys

| Key                       | Consumed by            | Maps to / used for                                              |
| ------------------------- | ---------------------- | -------------------------------------------------------------- |
| `domain`                  | entrypoint + policy    | `SIPHON_DOMAIN` — TLS cert CN, advertised host, local domain   |
| `publicIp`                | entrypoint             | `SIPHON_PUBLIC_IP` — `advertised_address` in Via/Contact/SDP   |
| `bindIp`                  | entrypoint             | `SIPHON_BIND_IP` — interface all listeners bind to             |
| `wssPort`                 | entrypoint             | `SIPHON_WSS_PORT` — WSS listener port for sip.js clients       |
| `tlsCertPath`             | entrypoint             | `TLS_CERT_PATH` — Let's Encrypt live dir (fullchain/privkey)   |
| `rtpengineAddress`        | entrypoint             | `RTPENGINE_ADDRESS` — RTPEngine NG endpoint (`host:port`)      |
| `webrtcServiceHost`       | policy                 | host SIPhon POSTs `/inbound-call` to (the webrtc-service box)  |
| `providersPath`           | policy                 | optional SIP-only providers catalog (`providers.json`)          |
| `globalServiceConfigPath` | policy                 | path to `globalserviceconfig.json` (provider/SBC catalog)      |

### Split-server deployment

SIPhon and `arnacon-webrtc-service` can run on different boxes:

- **webrtc-service -> SIPhon**: the service's own `kamailioWssHost` /
  `kamailioWssPort` (in its config, not this file) must point at SIPhon's
  **public IP** + `wssPort`.
- **SIPhon -> webrtc-service**: set `webrtcServiceHost` to the service box's
  reachable IP. The per-domain callback port comes from the service catalog
  (`callbackPort` in `globalserviceconfig.json`).
- **RTPEngine** can be local or remote: set `rtpengineAddress` (e.g.
  `127.0.0.1:22222` local, `3.125.225.232:2223` remote NG endpoint). If remote,
  allow SIPhon's source IP to reach that NG port, and allow UDP media range
  (typically 20000-40000) between RTPEngine, webrtc-service (`werift`), and SBC.

## Catalog source (`globalserviceconfig.json` + `services/<name>.json`)

SIP can use either:

1. `providersPath` (recommended minimal copy) — SIP-only `providers.json`
2. or `globalServiceConfigPath` (legacy/full copy) — shared globalserviceconfig + per-service files

If both are set, `providersPath` wins.

Per-service `static` block consumed by the policy:

```json
{
  "development": {
    "providerId": "esimera",
    "static": {
      "status": "active",
      "domains": ["esimeratest.global", "esimera.global"],
      "trustedIngressIps": ["51.85.90.127"],
      "outboundSbcAddress": "185.62.121.10"
    }
  }
}
```

- `domains` — accepted/canonical domains for the provider (first = canonical).
- `trustedIngressIps` + `outboundSbcAddress` — together form the trusted SBC IP
  set. An INVITE whose source IP is in this set is treated as INBOUND-from-SBC
  (auth bypassed, parked until the callee registers).
- `outboundSbcAddress` — where OUTBOUND calls for that provider are dialed
  (`sip:<number>@<sbc>:5061;transport=tls`).
- The service entry's `callbackPort` is the per-domain callback endpoint SIPhon
  POSTs to (resolved per inbound domain). Supported forms are:
  - numeric port (`9100`) -> `http://webrtcServiceHost:9100/inbound-call`
  - host[:port] (`webrtc.box:9100`) -> `http://webrtc.box:9100/inbound-call`
  - full URL (`https://webrtc.box:9100/inbound-call`) -> used as-is.

### Minimal `providers.json` example

```json
{
  "development": {
    "services": {
      "esimera": {
        "providerId": "esimera",
        "status": "active",
        "domains": ["esimeratest.global", "esimera.global"],
        "outboundSbcAddress": "185.62.121.10",
        "trustedIngressIps": ["185.62.121.10"],
        "callbackPort": "https://webrtc-esimera.example.com:9100/inbound-call"
      }
    }
  }
}
```
