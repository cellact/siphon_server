# `config.json` Reference (Service-Split)

`config.json` is the only SIPhon config. `common.providers` holds domains, trusted ingress, and outbound SBC. `common.clientIngress.logicProviders[].notifyPort` is the HTTPS listen port (one server each). The docker entrypoint exports `SIPHON_*` for `siphon.yaml` from this file and does not open `globalserviceconfig.json`.

## Package Installation Flow

Install the package once:

- `npm i @arnacon-webrtc`

Use subpath exports:

- `@arnacon-webrtc/core` for shared runtime entry points
- `@arnacon-webrtc/service/esimera` for service policy module
- `@arnacon-webrtc/service/basicService` for starter service module

Typical runtime model:

- one process per service (set `SERVICE_ID`)
- no dedicated orchestrator process; each service owns its own in-memory call state

## Top-Level Shape

```json
{
  "development": {
    "common": {},
    "services": {}
  },
  "production": {
    "common": {},
    "services": {}
  }
}
```

## `common` Keys

SIPhon-edge values (JSON key names kept for webrtc compatibility):

- `domain`
- `kamailioWssHost`
- `publicIp`
- `bindIp`
- `tlsCertPath`
- `kamailioWssPort`
- `rtpengineAddress` (`host:port`, used for `rtpengine_sock`)
- `webrtcServiceHost` (host used for callback URL construction when callback is port-only)
- `callbackScheme` (`http`/`https`, default `http`)
- `callbackPath` (default `/inbound-call`)

WebRTC global runtime values moved out of this file:

- `roflBaseUrl`
- `messageProcessorUrl`
- `polygon` (`rpc`, `ENSRegistry`, `NameWrapper`, `ServiceProviderRegistry`, `ProvisionRegistry`, `CustomENS`)
- `sapphire` (`rpc`, `NotificationManagerRegistry`)
- `sapphireTestnet` (`rpc`, `NFTCallerIdPool`)

## `services` Registry Keys

Each service entry in `config.json` contains:

- `providerId`: canonical provider key (`esimera`, `secnum`, etc.)
- `notifyPort`: HTTPS port used by clients (`/notify`)
- `callbackPort`: callback target for Kamailio; can be:
  - port only (`9101`) → resolved as `<scheme>://<webrtcServiceHost>:9101<callbackPath>`
  - host:port (`secnum.internal:9101`) → resolved as `<scheme>://secnum.internal:9101<callbackPath>`
  - full URL (`https://svc.example.com/inbound-call`) → used as-is
- `configPath`: per-service static config file path (relative to `test2_kamailio`)
- `modulePath`: service runtime module path (relative to `test2_kamailio`)

Example:

```json
"esimera": {
  "providerId": "esimera",
  "notifyPort": 9000,
  "callbackPort": 9100,
  "configPath": "./services/esimera.json",
  "modulePath": "./webRTCservice/services/esimera.js"
}
```

## Per-Service Config (`services/<name>.json`)

Each file has environment blocks and one static constants object:

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

`static` keys are deployment constants only. No routing policy schema belongs here.

## Service Module Interface (`webRTCservice/services/*.js`)

Each module exports:

- `id`
- `providerId`
- `resolveDestination(ctx)`
- `resolveCallerId(ctx)`
- `resolveInboundTarget(ctx)`
- `normalizeIdentity(ctx)` (optional)
- `shapeNotifyPayload(ctx)` (optional)
- `hooks.normalizeIncomingPayload(payload)`
- `hooks.normalizeInboundCallbackPayload(payload)`

Service methods receive shared helpers through `ctx.helpers` (dependency injection). Service modules should not import helper implementations directly.

## Migration Notes

- Old `providers` block in `config.json` is removed.
- Old single `serverPort` / `internalServerPort` is removed.
- Runtime supports service-isolated startup (one process per service via `SERVICE_ID`).
- Cross-service coordination is service-to-service (internal HTTP) with no shared external state requirement.
- Kamailio callback port is resolved per inbound domain using the service registry + per-service domains.
- Kamailio forwards raw inbound payload; inbound target selection (`to` vs `diversion`) stays service-side.
- Kamailio no longer runs ROFL/business lookup or ENS/blockchain fallback logic.

## Runtime Override Precedence

For dynamic deployment, SIPhon uses:

- `RTPENGINE_ADDRESS` env > `common.rtpengineAddress` > `127.0.0.1:2223`
- `WEBRTC_SERVICE_HOST` env > `common.webrtcServiceHost` > `common.bindIp`
- `WEBRTC_CALLBACK_SCHEME` env > `common.callbackScheme` > `http`
- `WEBRTC_CALLBACK_PATH` env > `common.callbackPath` > `/inbound-call`

## Secnum client ingress (`:9001` /notify)

Secnum Android/client HTTPS `/notify` is served by **SIPhon** (`siphon-bin --features http`), not Node `arnacon-webrtc-service`.

- Listener: entrypoint renders one `[::]:notifyPort` TLS server per `logicProviders` entry
- Script: `client_ingress.py` (+ `identity.py`, `logic_client.py`, `notify_push.py`)
- Config: `common.providers` and `common.clientIngress` in `config.json`

### Cutover

1. Deploy/rebuild SIPhon image (`FEATURES=http`).
2. **Stop/disable Node secnum process binding 9001** (leave other notify ports alone).
3. Point Android secnum notify base URL at SIPhon host:9001.
4. Contract: `POST /notify` offer → JSON `{ ok, type: "answer", sessionId, sdp, route }`; also `ice-batch` / `cancel` / `reject` / callee `answer`.
5. Inbound SBC → Node `/inbound-call` stays on Node until a follow-up; SIP inbound already hits SIPhon.
