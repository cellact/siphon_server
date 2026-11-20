# test2_kamailio (SIPhon edge)

Kamailio has been replaced by [SIPhon](https://github.com/siphon-project/siphon-sip).
This folder is the Arnacon SIP edge: WSS/TLS facing `arnacon-webrtc-service`, TLS to the carrier SBC, media via rtpengine.

## Layout

- `sip_code/siphon.yaml` — listeners, TLS, rtpengine profiles, registrar, `extensions.http`
- `sip_code/http.yaml` — HTTPS `:9001` secnum client `/notify`
- `sip_code/siphon_app.py` — B2BUA / REGISTER / REFER + imports client ingress
- `sip_code/client_ingress.py` / `identity.py` / `logic_client.py` / `notify_push.py` — client `/notify` path (replaces Node on 9001)
- `sip_code/policy.py` — provider catalog, SBC detect, webrtc `/inbound-call` callbacks
- `sip_code/config.json` — env-specific bind/domain/certs/rtpengine/callback + `clientIngress`
- `docker/` — image + compose (host network); builds `siphon-bin --features http`

Upstream SIPhon is **cloned from GitHub inside the Docker build** (`siphon-bin --features http`). No local `siphon-source` checkout required on the host.

## Run (Docker)

From this repo (`/etc/kamailio` on the server, or `test2_kamailio` locally):

```bash
cd docker
DEPLOY_ENV=development docker compose build
DEPLOY_ENV=development docker compose up -d
docker logs -f test2_siphon
```

Optional pin:

```bash
SIPHON_GIT_REF=main DEPLOY_ENV=development docker compose build
```

Production:

```bash
cd docker
DEPLOY_ENV=production docker compose build
DEPLOY_ENV=production docker compose up -d
```

Compose build context is the **repo root** (parent of `docker/`). Dockerfile copies `sip_code/` and clones https://github.com/siphon-project/siphon-sip.git.

## Config

`sip_code/config.json` remains the source of truth. The entrypoint exports `SIPHON_*` env vars (domain, bind IP, WSS port, TLS cert path, rtpengine address, webrtc callback host). SIPhon expands `${VAR}` inside `siphon.yaml`.

JSON keys such as `kamailioWssPort` are kept for compatibility with existing webrtc global config wiring.

Env overrides:

- `SIPHON_CONFIG_PATH`
- `SIPHON_GLOBAL_CONFIG_PATH`
- `RTPENGINE_ADDRESS`
- `WEBRTC_SERVICE_HOST`
- `WEBRTC_CALLBACK_SCHEME`
- `WEBRTC_CALLBACK_PATH`

## Call flows (parity)

| Flow | Behavior |
|---|---|
| Secnum client `/notify` :9001 | HTTPS offer → auth → route SBC/webrtc → rtpengine answer SDP (Node public notify disabled) |
| Outbound WebRTC → SBC (WSS) | WSS INVITE → From rewrite → rtpengine `webrtc_to_sbc` → TLS :5061 SBC |
| Inbound SBC → WebRTC | trusted SBC INVITE → HTTP `/inbound-call` → 180 + wait REGISTER → dial WSS contact |
| REGISTER | usrloc save + wake suspended inbound |
| REFER | callback to webrtc-service; local-bridge / pass-through / external-sip |

**Cutover:** stop Node secnum from binding 9001 (`publicNotifyDisabled` / `notifyOwner: siphon` in globalserviceconfig). Point Android notify URL at SIPhon `:9001`.

## Verify

```bash
docker logs test2_siphon --tail 200
# WSS target used by arnacon-webrtc-service should still be host:kamailioWssPort (8443)
curl -sk https://127.0.0.1:9001/healthz
```
