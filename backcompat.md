# Notify backcompat

Current app calls the old contract. New app calls the new contract. Same siphon.

## Siphon `/notify`

`client_ingress.py` `on_notify` accepts these three bodies. Anything else in `protocol` is 400.

- No `protocol`. Body is the offer (`from`, `to`, `sdp`). ICE path. Empty protocol does not enter the plaintext forward.
- `protocol: "webrtc"`. Read off the JSON. Unwrap `payload` into the offer, copy `x-sign` / `x-data` onto it, then the same ICE path.
- `protocol: "plaintext"`. Same unwrap. `author` counts as `from` for `/auth`. Then POST `{"x-sign","x-data","payload"}` to that provider's `smsUrl`. `from` is copied onto `author` only when `author` is missing. Secnum `smsUrl` is `la-sms-client-outbound`.

## LA

`la-sms-client-outbound` is unchanged. It still requires `payload`, `x-sign`, and `x-data`, and it reads `author` inside the payload. That is the body the old Secnum contract posted straight there. Old messages never reach siphon.

## Not a problem while the current app stays on the old contract

- 8 fields vs 9. The current app only decodes the old contract, which still returns 8 strings. It never `eth_call`s the new one. The new app is built for the 9th field, `protocol`. Siphon does not decode this tuple.
- ANS 404. The empty-`{{WEB3_IDENTITY}}` fork exists only in the new plan. The current app runs the old plan. The new app's runner stores `""` on 404.

## Out of this cut

eSIMera wrapper is still on the 4-arg plan.
