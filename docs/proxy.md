# Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer. Point your wallet at the proxy instead of the real server — every request and response is captured, classified by protocol step, decoded, and displayed both in the terminal and a live web dashboard.

```bash
oid4vc-dev proxy --target http://localhost:8080
oid4vc-dev proxy --target http://localhost:8080 --port 9090 --dashboard 9091
oid4vc-dev proxy --target http://localhost:8080 --no-dashboard
```

```
Wallet  <-->  Proxy (:9090)  <-->  Verifier/Issuer (:8080)
                  |
            Live dashboard (:9091)
```

## Traffic classification

Traffic is automatically classified into protocol steps:

| Badge               | Detected when                                                     |
|---------------------|-------------------------------------------------------------------|
| VP Auth Request     | `client_id` + `response_type=vp_token` in query                  |
| VP Request Object   | Response body is a JWT (request object fetch)                     |
| VP Auth Response    | POST body contains `vp_token`, `presentation_submission`, `id_token`, or `response` (JARM) |
| VCI Credential Offer| `credential_offer` / `credential_offer_uri` in query              |
| VCI Metadata        | Path contains `.well-known/openid-credential-issuer`              |
| VCI Token Request   | POST to path ending `/token`                                      |
| VCI Credential Req  | POST to path ending `/credential`                                 |

By default, only OID4VP/VCI traffic is shown. Non-matching requests (favicon, health checks, etc.) are still proxied but hidden from the output. Pass `--all-traffic` or toggle the "All traffic" checkbox in the dashboard to see everything.

## Features

- **Smart decoding** — payloads are decoded inline (SD-JWT, JWT, mDOC, DCQL queries, JWE headers)
- **Credential decode hints** — detected credentials are printed as `oid4vc-dev decode` commands for quick inspection
- **JARM/JWE decryption** — when the built-in wallet sends a `direct_post.jwt` response through the proxy, the encrypted payload is automatically decrypted (see [JWE Decryption](#jwe-decryption) below)
- **Flow correlation** — related protocol steps are grouped by shared `state`/`nonce` values
- **Web dashboard** at `http://localhost:9091` with live SSE updates, expandable cards, "View in Decoder" links, HAR export, and cURL copy
- **JARM/JWE detection** — shows encrypted response headers and the verifier's ephemeral public key
- **NDJSON output** — `--json` for machine-readable output, pipe to `jq` or log to file

## Flags

| Flag             | Default | Description                              |
|------------------|---------|------------------------------------------|
| `--target`       | —       | URL of the verifier/issuer (required)    |
| `--port`         | `9090`  | Proxy listen port                        |
| `--dashboard`    | `9091`  | Dashboard listen port                    |
| `--no-dashboard` | `false` | Disable web dashboard                    |
| `--all-traffic`  | `false` | Show all traffic, not just OID4VP/VCI    |
| `--json`         | `false` | NDJSON output to stdout (global flag)    |

## Example output

```
━━━ [14:32:05] GET /authorize?client_id=...  ← 200 (45ms)  [VP Auth Request]
    ┌ client_id: did:web:verifier.example
    ┌ response_mode: direct_post.jwt
    ┌ nonce: abc123
    ┌ dcql_query: { "credentials": [...] }

━━━ [14:32:05] GET /request/abc123  ← 200 (12ms)  [VP Request Object]
    ┌ header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
    ┌ payload: { ... }

━━━ [14:32:06] POST /response  ← 200 (89ms)  [VP Auth Response]
    ┌ response_type: JWE (decrypted via debug key)
    ┌ encryption_alg: ECDH-ES
    ┌ response_payload: {"vp_token":{...},"state":"abc123"}
  → oid4vc-dev decode 'eyJhbGci...'  (vp_token)
```

## JWE decryption

When the built-in wallet (`oid4vc-dev wallet`) sends an encrypted JARM response (`direct_post.jwt`) through the proxy, the proxy automatically decrypts the payload and shows the contained `vp_token` and `state`.

This works via a debug header: the wallet includes the AES content encryption key (CEK) in `X-Debug-JWE-CEK`. The proxy strips this header before forwarding the request to the verifier, so the verifier never sees it.

No configuration is needed — simply route the wallet through the proxy:

```
oid4vc-dev wallet                          # wallet sends to response_uri
oid4vc-dev proxy --target http://verifier  # proxy intercepts, decrypts, forwards
```

If the debug header is not present (e.g. when using a third-party wallet), the proxy falls back to showing only the JWE header fields (`alg`, `enc`, `kid`, `epk`).

## Debugging tips

- The wallet logs credentials and encryption keys to stdout for local debugging:
  - `[VP] JWE content encryption key for proxy debugging: <base64url CEK>`
  - `[VP] SD-JWT presentation created: ...`
- Use `--all-traffic` to see non-OID4VP/VCI requests (health checks, favicon, etc.)
- Pipe to `jq` with `--json` for structured analysis: `oid4vc-dev proxy --target ... --json | jq '.credentials'`
