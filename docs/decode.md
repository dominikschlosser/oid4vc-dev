# Decode

Auto-detect and decode credentials (SD-JWT, JWT, mDOC), OpenID4VCI/VP requests, and ETSI trust lists.

```bash
# Credentials
ssi-debugger decode credential.txt
ssi-debugger decode "eyJhbGci..."
ssi-debugger decode --json credential.txt
ssi-debugger decode -v credential.txt
cat credential.txt | ssi-debugger decode

# OpenID4VCI credential offers
ssi-debugger decode 'openid-credential-offer://?credential_offer_uri=...'
ssi-debugger decode 'https://issuer.example/offer?credential_offer=...'

# OpenID4VP authorization requests
ssi-debugger decode 'openid4vp://authorize?...'
ssi-debugger decode 'haip://authorize?...'
ssi-debugger decode 'eudi-openid4vp://authorize?...'
ssi-debugger decode request.jwt
cat offer.json | ssi-debugger decode

# ETSI trust lists
ssi-debugger decode trust-list.jwt
ssi-debugger decode -f trustlist https://example.com/trust-list.jwt
```

## Auto-detection order

1. **OpenID URI schemes** — `openid-credential-offer://` (VCI), `openid4vp://` / `haip://` / `eudi-openid4vp://` (VP)
2. **HTTP(S) URL with OID4 query params** — `credential_offer` / `credential_offer_uri` (VCI), `client_id` / `response_type` / `request_uri` (VP)
3. **SD-JWT** — contains `~` separator
4. **mDOC** — hex or base64url encoded CBOR
5. **JSON** — inspected for OID4 marker keys (`credential_issuer` → VCI, `client_id` → VP)
6. **JWT** — 3 dot-separated parts; payload inspected for OID4 markers and trust list markers (`TrustedEntitiesList`)

## Format override

Use `--format` / `-f` to skip auto-detection when it gets it wrong (e.g. a credential JWT whose payload happens to contain `credential_issuer`):

```bash
ssi-debugger decode -f jwt "eyJhbGci..."
ssi-debugger decode -f sdjwt credential.txt
ssi-debugger decode -f mdoc credential.hex
ssi-debugger decode -f vci 'openid-credential-offer://...'
ssi-debugger decode -f vp request.jwt
```

Accepted values: `sdjwt` (or `sd-jwt`), `jwt`, `mdoc` (or `mso_mdoc`), `vci` (or `oid4vci`), `vp` (or `oid4vp`), `trustlist` (or `trust`).

## QR Code Scanning

Scan a QR code directly from an image file or a screen capture:

```bash
ssi-debugger decode --qr screenshot.png
ssi-debugger decode --screen
```

`--screen` uses the native macOS `screencapture` tool in interactive selection mode — a crosshair appears to let you select the region containing the QR code. On other platforms, take a screenshot and use `--qr screenshot.png` instead.

> **Note:** Screen capture permission on macOS is granted to the **terminal app** (Terminal.app, iTerm2, etc.), not to `ssi-debugger` itself. If permission is missing, System Settings will be opened automatically to the Screen Recording pane — enable access for your terminal app there, then re-run the command.

## Flags

| Flag             | Description                                                  |
|------------------|--------------------------------------------------------------|
| `-f`, `--format` | Pin format: `sdjwt`, `jwt`, `mdoc`, `vci`, `vp`, `trustlist` |
| `--qr`           | Decode QR from a PNG or JPEG image file                      |
| `--screen`       | Open interactive screen region selector and decode a QR code from the selection (macOS only) |

`--qr`, `--screen`, and positional input arguments are mutually exclusive.

## Example output

```
SD-JWT Credential
──────────────────────────────────────────────────

┌ Header
  alg: ES256
  typ: dc+sd-jwt

┌ Payload (signed claims)
  _sd: ["77ofip...", "EyNwlR...", "X3X1zI..."]
  _sd_alg: sha-256
  iss: https://issuer.example
  vct: urn:eudi:pid:de:1

┌ Disclosed Claims (3)
  [1] given_name: Erika
  [2] family_name: Mustermann
  [3] birth_date: 1984-08-12
```

Use `-v` for x5c chains, digest IDs, and device key info. Use `--json` for machine-readable output.
