# ssi-debugger

[![CI](https://github.com/dominikschlosser/ssi-debugger/actions/workflows/ci.yml/badge.svg)](https://github.com/dominikschlosser/ssi-debugger/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dominikschlosser/ssi-debugger)](https://github.com/dominikschlosser/ssi-debugger/releases/latest)

A local-first CLI tool for decoding, validating, and inspecting SSI credentials — SD-JWT and mDOC (mso_mdoc).

No network calls by default. Decode and verify credentials entirely offline.

## Install

### From GitHub Releases

Download the latest binary for your platform from [Releases](https://github.com/dominikschlosser/ssi-debugger/releases).

### From source

```bash
go install github.com/dominikschlosser/ssi-debugger@latest
```

### Build locally

```bash
git clone https://github.com/dominikschlosser/ssi-debugger.git
cd ssi-debugger
go build -o ssi-debugger .
```

## Usage

```
ssi-debugger [--json] [--no-color] [-v] <command> [flags] [input]
```

Input can be a **file path**, **URL**, **raw credential string**, or piped via **stdin**.

### Commands

| Command    | Purpose                                                    |
|------------|------------------------------------------------------------|
| `decode`   | Auto-detect & decode SD-JWT or mDOC, show all claims       |
| `validate` | Decode + verify signatures, check status/trust              |
| `status`   | Check revocation via status list (network call)             |
| `trust`    | Inspect an ETSI TS 119 602 trust list JWT                   |
| `dcql`     | Generate a DCQL query from a credential's claims            |
| `version`  | Print version                                               |

### Decode

```bash
ssi-debugger decode credential.txt
ssi-debugger decode "eyJhbGci..."
ssi-debugger decode --json credential.txt
ssi-debugger decode -v credential.txt
cat credential.txt | ssi-debugger decode
```

**SD-JWT example:**

```
SD-JWT Credential
──────────────────────────────────────────────────

┌ Header
  alg: ES256
  typ: dc+sd-jwt

┌ Payload (signed claims)
  _sd: ["77ofip...", "EyNwlR...", "X3X1zI..."]
  _sd_alg: sha-256
  exp: 1742592000
  iat: 1740000000
  iss: https://issuer.example
  vct: urn:eudi:pid:1

┌ Disclosed Claims (3)
  [1] given_name: Erika
  [2] family_name: Mustermann
  [3] birth_date: 1984-08-12
```

**mDOC example:**

```
mDOC Credential
──────────────────────────────────────────────────
  (parsed from DeviceResponse)

┌ Document Info
  DocType: eu.europa.ec.eudi.pid.1
  MSO Version: 1.0
  Digest Algorithm: SHA-256
  Signed: 2026-02-25T00:00:00Z
  Valid From: 2026-02-25T00:00:00Z
  Valid Until: 2026-03-11T00:00:00Z (in 13 days)

┌ Namespace: eu.europa.ec.eudi.pid.1 (7 claims)
  birth_date: 1984-08-12
  family_name: MUSTERMANN
  given_name: ERIKA
  resident_city: KÖLN
  resident_country: DE
  resident_postal_code: 51147
  resident_street: HEIDESTRAẞE 17
```

With `-v`, each claim also shows its `digestID`. With `--json`, output is machine-readable:

```json
{
  "format": "dc+sd-jwt",
  "header": { "alg": "ES256", "typ": "dc+sd-jwt" },
  "payload": { "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", ... },
  "resolvedClaims": {
    "given_name": "Erika",
    "family_name": "Mustermann",
    "birth_date": "1984-08-12",
    ...
  },
  "disclosures": [
    { "name": "given_name", "value": "Erika", "salt": "...", "digest": "..." },
    ...
  ]
}
```

### Validate

Requires `--key` or `--trust-list` (or both).

```bash
ssi-debugger validate --key issuer-key.pem credential.txt
ssi-debugger validate --trust-list trust-list.jwt credential.txt
ssi-debugger validate --key key.pem --status-list credential.txt
ssi-debugger validate --key key.pem --allow-expired credential.txt
```

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK)                      |
| `--trust-list`    | ETSI trust list JWT (file path or URL)             |
| `--status-list`   | Check revocation via status list (network call)    |
| `--allow-expired` | Don't fail on expired credentials                  |

When a trust list is provided and the credential contains an x5c (SD-JWT) or x5chain (mDOC) certificate chain, the chain is validated against the trust list before verifying the signature.

### Status

Check credential revocation via the status list endpoint embedded in the credential.

```bash
ssi-debugger status credential.txt
```

### Trust

Inspect an ETSI TS 119 602 trust list JWT. Accepts a file path or URL.

```bash
ssi-debugger trust trust-list.jwt
ssi-debugger trust https://example.com/trust-list.jwt
```

### DCQL

Generate a DCQL (Digital Credentials Query Language) query from a credential's claims. Always outputs JSON.

```bash
ssi-debugger dcql credential.txt
```

**Example output (SD-JWT):**

```json
{
  "credentials": [
    {
      "id": "urn_eudi_pid_1",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:1"] },
      "claims": [
        { "path": ["birth_date"] },
        { "path": ["family_name"] },
        { "path": ["given_name"] }
      ]
    }
  ]
}
```

**Example output (mDOC):**

```json
{
  "credentials": [
    {
      "id": "eu_europa_ec_eudi_pid_1",
      "format": "mso_mdoc",
      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
      "claims": [
        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] },
        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
        ...
      ]
    }
  ]
}
```

## Supported Formats

### SD-JWT (`dc+sd-jwt`)

- Decodes JWT header/payload and all disclosures
- Resolves `_sd` digest arrays
- Shows key binding JWT if present
- Signature verification: ES256, ES384, ES512, RS256, RS384, RS512, PS256

### mDOC (`mso_mdoc`)

- Decodes CBOR IssuerSigned and DeviceResponse (hex or base64url input)
- Parses COSE_Sign1 issuerAuth and MSO (Mobile Security Object)
- COSE signature verification via go-cose

## Global Flags

| Flag         | Description              |
|--------------|--------------------------|
| `--json`     | Output as JSON           |
| `--no-color` | Disable colored output   |
| `-v`         | Verbose output           |

## License

Apache-2.0
